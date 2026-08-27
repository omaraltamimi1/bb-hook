#!/usr/bin/env bash
# AutoRecon V7 - full bug-bounty reconnaissance and attack-surface workflow.

set -uo pipefail
IFS=$'\n\t'

VERSION="7.0.0"
AUTO=0 DRY_RUN=0 ACTIVE=1 KEEP_TEMP=0
OUT_ROOT="${OUT_ROOT:-./autorecon-results}"
HTTPX_RATE="${HTTPX_RATE:-20}"
ACTIVE_RATE="${ACTIVE_RATE:-15}"
COMMAND_TIMEOUT="${COMMAND_TIMEOUT:-900}"
TARGET_INPUT=""
WORK="" REPORT="" LOG=""

usage() {
  cat <<EOF
AutoRecon $VERSION
Usage: $0 [options] <domain|IPv4|URL>

  --auto             use recommended choices without prompts
  --active           enable active stages (default)
  --passive          disable Nmap, FFUF, Nuclei, Arjun and access checks
  --dry-run          print commands without network activity
  --output-dir DIR   report directory (default: $OUT_ROOT)
  --keep-temp        retain working directory for debugging
  -h, --help         show this help

Environment: HTTPX_RATE, ACTIVE_RATE, COMMAND_TIMEOUT, BB_USER_AGENT,
             FFUF_WORDLIST, NUCLEI_SEVERITIES, OUT_ROOT
EOF
}

die() { printf '[-] %s\n' "$*" >&2; exit 2; }
warn() { printf '[!] %s\n' "$*" >&2; }
info() { printf '[*] %s\n' "$*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

while (($#)); do
  case "$1" in
    --auto) AUTO=1 ;;
    --active) ACTIVE=1 ;;
    --passive) ACTIVE=0 ;;
    --dry-run) DRY_RUN=1; AUTO=1 ;;
    --keep-temp) KEEP_TEMP=1 ;;
    --output-dir) (($# > 1)) || die "--output-dir requires a value"; OUT_ROOT="$2"; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) die "unknown option: $1" ;;
    *) [[ -z "$TARGET_INPUT" ]] || die "only one target is supported"; TARGET_INPUT="$1" ;;
  esac
  shift
done
[[ -n "$TARGET_INPUT" ]] || { usage >&2; exit 2; }

# URLs are accepted, but credentials, IPv6, and arbitrary schemes are rejected.
[[ "$TARGET_INPUT" != *$'\n'* && "$TARGET_INPUT" != *$'\r'* ]] || die "target contains a newline"
case "$TARGET_INPUT" in
  http://*|https://*) AUTHORITY="${TARGET_INPUT#*://}"; AUTHORITY="${AUTHORITY%%/*}" ;;
  *://*) die "only http:// and https:// URLs are supported" ;;
  *) AUTHORITY="${TARGET_INPUT%%/*}" ;;
esac
[[ "$AUTHORITY" != *@* ]] || die "credentials in target URLs are unsupported"
HOST="${AUTHORITY%%:*}"
[[ -n "$HOST" && "$HOST" =~ ^[A-Za-z0-9.-]+$ ]] || die "invalid hostname: $HOST"
HOST="${HOST,,}"
HOST="${HOST%.}"

is_ipv4=0
if [[ "$HOST" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  is_ipv4=1
  IFS=. read -r a b c d <<<"$HOST"
  for octet in "$a" "$b" "$c" "$d"; do
    ((10#$octet <= 255)) || die "invalid IPv4 address: $HOST"
  done
elif [[ "$HOST" != *.* || "$HOST" == .* || "$HOST" == *..* || "$HOST" == *-.* || "$HOST" == *.-* ]]; then
  die "invalid domain: $HOST"
fi

SAFE_NAME="${HOST//[^A-Za-z0-9._-]/_}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
umask 077
mkdir -p "$OUT_ROOT" || die "cannot create output directory: $OUT_ROOT"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/autorecon.${SAFE_NAME}.XXXXXX")" || die "mktemp failed"
REPORT="$OUT_ROOT/${SAFE_NAME}_${STAMP}_report.txt"
LOG="$WORK/run.log"

cleanup() {
  rc=$?
  if ((KEEP_TEMP)); then printf '[*] Work directory retained: %s\n' "$WORK"; else rm -rf -- "$WORK"; fi
  exit "$rc"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$WORK"/{dns,subs,http,urls,active}
exec > >(tee -a "$LOG") 2>&1

run_cmd() {
  local label="$1"; shift
  info "$label"
  if ((DRY_RUN)); then printf '[DRY-RUN] '; printf '%q ' "$@"; printf '\n'; return 0; fi
  if have timeout; then timeout --signal=TERM --kill-after=10 "$COMMAND_TIMEOUT" "$@"; else "$@"; fi
}

ask_yes() {
  local prompt="$1" default="${2:-n}" answer
  if ((AUTO)); then [[ "$default" == y ]]; return; fi
  read -r -p "$prompt [y/N]: " answer || answer=n
  [[ "${answer,,}" == y || "${answer,,}" == yes ]]
}

TOOLS=(dig subfinder assetfinder amass dnsx httpx naabu katana gau waybackurls arjun jq curl nmap ffuf nuclei python3)
{
  printf 'AutoRecon %s\nTarget: %s\nStarted: %s\nActive automation: %s\n\n' \
    "$VERSION" "$HOST" "$(date -Is)" "$ACTIVE"
  echo '[TOOL INVENTORY]'
  for tool in "${TOOLS[@]}"; do
    if have "$tool"; then printf 'present\t%s\t%s\n' "$tool" "$(command -v "$tool")"; else printf 'missing\t%s\n' "$tool"; fi
  done
} > "$WORK/meta.txt"

if (( !is_ipv4 )) && have dig; then
  for rr in A AAAA CNAME MX NS TXT CAA SOA; do
    { printf '### %s\n' "$rr"; run_cmd "DNS $rr" dig +time=3 +tries=1 +short "$rr" "$HOST" || true; } >> "$WORK/dns/records.txt"
  done
fi

: > "$WORK/subs/hosts.txt"
if (( !is_ipv4 )) && have subfinder; then
  run_cmd "Passive subdomain enumeration" subfinder -d "$HOST" -silent -rl 10 -o "$WORK/subs/raw.txt" || warn "subfinder failed"
fi
if (( !is_ipv4 )) && have assetfinder; then
  run_cmd "Assetfinder enumeration" assetfinder --subs-only "$HOST" > "$WORK/subs/assetfinder.txt" || warn "assetfinder failed"
fi
if (( !is_ipv4 )) && have amass; then
  run_cmd "Amass passive enumeration" amass enum -passive -d "$HOST" -o "$WORK/subs/amass.txt" || warn "amass failed"
fi
{ echo "$HOST"; cat "$WORK/subs/raw.txt" "$WORK/subs/assetfinder.txt" "$WORK/subs/amass.txt" 2>/dev/null || true; } \
  | awk 'NF' | tr '[:upper:]' '[:lower:]' | sort -u > "$WORK/subs/hosts.txt"
if have dnsx && [[ -s "$WORK/subs/hosts.txt" ]]; then
  run_cmd "DNS resolution and wildcard cleanup" dnsx -l "$WORK/subs/hosts.txt" -silent -a -aaaa -cname -resp \
    -o "$WORK/subs/resolved.txt" || warn "dnsx failed"
fi

: > "$WORK/http/live.txt"; : > "$WORK/http/details.jsonl"
if have httpx; then
  if ((DRY_RUN)); then echo "https://$HOST" > "$WORK/http/live.txt"; fi
  run_cmd "HTTP reachability" httpx -l "$WORK/subs/hosts.txt" -silent -nf -rl "$HTTPX_RATE" -timeout 10 \
    -o "$WORK/http/live.txt" || warn "httpx reachability failed"
  if [[ -s "$WORK/http/live.txt" ]]; then
    run_cmd "HTTP fingerprinting" httpx -l "$WORK/http/live.txt" -silent -json -sc -cl -ct -title -td -server \
      -ip -cname -cdn -location -rt -rl "$HTTPX_RATE" -o "$WORK/http/details.jsonl" || warn "httpx fingerprinting failed"
  fi
fi

if ((ACTIVE)) && have naabu && [[ -s "$WORK/subs/hosts.txt" ]]; then
  run_cmd "Fast port discovery" naabu -list "$WORK/subs/hosts.txt" -top-ports 1000 -rate "$ACTIVE_RATE" -silent \
    -o "$WORK/active/naabu.txt" || warn "naabu failed"
fi

: > "$WORK/urls/katana.txt"; : > "$WORK/urls/gau.txt"
if [[ -s "$WORK/http/live.txt" ]] && have katana; then
  : > "$WORK/urls/katana.raw"
  run_cmd "Scoped crawl" katana -list "$WORK/http/live.txt" -silent -d 3 -jc -kf all -fs rdn \
    -ef png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,eot,mp4,mp3 -rl 8 -o "$WORK/urls/katana.raw" || warn "katana failed"
  sort -u "$WORK/urls/katana.raw" > "$WORK/urls/katana.txt"
fi
if (( !is_ipv4 )) && have gau; then
  : > "$WORK/urls/gau.raw"
  run_cmd "Historical URL collection" gau --subs --threads 3 --timeout 15 --o "$WORK/urls/gau.raw" "$HOST" || warn "gau failed"
  sort -u "$WORK/urls/gau.raw" > "$WORK/urls/gau.txt"
fi
if (( !is_ipv4 )) && have waybackurls; then
  run_cmd "Wayback URL collection" waybackurls "$HOST" > "$WORK/urls/wayback.txt" || warn "waybackurls failed"
fi
cat "$WORK/http/live.txt" "$WORK/urls/katana.txt" "$WORK/urls/gau.txt" 2>/dev/null \
  "$WORK/urls/wayback.txt" \
  | sed 's/#.*//' | awk 'NF' | sort -u > "$WORK/urls/corpus.txt"

# Extract JavaScript files, parameters and high-value routes without dropping
# anything from the full corpus. These are additional triage views, not filters.
grep -Ei '\.(m?js)([?#]|$)' "$WORK/urls/corpus.txt" | sort -u > "$WORK/urls/javascript.txt" || true
grep -E '\?[^#]*=' "$WORK/urls/corpus.txt" | sort -u > "$WORK/urls/parameterized.txt" || true
grep -Eai '[/._?-](api|admin|auth|graphql|swagger|openapi|internal|debug|upload|export|backup|config|env|git|actuator)([/._?=&-]|$)' \
  "$WORK/urls/corpus.txt" | sort -u > "$WORK/urls/priority.txt" || true

# Download a capped JS set and perform offline endpoint/secret discovery. The
# evidence is retained verbatim so analysts can validate candidates themselves.
: > "$WORK/urls/js_secrets.tsv"; : > "$WORK/urls/js_endpoints.txt"
if have curl && have python3 && [[ -s "$WORK/urls/javascript.txt" ]] && (( !DRY_RUN )); then
  mkdir -p "$WORK/javascript"
  head -n "${JS_MAX_FILES:-100}" "$WORK/urls/javascript.txt" | while IFS= read -r js; do
    name="$(printf %s "$js" | cksum | cut -d' ' -f1).js"
    curl -kfsSL --compressed --max-time 20 --max-filesize "${JS_MAX_SIZE:-5242880}" \
      -A "${BB_USER_AGENT:-Mozilla/5.0 AutoRecon-V7}" "$js" -o "$WORK/javascript/$name" 2>/dev/null && \
      printf '%s\t%s\n' "$js" "$WORK/javascript/$name" >> "$WORK/urls/js_map.tsv"
  done
  python3 - "$WORK/urls/js_map.tsv" "$WORK/urls/js_secrets.tsv" "$WORK/urls/js_endpoints.txt" <<'PY'
import pathlib, re, sys
from urllib.parse import urljoin
mapping, secrets_out, endpoints_out = sys.argv[1:]
patterns = {
 "aws_key": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
 "google_key": r"\bAIza[A-Za-z0-9_-]{35}\b",
 "github_token": r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\b",
 "jwt": r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
 "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
 "secret_assignment": r'''(?i)\b(?:api[_-]?key|secret|token|password|client[_-]?secret)\b\s*[:=]\s*["'][^"'\r\n]{8,500}["']''',
}
url_rx = re.compile(r'''https?://[^\s"'<>\\]+''', re.I)
path_rx = re.compile(r'''["'](/(?:api|v\d+|graphql|oauth|auth|admin|internal|debug|upload|export|webhook)[^"']*)["']''', re.I)
found, endpoints = [], set()
p = pathlib.Path(mapping)
for row in p.read_text(errors="ignore").splitlines() if p.exists() else []:
    if "\t" not in row: continue
    source, filename = row.split("\t", 1)
    text = pathlib.Path(filename).read_text(errors="ignore")
    for label, raw in patterns.items():
        for match in re.finditer(raw, text):
            line = text.count("\n", 0, match.start()) + 1
            found.append((source, str(line), label, match.group(0)[:500].replace("\t", " ")))
    endpoints.update(m.group(0).rstrip(");,]}") for m in url_rx.finditer(text))
    endpoints.update(urljoin(source, m.group(1)) for m in path_rx.finditer(text))
pathlib.Path(secrets_out).write_text("".join("\t".join(x)+"\n" for x in found))
pathlib.Path(endpoints_out).write_text("".join(x+"\n" for x in sorted(endpoints)))
PY
fi

if ((ACTIVE)) && have arjun && [[ -s "$WORK/urls/corpus.txt" ]]; then
  head -n "${ARJUN_MAX_URLS:-50}" "$WORK/urls/corpus.txt" > "$WORK/active/arjun_targets.txt"
  run_cmd "Hidden parameter discovery" arjun -i "$WORK/active/arjun_targets.txt" -m GET -T 10 \
    --ratelimit "$ACTIVE_RATE" -oJ "$WORK/active/arjun.json" || warn "arjun failed"
fi

if ((ACTIVE)); then
  if have nmap && ask_yes "Run conservative Nmap scan?" y; then
    run_cmd "Nmap top ports" nmap -Pn -T3 --top-ports 1000 --open -sV -oN "$WORK/active/nmap.txt" "$HOST" || warn "nmap failed"
  fi
  if have nuclei && [[ -s "$WORK/http/live.txt" ]] && ask_yes "Run focused Nuclei scan?" y; then
    run_cmd "Nuclei medium+ scan" nuclei -l "$WORK/http/live.txt" -silent -jsonl -severity "${NUCLEI_SEVERITIES:-medium,high,critical}" \
      -rate-limit "$ACTIVE_RATE" -bulk-size 1 -concurrency 2 -timeout 10 -retries 1 -disable-update-check -o "$WORK/active/nuclei.jsonl" || warn "nuclei failed"
  fi
  if have ffuf && [[ -n "${FFUF_WORDLIST:-}" && -f "${FFUF_WORDLIST:-}" ]] && [[ -s "$WORK/http/live.txt" ]] && ask_yes "Run root-only FFUF?" n; then
    while IFS= read -r url; do
      run_cmd "FFUF $url" ffuf -w "$FFUF_WORDLIST" -u "${url%/}/FUZZ" -ac -fc 404 -rate "$ACTIVE_RATE" -t 2 \
        -maxtime 60 -noninteractive -of json -o "$WORK/active/ffuf.$(printf %s "$url" | cksum | cut -d' ' -f1).json" || warn "ffuf failed"
    done < "$WORK/http/live.txt"
  fi
else
  info "Active stages disabled by --passive."
fi

# Differential 401/403 checks preserve every response metric. A 2xx transition
# is highlighted separately; no candidate is silently discarded.
: > "$WORK/active/access_all.tsv"; : > "$WORK/active/access_candidates.tsv"
if ((ACTIVE)) && have curl && [[ -s "$WORK/urls/priority.txt" ]] && (( !DRY_RUN )); then
  metric() { curl -ksS --max-time 12 -o /dev/null -w '%{http_code}\t%{size_download}\t%{url_effective}' "$@" 2>/dev/null || printf '000\t0\t-'; }
  head -n "${ACCESS_MAX_URLS:-40}" "$WORK/urls/priority.txt" | while IFS= read -r url; do
    [[ "$url" =~ ^https?:// ]] || continue
    clean="${url%%\?*}"; origin="$(printf %s "$clean" | sed -E 's#^(https?://[^/]+).*#\1#')"
    path="${clean#"$origin"}"; [[ -n "$path" ]] || path=/
    base="$(metric "$url")"; base_code="${base%%$'\t'*}"
    printf '%s\t%s\tbaseline\t%s\n' "$base_code" "$base" "$url" >> "$WORK/active/access_all.tsv"
    while IFS='|' read -r label variant headers; do
      IFS=' ' read -r -a header_args <<< "$headers"
      result="$(metric "${header_args[@]}" "$variant")"; code="${result%%$'\t'*}"
      printf '%s\t%s\t%s\t%s\n' "$base_code" "$result" "$label" "$variant" >> "$WORK/active/access_all.tsv"
      if [[ "$base_code" =~ ^(401|403)$ && "$code" =~ ^2 ]]; then
        printf '%s\t%s\t%s\t%s\n' "$base_code" "$result" "$label" "$variant" >> "$WORK/active/access_candidates.tsv"
      fi
    done <<EOF
trailing-slash|${clean%/}/|
double-slash|${origin}//${path#/}|
encoded-dot|${origin}/%2e${path}|
X-Original-URL|${origin}/|-H X-Original-URL:$path
X-Rewrite-URL|${origin}/|-H X-Rewrite-URL:$path
X-Forwarded-For|$url|-H X-Forwarded-For:127.0.0.1
X-Custom-IP-Authorization|$url|-H X-Custom-IP-Authorization:127.0.0.1
EOF
    sleep "${ACCESS_DELAY:-0.1}"
  done
fi

# Compile through a temporary file so interrupted runs never leave a partial report.
REPORT_TMP="$WORK/report.tmp"
{
  cat "$WORK/meta.txt"
  for entry in \
    "DNS|$WORK/dns/records.txt" "HOSTS|$WORK/subs/hosts.txt" \
    "LIVE URLS|$WORK/http/live.txt" "HTTP DETAILS|$WORK/http/details.jsonl" \
    "CRAWLED URLS|$WORK/urls/katana.txt" "HISTORICAL URLS|$WORK/urls/gau.txt" \
    "WAYBACK URLS|$WORK/urls/wayback.txt" "FULL ENDPOINT CORPUS|$WORK/urls/corpus.txt" \
    "PARAMETERIZED URLS|$WORK/urls/parameterized.txt" "PRIORITY ENDPOINTS|$WORK/urls/priority.txt" \
    "JAVASCRIPT URLS|$WORK/urls/javascript.txt" "JAVASCRIPT ENDPOINTS|$WORK/urls/js_endpoints.txt" \
    "JAVASCRIPT SECRET CANDIDATES|$WORK/urls/js_secrets.tsv" "DNSX RESOLUTION|$WORK/subs/resolved.txt" \
    "NAABU PORTS|$WORK/active/naabu.txt" "NMAP|$WORK/active/nmap.txt" \
    "ARJUN PARAMETERS|$WORK/active/arjun.json" "NUCLEI|$WORK/active/nuclei.jsonl" \
    "ALL ACCESS VARIATIONS|$WORK/active/access_all.tsv" "ACCESS BYPASS CANDIDATES|$WORK/active/access_candidates.tsv"; do
    label="${entry%%|*}"; path="${entry#*|}"
    printf '\n============================================================\n%s\n============================================================\n' "$label"
    [[ -s "$path" ]] && cat "$path" || echo '(none recorded)'
  done
  echo; echo 'FFUF RESULTS'
  find "$WORK/active" -maxdepth 1 -type f -name 'ffuf.*.json' -exec cat {} + 2>/dev/null || echo '(none recorded)'
  echo; echo 'EXECUTION LOG'; sed -E $'s/\x1B\[[0-9;]*[mK]//g' "$LOG"
  printf '\nFinished: %s\n' "$(date -Is)"
} > "$REPORT_TMP"
mv -f -- "$REPORT_TMP" "$REPORT"
printf '[+] Report created: %s\n' "$REPORT"
