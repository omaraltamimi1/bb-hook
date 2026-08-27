#!/usr/bin/env bash
# AutoRecon V7 - full bug-bounty reconnaissance and attack-surface workflow.

set -uo pipefail
IFS=$'\n\t'

VERSION="7.1.0"
AUTO=0 DRY_RUN=0 ACTIVE=1 KEEP_TEMP=0
SCOPE_MODE="seed" SCREENSHOTS="${SCREENSHOTS:-0}"
OUT_ROOT="${OUT_ROOT:-./autorecon-results}"
HTTPX_RATE="${HTTPX_RATE:-20}"
ACTIVE_RATE="${ACTIVE_RATE:-15}"
COMMAND_TIMEOUT="${COMMAND_TIMEOUT:-900}"
TARGET_INPUT=""
WORK="" REPORT="" LOG=""
EXTRA_HEADERS=()

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
  --header VALUE     add an HTTP header (repeatable)
  --cookie VALUE     add a Cookie header
  --no-scope         retain and actively process every discovered host
  --screenshots      capture HTTP screenshots when supported
  -h, --help         show this help

Environment: HTTPX_RATE, ACTIVE_RATE, COMMAND_TIMEOUT, BB_USER_AGENT,
             FFUF_WORDLIST, PARAM_WORDLIST, NUCLEI_SEVERITIES,
             NUCLEI_TEMPLATES, NUCLEI_TAGS, GRAPHQL_INTROSPECTION,
             SCREENSHOTS, SCREENSHOT_BASELINE, OUT_ROOT
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
    --header) (($# > 1)) || die "--header requires a value"; EXTRA_HEADERS+=("$2"); shift ;;
    --cookie) (($# > 1)) || die "--cookie requires a value"; EXTRA_HEADERS+=("Cookie: $2"); shift ;;
    --no-scope) SCOPE_MODE="all" ;;
    --screenshots) SCREENSHOTS=1 ;;
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

in_scope_url() {
  local url="$1" authority host
  [[ "$SCOPE_MODE" == all ]] && return 0
  [[ "$url" =~ ^https?:// ]] || return 1
  authority="${url#*://}"; authority="${authority%%/*}"; authority="${authority##*@}"
  host="${authority%%:*}"; host="${host,,}"; host="${host%.}"
  [[ "$host" == "$HOST" ]] || (( !is_ipv4 )) && [[ "$host" == *."$HOST" ]]
}

scope_stream() {
  while IFS= read -r item; do in_scope_url "$item" && printf '%s\n' "$item"; done
}

append_headers() {
  local -n destination="$1"; local header
  for header in "${EXTRA_HEADERS[@]}"; do destination+=(-H "$header"); done
  [[ -n "${BB_USER_AGENT:-}" ]] && destination+=(-H "User-Agent: $BB_USER_AGENT")
}

TOOLS=(dig subfinder assetfinder amass dnsx httpx naabu katana gau waybackurls arjun jq curl nmap ffuf nuclei python3)
{
  printf 'AutoRecon %s\nTarget: %s\nStarted: %s\nActive automation: %s\nScope mode: %s\nHTTP headers configured: %s\n\n' \
    "$VERSION" "$HOST" "$(date -Is)" "$ACTIVE" "$SCOPE_MODE" "${#EXTRA_HEADERS[@]}"
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
  | awk 'NF' | tr '[:upper:]' '[:lower:]' | sort -u > "$WORK/subs/all_hosts.txt"
if [[ "$SCOPE_MODE" == all || "$is_ipv4" == 1 ]]; then
  cp "$WORK/subs/all_hosts.txt" "$WORK/subs/hosts.txt"
else
  while IFS= read -r candidate; do
    [[ "$candidate" == "$HOST" || "$candidate" == *."$HOST" ]] && printf '%s\n' "$candidate"
  done < "$WORK/subs/all_hosts.txt" > "$WORK/subs/hosts.txt"
fi
if have dnsx && [[ -s "$WORK/subs/hosts.txt" ]]; then
  run_cmd "DNS resolution and wildcard cleanup" dnsx -l "$WORK/subs/hosts.txt" -silent -a -aaaa -cname -resp \
    -o "$WORK/subs/resolved.txt" || warn "dnsx failed"
fi

: > "$WORK/http/live.txt"; : > "$WORK/http/details.jsonl"
if have httpx; then
  if ((DRY_RUN)); then echo "https://$HOST" > "$WORK/http/live.txt"; fi
  http_live=(httpx -l "$WORK/subs/hosts.txt" -silent -nf -rl "$HTTPX_RATE" -timeout 10 -o "$WORK/http/live.txt")
  append_headers http_live
  run_cmd "HTTP reachability" "${http_live[@]}" || warn "httpx reachability failed"
  if [[ -s "$WORK/http/live.txt" ]]; then
    http_details=(httpx -l "$WORK/http/live.txt" -silent -json -sc -cl -ct -title -td -server
      -ip -cname -cdn -location -rt -rl "$HTTPX_RATE" -o "$WORK/http/details.jsonl")
    append_headers http_details
    run_cmd "HTTP fingerprinting" "${http_details[@]}" || warn "httpx fingerprinting failed"
  fi
fi

: > "$WORK/http/technology_summary.tsv"
if have jq && [[ -s "$WORK/http/details.jsonl" ]]; then
  jq -r '[.url // .input // "", ((.tech // .technologies // []) | if type == "array" then join(",") else tostring end), .webserver // "", .cdn_name // ""] | @tsv' \
    "$WORK/http/details.jsonl" | sort -u > "$WORK/http/technology_summary.tsv" || true
fi
if ((SCREENSHOTS)) && have httpx && [[ -s "$WORK/http/live.txt" ]]; then
  mkdir -p "$WORK/http/screenshots"
  shot_args=(httpx -l "$WORK/http/live.txt" -silent -ss -esb -ehb -srd "$WORK/http/screenshots" -rl "${SCREENSHOT_RATE:-3}")
  append_headers shot_args
  run_cmd "HTTP screenshots" "${shot_args[@]}" || warn "screenshot capture failed"
fi

if ((ACTIVE)) && have naabu && [[ -s "$WORK/subs/hosts.txt" ]]; then
  run_cmd "Fast port discovery" naabu -list "$WORK/subs/hosts.txt" -top-ports 1000 -rate "$ACTIVE_RATE" -silent \
    -o "$WORK/active/naabu.txt" || warn "naabu failed"
fi

: > "$WORK/urls/katana.txt"; : > "$WORK/urls/gau.txt"
if [[ -s "$WORK/http/live.txt" ]] && have katana; then
  : > "$WORK/urls/katana.raw"
  katana_args=(katana -list "$WORK/http/live.txt" -silent -d "${KATANA_DEPTH:-5}" -jc -jsl -kf all -fs rdn
    -ef "png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,eot,mp4,mp3" -rl "${KATANA_RATE:-15}" -o "$WORK/urls/katana.raw")
  append_headers katana_args
  run_cmd "Deep authenticated crawl" "${katana_args[@]}" || warn "katana failed"
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
scope_stream < "$WORK/urls/corpus.txt" | sort -u > "$WORK/urls/scoped_corpus.txt"

# Extract JavaScript files, parameters and high-value routes without dropping
# anything from the full corpus. These are additional triage views, not filters.
grep -Ei '\.(m?js)([?#]|$)' "$WORK/urls/scoped_corpus.txt" | sort -u > "$WORK/urls/javascript.txt" || true
grep -E '\?[^#]*=' "$WORK/urls/scoped_corpus.txt" | sort -u > "$WORK/urls/parameterized.txt" || true
grep -Eai '[/._?-](api|admin|auth|graphql|swagger|openapi|internal|debug|upload|export|backup|config|env|git|actuator)([/._?=&-]|$)' \
  "$WORK/urls/scoped_corpus.txt" | sort -u > "$WORK/urls/priority.txt" || true

# Download a capped JS set and perform offline endpoint/secret discovery. The
# evidence is retained verbatim so analysts can validate candidates themselves.
: > "$WORK/urls/js_secrets.tsv"; : > "$WORK/urls/js_endpoints.txt"
if have curl && have python3 && [[ -s "$WORK/urls/javascript.txt" ]] && (( !DRY_RUN )); then
  mkdir -p "$WORK/javascript"
  head -n "${JS_MAX_FILES:-100}" "$WORK/urls/javascript.txt" | while IFS= read -r js; do
    name="$(printf %s "$js" | cksum | cut -d' ' -f1).js"
    curl_auth=(); for h in "${EXTRA_HEADERS[@]}"; do curl_auth+=(-H "$h"); done
    curl -kfsSL --compressed --max-time 20 --max-filesize "${JS_MAX_SIZE:-5242880}" "${curl_auth[@]}" \
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

# API specifications and GraphQL endpoints are first-class attack-surface data.
: > "$WORK/urls/api_specs.tsv"; : > "$WORK/urls/graphql.jsonl"
if have curl && [[ -s "$WORK/http/live.txt" ]] && (( !DRY_RUN )); then
  curl_auth=(); for h in "${EXTRA_HEADERS[@]}"; do curl_auth+=(-H "$h"); done
  while IFS= read -r base; do
    for path in /openapi.json /swagger.json /api-docs /v3/api-docs /swagger/v1/swagger.json /graphql; do
      metrics="$(curl -ksS --max-time 10 "${curl_auth[@]}" -o "$WORK/urls/api_body.tmp" -w '%{http_code}\t%{content_type}\t%{size_download}' "${base%/}$path" 2>/dev/null || printf '000\t-\t0')"
      code="${metrics%%$'\t'*}"
      [[ "$code" =~ ^(200|401|403)$ ]] && printf '%s\t%s\n' "$metrics" "${base%/}$path" >> "$WORK/urls/api_specs.tsv"
    done
    if [[ "${GRAPHQL_INTROSPECTION:-1}" == 1 ]]; then
      payload='{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind } } }"}'
      response="$(curl -ksS --max-time 15 "${curl_auth[@]}" -H 'Content-Type: application/json' --data "$payload" "${base%/}/graphql" 2>/dev/null || true)"
      [[ "$response" == *'__schema'* ]] && printf '%s\t%s\n' "${base%/}/graphql" "$response" >> "$WORK/urls/graphql.jsonl"
    fi
  done < "$WORK/http/live.txt"
  rm -f "$WORK/urls/api_body.tmp"
fi

if ((ACTIVE)) && have arjun && [[ -s "$WORK/urls/scoped_corpus.txt" ]]; then
  head -n "${ARJUN_MAX_URLS:-50}" "$WORK/urls/scoped_corpus.txt" > "$WORK/active/arjun_targets.txt"
  arjun_args=(arjun -i "$WORK/active/arjun_targets.txt" -m GET -T 10 --ratelimit "$ACTIVE_RATE" -oJ "$WORK/active/arjun.json")
  [[ ${#EXTRA_HEADERS[@]} -gt 0 ]] && arjun_args+=(--headers "$(IFS=,; echo "${EXTRA_HEADERS[*]}")")
  run_cmd "Authenticated hidden parameter discovery" "${arjun_args[@]}" || warn "arjun failed"
fi

if ((ACTIVE)); then
  if have nmap && ask_yes "Run conservative Nmap scan?" y; then
    run_cmd "Nmap top ports" nmap -Pn -T3 --top-ports 1000 --open -sV -oN "$WORK/active/nmap.txt" "$HOST" || warn "nmap failed"
  fi
  if have nuclei && [[ -s "$WORK/http/live.txt" ]] && ask_yes "Run focused Nuclei scan?" y; then
    nuclei_args=(nuclei -l "$WORK/http/live.txt" -silent -jsonl -severity "${NUCLEI_SEVERITIES:-medium,high,critical}"
      -rate-limit "$ACTIVE_RATE" -bulk-size "${NUCLEI_BULK:-10}" -concurrency "${NUCLEI_CONCURRENCY:-10}"
      -timeout 10 -retries 1 -disable-update-check -o "$WORK/active/nuclei.jsonl")
    [[ -n "${NUCLEI_TEMPLATES:-}" ]] && nuclei_args+=(-templates "$NUCLEI_TEMPLATES")
    [[ -n "${NUCLEI_TAGS:-}" ]] && nuclei_args+=(-tags "$NUCLEI_TAGS")
    append_headers nuclei_args
    run_cmd "Tuned Nuclei scan" "${nuclei_args[@]}" || warn "nuclei failed"
  fi
  if have ffuf && [[ -n "${FFUF_WORDLIST:-}" && -f "${FFUF_WORDLIST:-}" ]] && [[ -s "$WORK/http/live.txt" ]] && ask_yes "Run recursive path and parameter FFUF?" n; then
    : > "$WORK/active/ffuf_targets.txt"
    while IFS= read -r url; do printf '%s/FUZZ\n' "${url%/}"; done < "$WORK/http/live.txt" >> "$WORK/active/ffuf_targets.txt"
    sed -E 's#^(https?://[^/]+/.*)/[^/?#]*(\?.*)?$#\1/FUZZ#' "$WORK/urls/scoped_corpus.txt" \
      | grep '/FUZZ$' | sort -u | head -n "${FFUF_MAX_PATHS:-75}" >> "$WORK/active/ffuf_targets.txt" || true
    sort -u "$WORK/active/ffuf_targets.txt" -o "$WORK/active/ffuf_targets.txt"
    while IFS= read -r url; do
      hash="$(printf %s "$url" | cksum | cut -d' ' -f1)"
      ffuf_args=(ffuf -w "$FFUF_WORDLIST" -u "$url" -ac -fc 404 -rate "$ACTIVE_RATE" -t "${FFUF_THREADS:-20}"
        -recursion -recursion-depth "${FFUF_RECURSION_DEPTH:-2}" -maxtime "${FFUF_MAXTIME:-300}"
        -noninteractive -of json -o "$WORK/active/ffuf.$hash.json")
      append_headers ffuf_args
      run_cmd "Recursive FFUF $url" "${ffuf_args[@]}" || warn "ffuf failed"
    done < "$WORK/active/ffuf_targets.txt"

    if [[ -n "${PARAM_WORDLIST:-}" && -f "$PARAM_WORDLIST" && -s "$WORK/urls/parameterized.txt" ]]; then
      python3 - "$WORK/urls/parameterized.txt" "$WORK/active/ffuf_param_targets.txt" <<'PY'
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
out=[]
for raw in open(sys.argv[1], errors="ignore"):
    u=urlsplit(raw.strip()); pairs=parse_qsl(u.query, keep_blank_values=True)
    for i, (key, _) in enumerate(pairs):
        changed=pairs.copy(); changed[i]=(key, "FUZZ")
        out.append(urlunsplit((u.scheme,u.netloc,u.path,urlencode(changed),"")))
open(sys.argv[2],"w").write("\n".join(sorted(set(out)))+"\n")
PY
      head -n "${FFUF_MAX_PARAMS:-50}" "$WORK/active/ffuf_param_targets.txt" | while IFS= read -r url; do
        hash="$(printf %s "$url" | cksum | cut -d' ' -f1)"
        param_args=(ffuf -w "$PARAM_WORDLIST" -u "$url" -ac -rate "$ACTIVE_RATE" -t "${FFUF_THREADS:-20}"
          -maxtime "${FFUF_PARAM_MAXTIME:-120}" -noninteractive -of json -o "$WORK/active/ffuf.param.$hash.json")
        append_headers param_args
        run_cmd "Parameter FFUF $url" "${param_args[@]}" || warn "parameter ffuf failed"
      done
    fi
  fi
else
  info "Active stages disabled by --passive."
fi

SCREENSHOT_OUTPUT=""
if ((SCREENSHOTS)) && [[ -d "$WORK/http/screenshots" ]]; then
  (cd "$WORK/http/screenshots" && find . -type f -print0 | sort -z | xargs -0 -r sha256sum) > "$WORK/http/screenshot_manifest.txt"
  if [[ -n "${SCREENSHOT_BASELINE:-}" && -f "$SCREENSHOT_BASELINE" ]]; then
    diff -u "$SCREENSHOT_BASELINE" "$WORK/http/screenshot_manifest.txt" > "$WORK/http/screenshot_diff.txt" || true
  fi
  SCREENSHOT_OUTPUT="$OUT_ROOT/${SAFE_NAME}_${STAMP}_screenshots"
  cp -a "$WORK/http/screenshots" "$SCREENSHOT_OUTPUT"
fi

# Differential 401/403 checks preserve every response metric. A 2xx transition
# is highlighted separately; no candidate is silently discarded.
: > "$WORK/active/access_all.tsv"; : > "$WORK/active/access_candidates.tsv"
if ((ACTIVE)) && have curl && [[ -s "$WORK/urls/priority.txt" ]] && (( !DRY_RUN )); then
  curl_access=(); for h in "${EXTRA_HEADERS[@]}"; do curl_access+=(-H "$h"); done
  metric() { curl -ksS --max-time 12 "${curl_access[@]}" -o /dev/null -w '%{http_code}\t%{size_download}\t%{url_effective}' "$@" 2>/dev/null || printf '000\t0\t-'; }
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
    "DNS|$WORK/dns/records.txt" "ALL DISCOVERED HOSTS|$WORK/subs/all_hosts.txt" "SCOPED HOSTS|$WORK/subs/hosts.txt" \
    "LIVE URLS|$WORK/http/live.txt" "HTTP DETAILS|$WORK/http/details.jsonl" \
    "TECHNOLOGY CORRELATION|$WORK/http/technology_summary.tsv" \
    "SCREENSHOT MANIFEST|$WORK/http/screenshot_manifest.txt" "SCREENSHOT DIFF|$WORK/http/screenshot_diff.txt" \
    "CRAWLED URLS|$WORK/urls/katana.txt" "HISTORICAL URLS|$WORK/urls/gau.txt" \
    "WAYBACK URLS|$WORK/urls/wayback.txt" "FULL ENDPOINT CORPUS|$WORK/urls/corpus.txt" \
    "SCOPED OPERATIONAL CORPUS|$WORK/urls/scoped_corpus.txt" \
    "API SPEC CANDIDATES|$WORK/urls/api_specs.tsv" "GRAPHQL INTROSPECTION|$WORK/urls/graphql.jsonl" \
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
  [[ -n "$SCREENSHOT_OUTPUT" ]] && printf 'Screenshot directory: %s\n' "$SCREENSHOT_OUTPUT"
} > "$REPORT_TMP"
mv -f -- "$REPORT_TMP" "$REPORT"
printf '[+] Report created: %s\n' "$REPORT"
