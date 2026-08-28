#!/usr/bin/env bash
# AutoRecon V7.3.0 - raw-evidence reconnaissance and attack-surface workflow.

set -uo pipefail
IFS=$'\n\t'

VERSION="7.3.0"
AUTO=0 DRY_RUN=0 ACTIVE=1 KEEP_TEMP=0
SCOPE_MODE="all" SCREENSHOTS="${SCREENSHOTS:-0}" INCLUDE_PRIVATE=1
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
  --passive          disable Nmap, FFUF, Arjun and access checks
  --dry-run          print commands without network activity
  --output-dir DIR   report directory (default: $OUT_ROOT)
  --keep-temp        retain working directory for debugging
  --header VALUE     add an HTTP header (repeatable)
  --cookie VALUE     add a Cookie header
  --raw-mode         retain/process all discoveries (default)
  --strict-scope     restrict active tools to the seed and its subdomains
  --screenshots      capture HTTP screenshots when supported
  --include-private  include RFC1918 targets (default)
  --exclude-private  preserve but do not actively scan RFC1918 targets
  -h, --help         show this help

Environment: HTTPX_RATE, ACTIVE_RATE, COMMAND_TIMEOUT, BB_USER_AGENT,
             FFUF_WORDLIST, PARAM_WORDLIST, GRAPHQL_INTROSPECTION,
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
    --raw-mode|--no-scope) SCOPE_MODE="all"; INCLUDE_PRIVATE=1 ;;
    --strict-scope) SCOPE_MODE="seed" ;;
    --screenshots) SCREENSHOTS=1 ;;
    --include-private) INCLUDE_PRIVATE=1 ;;
    --exclude-private) INCLUDE_PRIVATE=0 ;;
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
STAGES="$WORK/stages.tsv"
: > "$STAGES"

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
  if ((DRY_RUN)); then
    printf '[DRY-RUN]'; local redact=0 arg
    for arg in "$@"; do
      if ((redact)); then printf ' %q' '<redacted>'; redact=0
      elif [[ "$arg" == -H || "$arg" == --headers ]]; then printf ' %q' "$arg"; redact=1
      elif [[ "$arg" == Authorization:* || "$arg" == Cookie:* ]]; then printf ' %q' '<redacted-header>'
      else printf ' %q' "$arg"; fi
    done
    printf '\n'; return 0
  fi
  if have timeout; then timeout --signal=TERM --kill-after=10 "$COMMAND_TIMEOUT" "$@"; else "$@"; fi
}

sanitize_file() {
  local source="$1" destination="$2"
  sed -E 's/(Authorization:|Cookie:|Bearer)[[:space:]]+[^[:space:]]+/\1 <redacted>/Ig; s/(session|token|secret)=([^&[:space:]]+)/\1=<redacted>/Ig' \
    "$source" > "$destination" 2>/dev/null || : > "$destination"
}

result_count() { [[ -s "$1" ]] && awk 'END{print NR+0}' "$1" 2>/dev/null || echo 0; }
stage_record() {
  local name="$1" status="$2" reason="$3" rc="$4" result="${5:-}" error="${6:-}" count=0 safe_error=""
  [[ -n "$result" ]] && count="$(result_count "$result")"
  if [[ -s "$error" ]]; then sanitize_file "$error" "$error.safe"; safe_error="$(tr '\n\t' '  ' < "$error.safe" | cut -c1-500)"; fi
  reason="$(printf %s "$reason" | tr '\n\t' '  ')"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$status" "$reason" "$rc" "$count" "$safe_error" >> "$STAGES"
}

stage_from_rc() {
  local name="$1" rc="$2" result="$3" success_reason="$4" error="${5:-}"
  if ((rc == 0)); then stage_record "$name" completed "$success_reason" "$rc" "$result" "$error"
  elif [[ -s "$result" ]]; then stage_record "$name" partial "tool exited non-zero; usable output retained" "$rc" "$result" "$error"
  else stage_record "$name" failed "tool exited without usable output" "$rc" "$result" "$error"; fi
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

valid_api_spec() {
  have python3 || return 1
  python3 - "$1" <<'PY'
import json, pathlib, re, sys
try:
    obj=json.loads(pathlib.Path(sys.argv[1]).read_text(errors="ignore"))
except Exception:
    raise SystemExit(1)
if not isinstance(obj, dict) or not isinstance(obj.get("paths"), dict):
    raise SystemExit(1)
version=obj.get("openapi") or obj.get("swagger")
raise SystemExit(0 if isinstance(version, str) and re.match(r"^(?:2\.0|3\.\d+(?:\.\d+)?)$", version) else 1)
PY
}

is_auth_header() {
  local name="${1%%:*}"
  case "${name,,}" in authorization|proxy-authorization|cookie|x-api-key|api-key|x-auth-token) return 0 ;; *) return 1 ;; esac
}

AUTH_MATERIAL_CONFIGURED=0 AUTH_PLACEHOLDER_WARNINGS=0
for header in "${EXTRA_HEADERS[@]}"; do
  is_auth_header "$header" || continue
  value="${header#*:}"; value="${value# }"
  if [[ -z "$value" || "$value" =~ (^|[=:[:space:]])(TOKEN|SESSION_VALUE|VALUE|CHANGEME|REPLACE_ME)($|[;[:space:]]) || "$header" =~ ^Cookie:[[:space:]]*[^=]*=$ ]]; then
    ((AUTH_PLACEHOLDER_WARNINGS++)); warn "authentication header contains an empty or obvious placeholder value (value redacted)"
  else
    ((AUTH_MATERIAL_CONFIGURED++))
  fi
done

TOOLS=(dig subfinder assetfinder amass dnsx tlsx httpx naabu katana gau waybackurls arjun jq curl nmap ffuf python3)
{
  printf 'AutoRecon %s\nTarget: %s\nStarted: %s\nActive automation: %s\nScope mode: %s\nAuthentication material configured: %s\nPlaceholder warnings: %s\nAuthentication validated: not-tested\n\n' \
    "$VERSION" "$HOST" "$(date -Is)" "$ACTIVE" "$SCOPE_MODE" "$AUTH_MATERIAL_CONFIGURED" "$AUTH_PLACEHOLDER_WARNINGS"
  echo '[TOOL INVENTORY]'
  for tool in "${TOOLS[@]}"; do
    if have "$tool"; then printf 'present\t%s\t%s\n' "$tool" "$(command -v "$tool")"; else printf 'missing\t%s\n' "$tool"; fi
  done
} > "$WORK/meta.txt"

if (( !is_ipv4 )) && have dig; then
  dns_rc=0; : > "$WORK/dns/records.txt"
  for rr in A AAAA CNAME MX NS TXT CAA SOA; do
    printf '### %s\n' "$rr" >> "$WORK/dns/records.txt"
    run_cmd "DNS $rr" dig +time=3 +tries=1 +short "$rr" "$HOST" >> "$WORK/dns/records.txt" 2>>"$WORK/dns/dns.err"; rc=$?
    ((rc != 0)) && dns_rc="$rc"
  done
  stage_from_rc dns "$dns_rc" "$WORK/dns/records.txt" "DNS queries completed" "$WORK/dns/dns.err"
else
  stage_record dns skipped "IP target or dig unavailable" 0
fi

: > "$WORK/subs/hosts.txt"
sub_sources=0 sub_rc=0
if (( !is_ipv4 )) && have subfinder; then
  ((sub_sources++)); run_cmd "Passive subdomain enumeration" subfinder -d "$HOST" -silent -rl 10 -o "$WORK/subs/raw.txt" 2>>"$WORK/subs/enumeration.err"; rc=$?; ((rc != 0)) && sub_rc="$rc"
fi
if (( !is_ipv4 )) && have assetfinder; then
  ((sub_sources++)); run_cmd "Assetfinder enumeration" assetfinder --subs-only "$HOST" > "$WORK/subs/assetfinder.txt" 2>>"$WORK/subs/enumeration.err"; rc=$?; ((rc != 0)) && sub_rc="$rc"
fi
if (( !is_ipv4 )) && have amass; then
  ((sub_sources++)); run_cmd "Amass passive enumeration" amass enum -passive -d "$HOST" -o "$WORK/subs/amass.txt" 2>>"$WORK/subs/enumeration.err"; rc=$?; ((rc != 0)) && sub_rc="$rc"
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
    -o "$WORK/subs/resolved.txt" 2>"$WORK/subs/dnsx.err"; rc=$?
  stage_from_rc dnsx "$rc" "$WORK/subs/resolved.txt" "resolution completed" "$WORK/subs/dnsx.err"
else
  stage_record dnsx skipped "dnsx unavailable or no scoped hosts" 0
fi
if ((is_ipv4)); then stage_record subdomains skipped "IP target" 0
elif ((sub_sources == 0)); then stage_record subdomains skipped "no subdomain enumeration tools available; seed retained" 0 "$WORK/subs/hosts.txt"
else stage_from_rc subdomains "$sub_rc" "$WORK/subs/hosts.txt" "multi-source results aggregated; raw and scoped lists retained" "$WORK/subs/enumeration.err"; fi

: > "$WORK/subs/private_dns.txt"; : > "$WORK/subs/private_hosts.txt"
if have python3 && [[ -s "$WORK/subs/resolved.txt" ]]; then
  python3 - "$WORK/subs/resolved.txt" "$WORK/subs/private_dns.txt" "$WORK/subs/private_hosts.txt" <<'PY'
import ipaddress, pathlib, re, sys
lines=[]; hosts=set()
for line in pathlib.Path(sys.argv[1]).read_text(errors="ignore").splitlines():
    ips=[]
    for raw in re.findall(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])", line):
        try:
            ip=ipaddress.ip_address(raw)
            if ip.is_private: ips.append(raw)
        except ValueError: pass
    if ips:
        lines.append(line); hosts.add(line.split()[0].rstrip("."))
pathlib.Path(sys.argv[2]).write_text("\n".join(lines) + ("\n" if lines else ""))
pathlib.Path(sys.argv[3]).write_text("\n".join(sorted(hosts)) + ("\n" if hosts else ""))
PY
fi
if ((INCLUDE_PRIVATE)); then
  cp "$WORK/subs/hosts.txt" "$WORK/subs/active_hosts.txt"
else
  sort -u "$WORK/subs/hosts.txt" > "$WORK/subs/hosts.sorted"
  sort -u "$WORK/subs/private_hosts.txt" > "$WORK/subs/private.sorted"
  comm -23 "$WORK/subs/hosts.sorted" "$WORK/subs/private.sorted" > "$WORK/subs/active_hosts.txt"
fi
stage_record private_dns completed "RFC1918 DNS evidence preserved; active scanning requires --include-private" 0 "$WORK/subs/private_dns.txt"

: > "$WORK/subs/tls_sans.txt"
if have tlsx && [[ -s "$WORK/subs/hosts.txt" ]]; then
  run_cmd "TLS certificate and SAN discovery" tlsx -l "$WORK/subs/hosts.txt" -san -cn -so -silent \
    -o "$WORK/subs/tls_sans.txt" 2>"$WORK/subs/tlsx.err"; rc=$?
  stage_from_rc tls "$rc" "$WORK/subs/tls_sans.txt" "certificate metadata and SANs collected" "$WORK/subs/tlsx.err"
  grep -Eo '([A-Za-z0-9_-]+\.)+[A-Za-z]{2,63}' "$WORK/subs/tls_sans.txt" | tr '[:upper:]' '[:lower:]' | sort -u > "$WORK/subs/tls_hosts.txt" || true
  if [[ "$SCOPE_MODE" == all ]]; then
    cat "$WORK/subs/hosts.txt" "$WORK/subs/tls_hosts.txt" | sort -u > "$WORK/subs/hosts.plus-tls"
  else
    { cat "$WORK/subs/hosts.txt"; while IFS= read -r h; do [[ "$h" == "$HOST" || "$h" == *."$HOST" ]] && echo "$h"; done < "$WORK/subs/tls_hosts.txt"; } \
      | sort -u > "$WORK/subs/hosts.plus-tls"
  fi
  mv "$WORK/subs/hosts.plus-tls" "$WORK/subs/hosts.txt"
  if ((INCLUDE_PRIVATE)); then cp "$WORK/subs/hosts.txt" "$WORK/subs/active_hosts.txt"; fi
else
  stage_record tls skipped "tlsx unavailable or no hosts" 0
fi

: > "$WORK/http/live.txt"; : > "$WORK/http/details.jsonl"
if have httpx; then
  if ((DRY_RUN)); then echo "https://$HOST" > "$WORK/http/live.txt"; fi
  http_live=(httpx -l "$WORK/subs/hosts.txt" -silent -nf -rl "$HTTPX_RATE" -timeout 10 -o "$WORK/http/live.txt")
  append_headers http_live
  run_cmd "HTTP reachability" "${http_live[@]}" 2>"$WORK/http/live.err"; http_rc=$?
  if [[ -s "$WORK/http/live.txt" ]]; then
    http_details=(httpx -l "$WORK/http/live.txt" -silent -json -sc -cl -ct -title -td -server
      -ip -cname -cdn -location -rt -rl "$HTTPX_RATE" -o "$WORK/http/details.jsonl")
    append_headers http_details
    run_cmd "HTTP fingerprinting" "${http_details[@]}" 2>"$WORK/http/details.err"; details_rc=$?
    cp "$WORK/http/details.jsonl" "$WORK/http/details.raw.jsonl"
    # Normalize URL identity and retain one detail record per endpoint.
    if have python3 && [[ -s "$WORK/http/details.jsonl" ]]; then
      python3 - "$WORK/http/details.jsonl" <<'PY'
import json, pathlib, sys
from urllib.parse import urlsplit, urlunsplit
p=pathlib.Path(sys.argv[1]); unique={}
for line in p.read_text(errors="ignore").splitlines():
    try: obj=json.loads(line)
    except Exception: continue
    raw=obj.get("url") or obj.get("input") or ""
    try:
        u=urlsplit(raw); port=u.port
        host=(u.hostname or "").lower()
        netloc=host if port in (None,80,443) else f"{host}:{port}"
        key=urlunsplit((u.scheme.lower(),netloc,u.path.rstrip("/") or "/",u.query,""))
    except Exception: key=raw.lower().rstrip("/")
    unique[key]=obj
p.write_text("".join(json.dumps(v,separators=(",",":"))+"\n" for v in unique.values()))
PY
    fi
  fi
  cp "$WORK/http/live.txt" "$WORK/http/live.raw.txt"
  if have python3 && [[ -s "$WORK/http/live.txt" ]]; then
    python3 - "$WORK/http/live.txt" <<'PY'
import pathlib, sys
from urllib.parse import urlsplit, urlunsplit
p=pathlib.Path(sys.argv[1]); unique={}
for raw in p.read_text(errors="ignore").splitlines():
    try:
        u=urlsplit(raw.strip()); port=u.port; host=(u.hostname or "").lower()
        netloc=host if port in (None,80,443) else f"{host}:{port}"
        normalized=urlunsplit((u.scheme.lower(),netloc,u.path.rstrip("/") or "",u.query,""))
    except Exception: normalized=raw.strip().lower().rstrip("/")
    unique[normalized]=normalized
p.write_text("\n".join(sorted(unique))+("\n" if unique else ""))
PY
  else
    sort -fu "$WORK/http/live.txt" -o "$WORK/http/live.txt"
  fi
  combined_rc=$(( http_rc != 0 ? http_rc : ${details_rc:-0} ))
  stage_from_rc httpx "$combined_rc" "$WORK/http/live.txt" "reachability and fingerprinting completed" "$WORK/http/live.err"
else
  stage_record httpx skipped "httpx unavailable" 0
fi

: > "$WORK/http/auth_validation.tsv"
if [[ "$AUTH_MATERIAL_CONFIGURED" -gt 0 && -n "${AUTH_CHECK_URL:-}" ]] && have curl && (( !DRY_RUN )); then
  if in_scope_url "$AUTH_CHECK_URL"; then
    curl_auth=(); for h in "${EXTRA_HEADERS[@]}"; do curl_auth+=(-H "$h"); done
    unauth_code="$(curl -ksS --max-time 10 -o /dev/null -w '%{http_code}' "$AUTH_CHECK_URL" 2>/dev/null || echo 000)"
    auth_code="$(curl -ksS --max-time 10 "${curl_auth[@]}" -o /dev/null -w '%{http_code}' "$AUTH_CHECK_URL" 2>/dev/null || echo 000)"
    if [[ "$unauth_code" =~ ^(401|403)$ && "$auth_code" =~ ^2 ]]; then
      printf 'validated-differential\tunauth=%s\tauth=%s\n' "$unauth_code" "$auth_code" > "$WORK/http/auth_validation.tsv"
    else
      printf 'inconclusive\tunauth=%s\tauth=%s\n' "$unauth_code" "$auth_code" > "$WORK/http/auth_validation.tsv"
    fi
  else
    printf 'not-tested\tout-of-scope-validation-url\n' > "$WORK/http/auth_validation.tsv"
  fi
else
  printf 'not-tested\t%s\n' "$([[ "$AUTH_MATERIAL_CONFIGURED" -gt 0 ]] && echo AUTH_CHECK_URL-not-set || echo no-auth-material)" > "$WORK/http/auth_validation.tsv"
fi
auth_validation_state="$(cut -f1 "$WORK/http/auth_validation.tsv")"
if [[ "$auth_validation_state" == not-tested ]]; then
  stage_record authentication_validation skipped "$(cut -f2- "$WORK/http/auth_validation.tsv")" 0
elif grep -q '=000' "$WORK/http/auth_validation.tsv"; then
  stage_record authentication_validation failed "authentication validation request failed" 1 "$WORK/http/auth_validation.tsv"
else
  stage_record authentication_validation completed "safe authenticated/unauthenticated differential recorded" 0 "$WORK/http/auth_validation.tsv"
fi

: > "$WORK/http/technology_summary.tsv"
if have jq && [[ -s "$WORK/http/details.jsonl" ]]; then
  jq -r '[.url // .input // "", ((.tech // .technologies // []) | if type == "array" then join(",") else tostring end), .webserver // "", .cdn_name // ""] | @tsv' \
    "$WORK/http/details.jsonl" | sort -u > "$WORK/http/technology_summary.tsv" || true
fi
if [[ -s "$WORK/http/details.jsonl" ]]; then
  stage_record technology completed "technology summary correlated from deduplicated HTTP details" 0 "$WORK/http/technology_summary.tsv"
else
  stage_record technology skipped "no HTTP details available" 0
fi
if ((SCREENSHOTS)) && have httpx && [[ -s "$WORK/http/live.txt" ]]; then
  mkdir -p "$WORK/http/screenshots"
  shot_args=(httpx -l "$WORK/http/live.txt" -silent -ss -esb -ehb -srd "$WORK/http/screenshots" -rl "${SCREENSHOT_RATE:-3}")
  append_headers shot_args
  if httpx -h 2>&1 | grep -q -- '-ss'; then
    run_cmd "HTTP screenshots" "${shot_args[@]}" 2>"$WORK/http/screenshots.err"; shot_rc=$?
    find "$WORK/http/screenshots" -type f > "$WORK/http/screenshots.files"
    if ((shot_rc == 0)) && [[ ! -s "$WORK/http/screenshots.files" ]]; then
      stage_record screenshots failed "httpx exited successfully but produced no screenshot artifacts" 0 "$WORK/http/screenshots.files" "$WORK/http/screenshots.err"
    else
      stage_from_rc screenshots "$shot_rc" "$WORK/http/screenshots.files" "screenshots captured" "$WORK/http/screenshots.err"
    fi
  else
    stage_record screenshots skipped "installed httpx does not support screenshots" 0
  fi
elif (( !SCREENSHOTS )); then
  stage_record screenshots skipped "disabled; enable with --screenshots or SCREENSHOTS=1" 0
elif ! have httpx; then
  stage_record screenshots skipped "httpx unavailable" 0
else
  stage_record screenshots skipped "no live URLs" 0
fi

if ((ACTIVE)) && have naabu && [[ -s "$WORK/subs/active_hosts.txt" ]]; then
  run_cmd "Fast port discovery" naabu -list "$WORK/subs/active_hosts.txt" -top-ports 1000 -rate "$ACTIVE_RATE" -silent \
    -o "$WORK/active/naabu.txt" 2>"$WORK/active/naabu.err"; rc=$?
  stage_from_rc naabu "$rc" "$WORK/active/naabu.txt" "port discovery completed" "$WORK/active/naabu.err"
else
  stage_record naabu skipped "passive mode, naabu unavailable, or no scoped hosts" 0
fi

: > "$WORK/urls/katana.txt"; : > "$WORK/urls/gau.txt"
if [[ -s "$WORK/http/live.txt" ]] && have katana; then
  : > "$WORK/urls/katana.raw"
  katana_args=(katana -list "$WORK/http/live.txt" -silent -d "${KATANA_DEPTH:-5}" -jc -jsl -kf all -fs rdn
    -rl "${KATANA_RATE:-15}" -o "$WORK/urls/katana.raw")
  append_headers katana_args
  run_cmd "Deep authenticated crawl" "${katana_args[@]}" 2>"$WORK/urls/katana.err"; katana_rc=$?
  sort -u "$WORK/urls/katana.raw" > "$WORK/urls/katana.txt"
  stage_from_rc katana "$katana_rc" "$WORK/urls/katana.txt" "crawl completed" "$WORK/urls/katana.err"
else
  stage_record katana skipped "katana unavailable or no live URLs" 0
fi
archive_ran=0 archive_rc=0
if (( !is_ipv4 )) && have gau; then
  archive_ran=1
  : > "$WORK/urls/gau.raw"
  run_cmd "Historical URL collection" gau --subs --threads 3 --timeout 15 --o "$WORK/urls/gau.raw" "$HOST" 2>"$WORK/urls/archives.err"; rc=$?; ((rc != 0)) && archive_rc="$rc"
  sort -u "$WORK/urls/gau.raw" > "$WORK/urls/gau.txt"
fi
if (( !is_ipv4 )) && have waybackurls; then
  archive_ran=1
  run_cmd "Wayback URL collection" waybackurls "$HOST" > "$WORK/urls/wayback.txt" 2>>"$WORK/urls/archives.err"; rc=$?; ((rc != 0)) && archive_rc="$rc"
fi
cat "$WORK/urls/gau.txt" "$WORK/urls/wayback.txt" 2>/dev/null | sort -u > "$WORK/urls/archives.txt"
if ((archive_ran)); then stage_from_rc archives "$archive_rc" "$WORK/urls/archives.txt" "historical URL sources processed" "$WORK/urls/archives.err"
else stage_record archives skipped "historical tools unavailable or IP target" 0; fi
cat "$WORK/http/live.txt" "$WORK/urls/katana.txt" "$WORK/urls/gau.txt" 2>/dev/null \
  "$WORK/urls/wayback.txt" \
  | sed 's/#.*//' | awk 'NF' | sort -u > "$WORK/urls/corpus.txt"
scope_stream < "$WORK/urls/corpus.txt" | sort -u > "$WORK/urls/scoped_corpus.txt"
stage_record corpus completed "raw corpus retained and operational corpus scope-enforced" 0 "$WORK/urls/scoped_corpus.txt"

# Extract JavaScript files, parameters and high-value routes without dropping
# anything from the full corpus. These are additional triage views, not filters.
grep -Ei '\.(m?js)([?#]|$)' "$WORK/urls/scoped_corpus.txt" | sort -u > "$WORK/urls/javascript.txt" || true
grep -E '\?[^#]*=' "$WORK/urls/scoped_corpus.txt" | sort -u > "$WORK/urls/parameterized.txt" || true
grep -Eai '[/._?-](api|admin|auth|graphql|swagger|openapi|internal|debug|upload|export|backup|config|env|git|actuator)([/._?=&-]|$)' \
  "$WORK/urls/scoped_corpus.txt" | sort -u > "$WORK/urls/priority.txt" || true

# Download a capped JS set and perform offline endpoint/secret discovery. The
# evidence is retained verbatim so analysts can validate candidates themselves.
: > "$WORK/urls/js_secrets_raw.tsv"; : > "$WORK/urls/js_secrets.tsv"; : > "$WORK/urls/js_endpoints.txt"; : > "$WORK/urls/grpc_web.tsv"; : > "$WORK/urls/source_maps.tsv"
js_ran=0
if have curl && have python3 && [[ -s "$WORK/urls/javascript.txt" ]] && (( !DRY_RUN )); then
  js_ran=1
  mkdir -p "$WORK/javascript"
  head -n "${JS_MAX_FILES:-100}" "$WORK/urls/javascript.txt" | while IFS= read -r js; do
    name="$(printf %s "$js" | cksum | cut -d' ' -f1).js"
    curl_auth=(); for h in "${EXTRA_HEADERS[@]}"; do curl_auth+=(-H "$h"); done
    curl -kfsSL --compressed --max-time 20 --max-filesize "${JS_MAX_SIZE:-5242880}" "${curl_auth[@]}" \
      -A "${BB_USER_AGENT:-Mozilla/5.0 AutoRecon-V7}" "$js" -o "$WORK/javascript/$name" 2>/dev/null && \
      printf '%s\t%s\n' "$js" "$WORK/javascript/$name" >> "$WORK/urls/js_map.tsv"
  done
  python3 - "$WORK/urls/js_map.tsv" "$WORK/urls/js_secrets_raw.tsv" "$WORK/urls/js_secrets.tsv" "$WORK/urls/js_endpoints.txt" "$WORK/urls/grpc_web.tsv" <<'PY'
import pathlib, re, sys
from urllib.parse import urljoin
mapping, raw_out, secrets_out, endpoints_out, grpc_out = sys.argv[1:]
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
found, endpoints, grpc = [], set(), set()
p = pathlib.Path(mapping)
for row in p.read_text(errors="ignore").splitlines() if p.exists() else []:
    if "\t" not in row: continue
    source, filename = row.split("\t", 1)
    text = pathlib.Path(filename).read_text(errors="ignore")
    for label, raw in patterns.items():
        for match in re.finditer(raw, text):
            line = text.count("\n", 0, match.start()) + 1
            evidence=match.group(0)[:500].replace("\t", " ")
            low=evidence.lower().replace(' ', '')
            confidence="high" if label != "secret_assignment" else "medium"
            context="token-format" if label != "secret_assignment" else "assignment"
            if any(x in low for x in ('password="password"', "password='password'", 'token="token"', 'secret="secret"', 'changeme', 'example')):
                confidence="low"; context="placeholder-or-example"
            found.append((source, str(line), confidence, context, label, evidence))
    endpoints.update(m.group(0).rstrip(");,]}") for m in url_rx.finditer(text))
    endpoints.update(urljoin(source, m.group(1)) for m in path_rx.finditer(text))
    for m in re.finditer(r'''(?i)(?:grpc[-_]?web|service|method)["'\s:=]+([A-Za-z_][\w.]*)''', text):
        grpc.add((source, m.group(1)))
pathlib.Path(raw_out).write_text("".join("\t".join((x[0],x[1],x[4],x[5]))+"\n" for x in found))
pathlib.Path(secrets_out).write_text("".join("\t".join(x)+"\n" for x in found))
pathlib.Path(endpoints_out).write_text("".join(x+"\n" for x in sorted(endpoints)))
pathlib.Path(grpc_out).write_text("".join("\t".join(x)+"\n" for x in sorted(grpc)))
PY
  curl_auth=(); for h in "${EXTRA_HEADERS[@]}"; do curl_auth+=(-H "$h"); done
  head -n "${SOURCE_MAP_MAX_FILES:-40}" "$WORK/urls/javascript.txt" | while IFS= read -r js; do
    map_url="${js%%\?*}.map"
    map_code="$(curl -ksS --max-time 10 "${curl_auth[@]}" -o "$WORK/urls/source_map.tmp" -w '%{http_code}' "$map_url" 2>/dev/null || echo 000)"
    if [[ "$map_code" == 200 ]] && grep -Eq '"(sources|sourceRoot|mappings)"[[:space:]]*:' "$WORK/urls/source_map.tmp"; then
      printf '200\tvalidated-source-map\t%s\n' "$map_url" >> "$WORK/urls/source_maps.tsv"
    fi
  done
  rm -f "$WORK/urls/source_map.tmp"
fi
cat "$WORK/urls/js_endpoints.txt" "$WORK/urls/js_secrets.tsv" "$WORK/urls/grpc_web.tsv" "$WORK/urls/source_maps.tsv" 2>/dev/null > "$WORK/urls/js_results.txt"
if ((js_ran)); then stage_record javascript completed "offline endpoint, classified secret, passive gRPC-Web, and source-map extraction completed" 0 "$WORK/urls/js_results.txt"
else stage_record javascript skipped "dry-run, dependencies unavailable, or no JavaScript URLs" 0; fi

# API specifications and GraphQL endpoints are first-class attack-surface data.
: > "$WORK/urls/api_specs.tsv"; : > "$WORK/urls/api_candidates.tsv"; : > "$WORK/urls/graphql.jsonl"; : > "$WORK/urls/graphql_raw.tsv"; : > "$WORK/urls/scim.tsv"; : > "$WORK/urls/oidc.tsv"; : > "$WORK/urls/focused_probes_raw.tsv"
printf 'master\n' > "$WORK/urls/realm_candidates.txt"
sed -nE 's#.*(/auth)?/realms/([^/?#]+).*#\2#p' "$WORK/urls/scoped_corpus.txt" | sort -u >> "$WORK/urls/realm_candidates.txt"
sort -u "$WORK/urls/realm_candidates.txt" -o "$WORK/urls/realm_candidates.txt"
api_ran=0
if have curl && [[ -s "$WORK/http/live.txt" ]] && (( !DRY_RUN )); then
  api_ran=1
  curl_auth=(); for h in "${EXTRA_HEADERS[@]}"; do curl_auth+=(-H "$h"); done
  while IFS= read -r base; do
    for path in /openapi.json /swagger.json /api-docs /v3/api-docs /swagger/v1/swagger.json /graphql; do
      metrics="$(curl -ksS --max-time 10 "${curl_auth[@]}" -o "$WORK/urls/api_body.tmp" -w '%{http_code}\t%{content_type}\t%{size_download}' "${base%/}$path" 2>/dev/null || printf '000\t-\t0')"
      printf 'api\t%s\t%s\n' "$metrics" "${base%/}$path" >> "$WORK/urls/focused_probes_raw.tsv"
      code="${metrics%%$'\t'*}"
      if [[ "$code" == 200 ]] && valid_api_spec "$WORK/urls/api_body.tmp"; then
        printf '%s\tvalidated-signature\t%s\n' "$metrics" "${base%/}$path" >> "$WORK/urls/api_specs.tsv"
      elif [[ "$code" =~ ^(200|401|403)$ ]]; then
        printf '%s\tprotected-or-uncertain\t%s\n' "$metrics" "${base%/}$path" >> "$WORK/urls/api_candidates.tsv"
      fi
    done
    if [[ "${GRAPHQL_INTROSPECTION:-1}" == 1 ]]; then
      payload='{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind } } }"}'
      response="$(curl -ksS --max-time 15 "${curl_auth[@]}" -H 'Content-Type: application/json' --data "$payload" "${base%/}/graphql" 2>/dev/null || true)"
      printf '%s\t%s\n' "${base%/}/graphql" "$response" >> "$WORK/urls/graphql_raw.tsv"
      [[ "$response" == *'__schema'* ]] && printf '%s\t%s\n' "${base%/}/graphql" "$response" >> "$WORK/urls/graphql.jsonl"
    fi
    for path in /scim/v2/ServiceProviderConfig /scim/v2/ResourceTypes /scim/v2/Schemas '/scim/v2/Users?count=1' '/scim/v2/Groups?count=1'; do
      metrics="$(curl -ksS --max-time 10 "${curl_auth[@]}" -o /dev/null -w '%{http_code}\t%{content_type}\t%{size_download}' "${base%/}$path" 2>/dev/null || printf '000\t-\t0')"
      printf 'scim\t%s\t%s\n' "$metrics" "${base%/}$path" >> "$WORK/urls/focused_probes_raw.tsv"
      [[ "${metrics%%$'\t'*}" != 404 && "${metrics%%$'\t'*}" != 000 ]] && printf '%s\t%s\n' "$metrics" "${base%/}$path" >> "$WORK/urls/scim.tsv"
    done
    for path in /.well-known/openid-configuration /admin /resources; do
      metrics="$(curl -ksS --max-time 10 "${curl_auth[@]}" -o /dev/null -w '%{http_code}\t%{content_type}\t%{size_download}' "${base%/}$path" 2>/dev/null || printf '000\t-\t0')"
      printf 'oidc-surface\t%s\t%s\n' "$metrics" "${base%/}$path" >> "$WORK/urls/focused_probes_raw.tsv"
      [[ "${metrics%%$'\t'*}" != 404 && "${metrics%%$'\t'*}" != 000 ]] && printf '%s\t%s\n' "$metrics" "${base%/}$path" >> "$WORK/urls/oidc.tsv"
    done
    while IFS= read -r realm; do
      for prefix in /realms /auth/realms; do
        path="$prefix/$realm/.well-known/openid-configuration"
        metrics="$(curl -ksS --max-time 10 "${curl_auth[@]}" -o "$WORK/urls/oidc_body.tmp" -w '%{http_code}\t%{content_type}\t%{size_download}' "${base%/}$path" 2>/dev/null || printf '000\t-\t0')"
        printf 'oidc-realm\t%s\t%s\n' "$metrics" "${base%/}$path" >> "$WORK/urls/focused_probes_raw.tsv"
        if [[ "${metrics%%$'\t'*}" == 200 ]] && grep -Eq '"(issuer|authorization_endpoint|token_endpoint)"[[:space:]]*:' "$WORK/urls/oidc_body.tmp"; then
          printf '%s\tvalidated-oidc\trealm=%s\t%s\n' "$metrics" "$realm" "${base%/}$path" >> "$WORK/urls/oidc.tsv"
        elif [[ "${metrics%%$'\t'*}" =~ ^(401|403)$ ]]; then
          printf '%s\tprotected-realm\trealm=%s\t%s\n' "$metrics" "$realm" "${base%/}$path" >> "$WORK/urls/oidc.tsv"
        fi
      done
    done < "$WORK/urls/realm_candidates.txt"
  done < "$WORK/http/live.txt"
  rm -f "$WORK/urls/api_body.tmp" "$WORK/urls/oidc_body.tmp"
fi
cat "$WORK/urls/focused_probes_raw.tsv" "$WORK/urls/api_specs.tsv" "$WORK/urls/api_candidates.tsv" "$WORK/urls/graphql_raw.tsv" "$WORK/urls/scim.tsv" "$WORK/urls/oidc.tsv" 2>/dev/null > "$WORK/urls/api_results.tsv"
if ((api_ran)); then stage_record api_discovery completed "validated specs separated from protected/uncertain candidates; read-only SCIM/OIDC/GraphQL probes completed" 0 "$WORK/urls/api_results.tsv"
else stage_record api_discovery skipped "dry-run, curl unavailable, or no live URLs" 0; fi

# Preserve raw read-only web intelligence: well-known files, headers, policy
# documents, accidental metadata, CORS behavior, CSP references, and cookies.
: > "$WORK/urls/web_intel.tsv"; : > "$WORK/urls/csp_references.txt"
web_intel_ran=0
if have curl && [[ -s "$WORK/http/live.txt" ]] && (( !DRY_RUN )); then
  web_intel_ran=1; mkdir -p "$WORK/urls/web_intel_bodies" "$WORK/urls/web_intel_headers"
  curl_auth=(); for h in "${EXTRA_HEADERS[@]}"; do curl_auth+=(-H "$h"); done
  head -n "${WEB_INTEL_MAX_HOSTS:-50}" "$WORK/http/live.txt" | while IFS= read -r base; do
    for path in /robots.txt /sitemap.xml /.well-known/security.txt /crossdomain.xml /clientaccesspolicy.xml /.git/HEAD /.env /server-status; do
      key="$(printf '%s' "${base%/}$path" | cksum | cut -d' ' -f1)"
      metrics="$(curl -ksS --max-time 12 --max-filesize "${WEB_INTEL_MAX_SIZE:-524288}" "${curl_auth[@]}" -H 'Origin: https://attacker.invalid' \
        -D "$WORK/urls/web_intel_headers/$key.txt" -o "$WORK/urls/web_intel_bodies/$key.txt" \
        -w '%{http_code}\t%{content_type}\t%{size_download}' "${base%/}$path" 2>/dev/null || printf '000\t-\t0')"
      printf '%s\t%s\n' "$metrics" "${base%/}$path" >> "$WORK/urls/web_intel.tsv"
      grep -Eai '^(content-security-policy|access-control-allow-|set-cookie:|location:|server:|x-powered-by:)' \
        "$WORK/urls/web_intel_headers/$key.txt" >> "$WORK/urls/web_intel_headers_summary.txt" 2>/dev/null || true
      grep -Eaio 'https?://[^[:space:]"'"'"'<>;]+' "$WORK/urls/web_intel_headers/$key.txt" \
        >> "$WORK/urls/csp_references.txt" 2>/dev/null || true
    done
  done
  sort -u "$WORK/urls/csp_references.txt" -o "$WORK/urls/csp_references.txt"
fi
if ((web_intel_ran)); then stage_record web_intelligence completed "raw read-only files, headers, CORS/CSP references, and metadata preserved" 0 "$WORK/urls/web_intel.tsv"
else stage_record web_intelligence skipped "dry-run, curl unavailable, or no live URLs" 0; fi

: > "$WORK/urls/web_intel_evidence.txt"
for evidence in "$WORK"/urls/web_intel_headers/*.txt "$WORK"/urls/web_intel_bodies/*.txt; do
  [[ -f "$evidence" ]] || continue
  printf '\n----- %s -----\n' "${evidence#"$WORK/"}" >> "$WORK/urls/web_intel_evidence.txt"
  cat "$evidence" >> "$WORK/urls/web_intel_evidence.txt"
done

if ((ACTIVE)) && have arjun && [[ -s "$WORK/urls/scoped_corpus.txt" ]]; then
  head -n "${ARJUN_MAX_URLS:-50}" "$WORK/urls/scoped_corpus.txt" > "$WORK/active/arjun_targets.txt"
  arjun_args=(arjun -i "$WORK/active/arjun_targets.txt" -m GET -T 10 -oJ "$WORK/active/arjun.json")
  if [[ ${#EXTRA_HEADERS[@]} -gt 0 ]]; then printf -v arjun_headers '%s\n' "${EXTRA_HEADERS[@]}"; arjun_args+=(--headers "$arjun_headers"); fi
  arjun_args+=(--rate-limit "$ACTIVE_RATE")
  run_cmd "Authenticated hidden parameter discovery" "${arjun_args[@]}" 2>"$WORK/active/arjun.err"; rc=$?
  stage_from_rc arjun "$rc" "$WORK/active/arjun.json" "parameter discovery completed" "$WORK/active/arjun.err"
else
  stage_record arjun skipped "passive mode, arjun unavailable, or no scoped URLs" 0
fi

if ((ACTIVE)); then
  if have nmap && ask_yes "Run Nmap against scoped resolved/live hosts?" y; then
    { cat "$WORK/subs/active_hosts.txt" 2>/dev/null; sed -E 's#^https?://([^/:]+).*#\1#' "$WORK/http/live.txt" 2>/dev/null; } \
      | awk 'NF' | sort -u | head -n "${NMAP_MAX_HOSTS:-50}" > "$WORK/active/nmap_targets.txt"
    : > "$WORK/active/nmap.txt"; nmap_rc=0; nmap_scanned=0
    while IFS= read -r nmap_host; do
      getent ahosts "$nmap_host" >/dev/null 2>&1 || { printf 'skipped-unresolved\t%s\n' "$nmap_host" >> "$WORK/active/nmap_skipped.tsv"; continue; }
      ((nmap_scanned++))
      run_cmd "Nmap $nmap_host" nmap -Pn -T3 --top-ports 1000 --open -sV -oN "$WORK/active/nmap.one" "$nmap_host" \
        2>>"$WORK/active/nmap.err"; rc=$?
      [[ -s "$WORK/active/nmap.one" ]] && { printf '\n### %s\n' "$nmap_host" >> "$WORK/active/nmap.txt"; cat "$WORK/active/nmap.one" >> "$WORK/active/nmap.txt"; }
      ((rc != 0)) && nmap_rc="$rc"
    done < "$WORK/active/nmap_targets.txt"
    if [[ ! -s "$WORK/active/nmap_targets.txt" ]]; then stage_record nmap skipped "no scoped resolved/live hosts" 0
    elif ((nmap_scanned == 0)); then stage_record nmap skipped "all scoped candidates were unresolved" 0 "$WORK/active/nmap_skipped.tsv"
    else stage_from_rc nmap "$nmap_rc" "$WORK/active/nmap.txt" "scoped multi-host scan completed" "$WORK/active/nmap.err"; fi
  else
    stage_record nmap skipped "nmap unavailable or declined" 0
  fi
  if [[ -z "${FFUF_WORDLIST:-}" ]]; then
    for candidate in /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt /usr/share/wordlists/dirb/common.txt; do
      [[ -f "$candidate" ]] && { FFUF_WORDLIST="$candidate"; break; }
    done
  fi
  if have ffuf && [[ -n "${FFUF_WORDLIST:-}" && -f "${FFUF_WORDLIST:-}" ]] && [[ -s "$WORK/http/live.txt" ]] && ask_yes "Run recursive path and parameter FFUF?" y; then
    : > "$WORK/active/ffuf_targets.txt"
    head -n "${FFUF_MAX_HOSTS:-20}" "$WORK/http/live.txt" | while IFS= read -r url; do printf '%s/FUZZ\n' "${url%/}"; done >> "$WORK/active/ffuf_targets.txt"
    sed -E 's#^(https?://[^/]+/.*)/[^/?#]*(\?.*)?$#\1/FUZZ#' "$WORK/urls/scoped_corpus.txt" \
      | grep '/FUZZ$' | sort -u | head -n "${FFUF_MAX_PATHS:-75}" >> "$WORK/active/ffuf_targets.txt" || true
    sort -u "$WORK/active/ffuf_targets.txt" -o "$WORK/active/ffuf_targets.txt"
    while IFS= read -r url; do
      hash="$(printf %s "$url" | cksum | cut -d' ' -f1)"
      ffuf_args=(ffuf -w "$FFUF_WORDLIST" -u "$url" -rate "$ACTIVE_RATE" -t "${FFUF_THREADS:-20}"
        -recursion -recursion-depth "${FFUF_RECURSION_DEPTH:-2}" -maxtime "${FFUF_MAXTIME:-300}"
        -mc all -noninteractive -of json -o "$WORK/active/ffuf.$hash.json")
      append_headers ffuf_args
      run_cmd "Recursive FFUF $url" "${ffuf_args[@]}" 2>>"$WORK/active/ffuf.err"; rc=$?; ((rc != 0)) && ffuf_rc="$rc"
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
        param_args=(ffuf -w "$PARAM_WORDLIST" -u "$url" -mc all -rate "$ACTIVE_RATE" -t "${FFUF_THREADS:-20}"
          -maxtime "${FFUF_PARAM_MAXTIME:-120}" -noninteractive -of json -o "$WORK/active/ffuf.param.$hash.json")
        append_headers param_args
        run_cmd "Parameter FFUF $url" "${param_args[@]}" 2>>"$WORK/active/ffuf.err"; rc=$?; ((rc != 0)) && ffuf_rc="$rc"
      done
    fi
    cat "$WORK"/active/ffuf.*.json > "$WORK/active/ffuf_combined.json" 2>/dev/null || true
    stage_from_rc ffuf "${ffuf_rc:-0}" "$WORK/active/ffuf_combined.json" "recursive content fuzzing completed" "$WORK/active/ffuf.err"
  elif ! have ffuf; then
    stage_record ffuf skipped "ffuf unavailable" 0
  elif [[ -z "${FFUF_WORDLIST:-}" || ! -f "${FFUF_WORDLIST:-}" ]]; then
    stage_record ffuf skipped "no valid content wordlist found; set FFUF_WORDLIST" 0
  elif [[ ! -s "$WORK/http/live.txt" ]]; then
    stage_record ffuf skipped "no live URLs" 0
  else
    stage_record ffuf skipped "declined by operator" 0
  fi
else
  info "Active stages disabled by --passive."
  stage_record nmap skipped "passive mode" 0
  stage_record ffuf skipped "passive mode" 0
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
  stage_record access_checks completed "read-only differential checks completed" 0 "$WORK/active/access_all.tsv"
else
  stage_record access_checks skipped "passive/dry-run mode, curl unavailable, or no priority URLs" 0
fi

# Compile through a temporary file so interrupted runs never leave a partial report.
REPORT_TMP="$WORK/report.tmp"
{
  cat "$WORK/meta.txt"
  for entry in \
    "DNS|$WORK/dns/records.txt" "ALL DISCOVERED HOSTS|$WORK/subs/all_hosts.txt" "SCOPED HOSTS|$WORK/subs/hosts.txt" \
    "PRIVATE DNS / SSRF CORPUS|$WORK/subs/private_dns.txt" "TLS CERTIFICATES / SANS|$WORK/subs/tls_sans.txt" \
    "RAW LIVE URL EVIDENCE|$WORK/http/live.raw.txt" "NORMALIZED LIVE URLS|$WORK/http/live.txt" \
    "RAW HTTP DETAILS|$WORK/http/details.raw.jsonl" "DEDUPLICATED HTTP DETAILS|$WORK/http/details.jsonl" \
    "AUTHENTICATION VALIDATION|$WORK/http/auth_validation.tsv" \
    "TECHNOLOGY CORRELATION|$WORK/http/technology_summary.tsv" \
    "SCREENSHOT MANIFEST|$WORK/http/screenshot_manifest.txt" "SCREENSHOT DIFF|$WORK/http/screenshot_diff.txt" \
    "CRAWLED URLS|$WORK/urls/katana.txt" "HISTORICAL URLS|$WORK/urls/gau.txt" \
    "WAYBACK URLS|$WORK/urls/wayback.txt" "FULL ENDPOINT CORPUS|$WORK/urls/corpus.txt" \
    "SCOPED OPERATIONAL CORPUS|$WORK/urls/scoped_corpus.txt" \
    "RAW FOCUSED API / IDENTITY PROBES|$WORK/urls/focused_probes_raw.tsv" \
    "VALIDATED API SPECIFICATIONS|$WORK/urls/api_specs.tsv" "PROTECTED OR UNCERTAIN API CANDIDATES|$WORK/urls/api_candidates.tsv" \
    "RAW GRAPHQL RESPONSES|$WORK/urls/graphql_raw.tsv" "CONFIRMED GRAPHQL INTROSPECTION|$WORK/urls/graphql.jsonl" \
    "SCIM DISCOVERY|$WORK/urls/scim.tsv" "OIDC / KEYCLOAK DISCOVERY|$WORK/urls/oidc.tsv" \
    "RAW WEB INTELLIGENCE INDEX|$WORK/urls/web_intel.tsv" "RAW WEB INTELLIGENCE EVIDENCE|$WORK/urls/web_intel_evidence.txt" \
    "CSP / EXTERNAL REFERENCES|$WORK/urls/csp_references.txt" "SECURITY / CORS / COOKIE HEADERS|$WORK/urls/web_intel_headers_summary.txt" \
    "PARAMETERIZED URLS|$WORK/urls/parameterized.txt" "PRIORITY ENDPOINTS|$WORK/urls/priority.txt" \
    "JAVASCRIPT URLS|$WORK/urls/javascript.txt" "JAVASCRIPT ENDPOINTS|$WORK/urls/js_endpoints.txt" \
    "JAVASCRIPT SECRET RAW EVIDENCE|$WORK/urls/js_secrets_raw.tsv" "CLASSIFIED JAVASCRIPT SECRET CANDIDATES|$WORK/urls/js_secrets.tsv" \
    "PASSIVE GRPC-WEB SERVICES AND METHODS|$WORK/urls/grpc_web.tsv" "VALIDATED SOURCE MAPS|$WORK/urls/source_maps.tsv" \
    "DNSX RESOLUTION|$WORK/subs/resolved.txt" \
    "NAABU PORTS|$WORK/active/naabu.txt" "NMAP|$WORK/active/nmap.txt" \
    "ARJUN PARAMETERS|$WORK/active/arjun.json" \
    "ALL ACCESS VARIATIONS|$WORK/active/access_all.tsv" "ACCESS BYPASS CANDIDATES|$WORK/active/access_candidates.tsv"; do
    label="${entry%%|*}"; path="${entry#*|}"
    printf '\n============================================================\n%s\n============================================================\n' "$label"
    [[ -s "$path" ]] && cat "$path" || echo '(none recorded)'
  done
  printf '\n============================================================\nSTAGE STATUS\n============================================================\n'
  printf 'stage\tstatus\treason\texit_code\tresult_count\tsanitized_error\n'
  cat "$STAGES"
  echo; echo 'FFUF RESULTS'
  find "$WORK/active" -maxdepth 1 -type f -name 'ffuf.*.json' -exec cat {} + 2>/dev/null || echo '(none recorded)'
  echo; echo 'EXECUTION LOG'; sed -E $'s/\x1B\[[0-9;]*[mK]//g' "$LOG"
  printf '\nFinished: %s\n' "$(date -Is)"
  [[ -n "$SCREENSHOT_OUTPUT" ]] && printf 'Screenshot directory: %s\n' "$SCREENSHOT_OUTPUT"
} > "$REPORT_TMP"
mv -f -- "$REPORT_TMP" "$REPORT"
printf '[+] Report created: %s\n' "$REPORT"
