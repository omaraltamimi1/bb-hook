#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

bash -n autorecon.sh
./autorecon.sh --help | grep -q 'AutoRecon 7.3.0'
if rg -ni 'nuc''lei' . >/dev/null; then echo 'removed scanner references remain' >&2; exit 1; fi
rate_pattern="--rate-limit \"\$ACTIVE_RATE\""
grep -Fq -- "$rate_pattern" autorecon.sh
if grep -q -- '--ratelimit' autorecon.sh; then echo 'obsolete Arjun flag remains' >&2; exit 1; fi

if ./autorecon.sh --dry-run 999.1.1.1 >"$tmp/bad.log" 2>&1; then
  echo 'invalid IPv4 unexpectedly accepted' >&2; exit 1
fi
grep -q 'invalid IPv4 address' "$tmp/bad.log"

mkdir -p "$tmp/bin" "$tmp/reports"
cat > "$tmp/bin/subfinder" <<'SH'
#!/usr/bin/env bash
out=""; while (($#)); do [[ "$1" == -o ]] && { out="$2"; shift; }; shift; done
printf 'live.example.com\n' > "$out"
SH
cat > "$tmp/bin/httpx" <<'SH'
#!/usr/bin/env bash
[[ " ${*} " == *' -h '* ]] && { echo ' -ss screenshot support'; exit 0; }
[[ " ${*} " == *' -ss '* ]] && exit 0
out=""; json=0
while (($#)); do [[ "$1" == -o ]] && { out="$2"; shift; }; [[ "$1" == -json ]] && json=1; shift; done
if ((json)); then
  printf '%s\n' '{"url":"https://live.example.com/","status_code":401}' '{"url":"https://live.example.com","status_code":503}' > "$out"
else printf '%s\n' 'https://live.example.com/' 'https://live.example.com' > "$out"; fi
SH
cat > "$tmp/bin/naabu" <<'SH'
#!/usr/bin/env bash
out=""; while (($#)); do [[ "$1" == -o ]] && { out="$2"; shift; }; shift; done
echo 'live.example.com:443' > "$out"; echo 'runner ended early' >&2; exit 2
SH
cat > "$tmp/bin/arjun" <<'SH'
#!/usr/bin/env bash
printf '%q ' "$@" > "$FAKE_LOG/arjun.args"
out=""; while (($#)); do [[ "$1" == -oJ ]] && { out="$2"; shift; }; shift; done
[[ "${FAIL_ARJUN:-0}" == 1 ]] && { echo 'arjun synthetic failure' >&2; exit 3; }
echo '{}' > "$out"
SH
cat > "$tmp/bin/nmap" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "${*: -1}" >> "$FAKE_LOG/nmap.targets"
out=""; while (($#)); do [[ "$1" == -oN ]] && { out="$2"; shift; }; shift; done
echo '443/tcp open https' > "$out"
SH
cat > "$tmp/bin/getent" <<'SH'
#!/usr/bin/env bash
[[ "${*: -1}" == live.example.com ]]
SH
cat > "$tmp/bin/ffuf" <<'SH'
#!/usr/bin/env bash
out=""; while (($#)); do [[ "$1" == -o ]] && { out="$2"; shift; }; shift; done
echo '{"results":[]}' > "$out"
SH
cat > "$tmp/bin/curl" <<'SH'
#!/usr/bin/env bash
out=""; format=""; authenticated=0; while (($#)); do
  [[ "$1" == -o ]] && { out="$2"; shift; }
  [[ "$1" == -w ]] && { format="$2"; shift; }
  [[ "$1" == -H && "${2:-}" == Authorization:* ]] && authenticated=1
  shift
done
[[ -n "$out" && "$out" != /dev/null ]] && echo '{"error":"protected"}' > "$out"
if [[ -n "$format" ]]; then
  if [[ "$format" == '%{http_code}' && "${AUTH_DIFF:-0}" == 1 && "$authenticated" == 1 ]]; then printf '200'
  elif [[ "$format" == '%{http_code}' ]]; then printf '401'
  else printf '401\tapplication/json\t21'; fi
fi
SH
chmod +x "$tmp/bin"/*
echo word > "$tmp/words.txt"

FAKE_LOG="$tmp" PATH="$tmp/bin:$PATH" FFUF_WORDLIST="$tmp/words.txt" \
  ./autorecon.sh --auto --header 'Authorization: Bearer super-secret-test-value' \
  --header 'Accept: application/json' --cookie 'session=SESSION_VALUE' --output-dir "$tmp/reports" example.com >/dev/null
report="$(find "$tmp/reports" -name '*_report.txt' -print -quit)"
test -s "$report"

# Regression assertions from the real scan.
grep -q -- '--rate-limit' "$tmp/arjun.args"
grep -q 'live.example.com' "$tmp/nmap.targets"
if grep -qx 'example.com' "$tmp/nmap.targets"; then echo 'unresolved apex sent to nmap' >&2; exit 1; fi
grep -q $'naabu\tpartial\ttool exited non-zero; usable output retained\t2\t1' "$report"
grep -q $'ffuf\tcompleted' "$report"
grep -q $'screenshots\tskipped\tdisabled; enable with --screenshots or SCREENSHOTS=1' "$report"
grep -q 'runner ended early' "$report"
if grep -q 'super-secret-test-value' "$report"; then echo 'authentication value leaked' >&2; exit 1; fi
grep -q '^Placeholder warnings: 1$' "$report"
grep -q '^Authentication material configured: 1$' "$report"
raw_http_count="$(awk '/RAW HTTP DETAILS/{on=1;next}/DEDUPLICATED HTTP DETAILS/{on=0}on' "$report" | grep -c '"url":"https://live.example.com')"
dedup_http_count="$(awk '/DEDUPLICATED HTTP DETAILS/{on=1;next}/AUTHENTICATION VALIDATION/{on=0}on' "$report" | grep -c '"url":"https://live.example.com')"
[[ "$raw_http_count" -eq 2 && "$dedup_http_count" -eq 1 ]]
grep -q '^Scope mode: all$' "$report"
if awk '/VALIDATED API SPECIFICATIONS/{on=1;next}/PROTECTED OR UNCERTAIN API CANDIDATES/{on=0}on' "$report" | grep -q '401'; then
  echo 'protected path labelled as validated API specification' >&2; exit 1
fi
awk '/PROTECTED OR UNCERTAIN API CANDIDATES/{on=1;next}/GRAPHQL INTROSPECTION/{on=0}on' "$report" | grep -q '401'

# FFUF skip reasons are explicit in passive mode.
./autorecon.sh --dry-run --passive --output-dir "$tmp/passive" example.com >/dev/null
passive_report="$(find "$tmp/passive" -name '*_report.txt' -print -quit)"
grep -q $'ffuf\tskipped\tpassive mode' "$passive_report"

# A failed tool is explicitly failed, never represented as no findings.
mkdir -p "$tmp/failure"
FAKE_LOG="$tmp" FAIL_ARJUN=1 PATH="$tmp/bin:$PATH" FFUF_WORDLIST="$tmp/words.txt" \
  ./autorecon.sh --auto --output-dir "$tmp/failure" example.com >/dev/null
failure_report="$(find "$tmp/failure" -name '*_report.txt' -print -quit)"
grep -q $'arjun\tfailed\ttool exited without usable output\t3\t0' "$failure_report"
grep -q 'arjun synthetic failure' "$failure_report"

# Supported screenshot mode that produces no files is an explicit failure.
mkdir -p "$tmp/screenshots"
FAKE_LOG="$tmp" PATH="$tmp/bin:$PATH" ./autorecon.sh --passive --screenshots \
  --output-dir "$tmp/screenshots" example.com >/dev/null
screenshot_report="$(find "$tmp/screenshots" -name '*_report.txt' -print -quit)"
grep -q $'screenshots\tfailed\thttpx exited successfully but produced no screenshot artifacts\t0\t0' "$screenshot_report"

# Authentication is validated only by a safe in-scope unauthenticated/authenticated differential.
mkdir -p "$tmp/auth-diff"
FAKE_LOG="$tmp" AUTH_DIFF=1 AUTH_CHECK_URL='https://live.example.com/account' PATH="$tmp/bin:$PATH" \
  ./autorecon.sh --passive --header 'Authorization: Bearer differential-test-secret' \
  --output-dir "$tmp/auth-diff" example.com >/dev/null
auth_diff_report="$(find "$tmp/auth-diff" -name '*_report.txt' -print -quit)"
grep -q $'validated-differential\tunauth=401\tauth=200' "$auth_diff_report"
if grep -q 'differential-test-secret' "$auth_diff_report"; then echo 'differential authentication value leaked' >&2; exit 1; fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

bash -n autorecon.sh
./autorecon.sh --help | grep -q 'AutoRecon 7.0.0'

if ./autorecon.sh --dry-run 999.1.1.1 >"$tmp/bad.log" 2>&1; then
  echo 'invalid IPv4 unexpectedly accepted' >&2
  exit 1
fi
grep -q 'invalid IPv4 address' "$tmp/bad.log"

./autorecon.sh --dry-run --passive --output-dir "$tmp/reports" https://Example.COM/a >/dev/null
report="$(find "$tmp/reports" -type f -name '*_report.txt' -print -quit)"
test -s "$report"
grep -q '^Target: example.com$' "$report"
grep -q '^Active automation: 0$' "$report"

echo 'smoke tests passed'
