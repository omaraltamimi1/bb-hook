#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

bash -n autorecon.sh
./autorecon.sh --help | grep -q 'AutoRecon 7.1.0'

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

./autorecon.sh --dry-run --passive --header 'Authorization: Bearer test-token' \
  --cookie 'session=test-session' --no-scope --output-dir "$tmp/auth-reports" example.com >/dev/null
auth_report="$(find "$tmp/auth-reports" -type f -name '*_report.txt' -print -quit)"
grep -q '^Scope mode: all$' "$auth_report"
grep -q '^HTTP headers configured: 2$' "$auth_report"

echo 'smoke tests passed'
