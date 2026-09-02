#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python3 -m tests
./autorecon --list-stages >/dev/null
out="$(mktemp -d)"; trap 'rm -rf "$out"' EXIT
./autorecon example.com --dry-run --skip nmap,ffuf --output-dir "$out" >/dev/null
test -s "$out/$(cat "$out/last")/report.json"
