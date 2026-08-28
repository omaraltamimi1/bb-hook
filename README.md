# bb-hook

This repository contains a safe, no-op `post-checkout` hook fixture.

The hook must not read or persist host data, account information, environment
variables, credentials, tokens, or other process secrets. In particular, a
checkout hook runs outside the application's TLS boundary, so collecting that
data would be a separate local sensitive-data exposure rather than evidence of
impact from a remote certificate hostname mismatch.

## Verification

Run the following checks from the repository root:

```sh
sh -n y/hooks/post-checkout
tmpdir="$(mktemp -d)"
(
  cd "$tmpdir"
  /workspace/bb-hook/y/hooks/post-checkout old-ref new-ref 1
)
test -z "$(find "$tmpdir" -mindepth 1 -print -quit)"
rm -rf "$tmpdir"
# AutoRecon V7.3.0

`autorecon.sh` is a one-file reconnaissance and attack-surface orchestrator for
a domain, IPv4 address, or HTTP(S) URL. It preserves raw discovery evidence,
keeps unfiltered raw evidence alongside normalized views, and publishes an atomic TXT
report with explicit status for every stage.

## Highlights

- Multi-source host/DNS discovery with an isolated RFC1918/SSRF corpus.
- Raw mode is the default: external discoveries, private targets, HTTP duplicates,
  raw headers/bodies, and all FFUF response codes remain available as evidence.
- Deduplicated HTTPX reachability, details, technology correlation, and optional screenshots.
- Authenticated crawling and probing via repeatable `--header` and `--cookie` options.
- Authentication material is redacted; configuration is not reported as proof of login.
  Optional validation requires a 401/403-to-2xx authenticated differential.
- Scoped multi-host Naabu/Nmap scanning with partial-output preservation.
- Automatic SecLists detection plus bounded recursive and parameter FFUF.
- Classified JavaScript secret evidence and passive gRPC-Web service/method extraction.
- Signature-validated OpenAPI/Swagger results, separate protected/uncertain candidates,
  optional GraphQL introspection, realm-aware read-only SCIM/OIDC/Keycloak discovery,
  and validated public JavaScript source-map discovery.
- Stage status records distinguish completed, partial, failed, and skipped runs.
- TLS certificate/SAN expansion plus read-only robots, sitemap, security.txt,
  CORS, CSP, cookie, redirect, accidental metadata, and security-header collection.
# AutoRecon

`autorecon.sh` is a one-file bug-bounty reconnaissance and attack-surface
orchestrator for a domain, IPv4 address, or HTTP(S) URL. V7 runs the complete
workflow by default and publishes every artifact into one atomic text report.

## Highlights

- Strict target parsing, including complete IPv4 octet validation.
- Non-interactive `--auto`, network-free `--dry-run`, and optional `--passive` modes.
- Multi-source discovery with Subfinder, Assetfinder, Amass, DNSx, GAU and Waybackurls.
- HTTP fingerprinting, Naabu/Nmap ports, Katana crawling, Arjun parameter discovery,
  FFUF content discovery and Nuclei scanning.
- JavaScript downloads with offline endpoint and hardcoded-secret extraction.
- Full endpoint corpus plus additional parameterized and high-value triage views;
  discovery results are not removed from the complete corpus.
- 401/403 header and path differential checks with complete response metrics.
- Per-command timeouts, failure isolation, signal-safe cleanup, and an execution log.
- Atomic report publication prevents interrupted runs from leaving partial results.

## Usage

```bash
./autorecon.sh --auto example.com
./autorecon.sh --auto --dry-run https://example.com/path
./autorecon.sh --auto --header 'Authorization: Bearer REAL_TOKEN' \
  --cookie 'session=REAL_VALUE' example.com
FFUF_WORDLIST=/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
PARAM_WORDLIST=/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  ./autorecon.sh --auto example.com
./autorecon.sh --auto --screenshots example.com
./autorecon.sh --passive example.com
./autorecon.sh --strict-scope --exclude-private --auto example.com
```

Raw mode is enabled by default and does not discard external discoveries, private
DNS targets, duplicate HTTP evidence, or non-matching FFUF responses. Use
`--strict-scope` and/or `--exclude-private` when you want an intentionally reduced
operational target set. Rate, time, recursion, file-size, and target caps remain
configurable resource bounds rather than evidence filters.

Set `AUTH_CHECK_URL` to a safe in-scope endpoint when you want the report to
record whether authentication changes a 401/403 response to 2xx. The report never
prints authentication values. Screenshots are saved next to the TXT report;
`SCREENSHOT_BASELINE` can point to an earlier SHA-256 manifest for change detection.
./autorecon.sh example.com
./autorecon.sh --auto --dry-run https://example.com/path
FFUF_WORDLIST=/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
  ./autorecon.sh --auto --output-dir ./reports example.com
./autorecon.sh --passive example.com
```

Run `./autorecon.sh --help` for environment and rate overrides.

## Checks

```bash
bash -n autorecon.sh
shellcheck autorecon.sh tests/smoke.sh
./tests/smoke.sh
# The removed scanner integration should have no project references.
shellcheck autorecon.sh
./tests/smoke.sh
```
