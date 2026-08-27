# AutoRecon

`autorecon.sh` is a one-file bug-bounty reconnaissance and attack-surface
orchestrator for a domain, IPv4 address, or HTTP(S) URL. V7.1 runs the complete
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
- Repeatable authenticated headers/cookies propagated to HTTP-aware tools.
- Seed-and-subdomain operational scope with raw discoveries preserved separately;
  `--no-scope` is available when the engagement includes related external assets.
- Recursive path and query-value FFUF, custom Nuclei templates/tags, OpenAPI and
  GraphQL discovery, screenshots, visual manifests/diffs, and technology correlation.
- Per-command timeouts, failure isolation, signal-safe cleanup, and an execution log.
- Atomic report publication prevents interrupted runs from leaving partial results.

## Usage

```bash
./autorecon.sh example.com
./autorecon.sh --auto --dry-run https://example.com/path
FFUF_WORDLIST=/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
  ./autorecon.sh --auto --output-dir ./reports example.com
./autorecon.sh --passive example.com
./autorecon.sh --auto --header 'Authorization: Bearer TOKEN' \
  --cookie 'session=VALUE' example.com
NUCLEI_TEMPLATES=./nuclei-templates NUCLEI_TAGS=cve,exposure \
  ./autorecon.sh --auto example.com
SCREENSHOTS=1 SCREENSHOT_BASELINE=previous-manifest.txt \
  ./autorecon.sh --auto example.com
```

For query-value fuzzing, set `PARAM_WORDLIST` in addition to `FFUF_WORDLIST`.
Screenshots are written next to the TXT report because binary images cannot be
embedded usefully in it. Run `./autorecon.sh --help` for all major overrides.

## Checks

```bash
bash -n autorecon.sh
shellcheck autorecon.sh
./tests/smoke.sh
```
