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
shellcheck autorecon.sh
./tests/smoke.sh
```
