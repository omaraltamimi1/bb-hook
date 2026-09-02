# AutoRecon v8 — Raccoon 4K

A Python 3.11+ reconnaissance orchestrator for authorized assessments. V8 prioritizes strict scope decisions, bounded execution, atomic resumability, process-group shutdown, observable progress, and preservation of raw evidence. The archived v7 implementation is never invoked.

## Install

```bash
python3 -m pip install -e .
# or run without installation
./autorecon --list-stages
```

No runtime Python dependency outside the standard library is required. External tools are optional: a missing tool produces an explicit skipped stage rather than a false empty result.

## Run

```bash
./autorecon wellsfargo.com --auto --active --strict-scope --profile balanced \
  --skip nmap,ffuf --output-dir /mnt/KaliShare/autorecon-results
./autorecon example.com --passive --profile passive
./autorecon example.com --only dns,httpx,api-discovery
./autorecon example.com --from crawl --until javascript
./autorecon example.com --resume last --output-dir ./autorecon-results
./autorecon example.com --resume RUN_ID --restart-stage api-discovery
```

Selection controls are `--only`, `--skip`, `--from`, `--until`, and `--list-stages`. Runtime controls are `--request-timeout`, `--tool-timeout`, `--stage-timeout`, `--global-timeout`, `--max-hosts`, `--concurrency`, `--rate-limit`, `--heartbeat`, and `--kill-grace`. CLI values override profile defaults. `--dry-run` performs no subprocess/network work while exercising stages and reports.

## Profiles

| Profile | Concurrency | Rate/s | Request | Tool | Stage | Max hosts | Selection |
|---|---:|---:|---:|---:|---:|---:|---|
| passive | 4 | 5 | 10s | 300s | 600s | 500 | passive stages only |
| fast | 8 | 20 | 8s | 300s | 600s | 200 | screenshots/nmap/ffuf off |
| balanced | 10 | 15 | 12s | 900s | 1800s | 1000 | all |
| deep | 20 | 10 | 20s | 1800s | 7200s | 5000 | all |
| custom | 4 | 5 | 10s | 600s | 1200s | 500 | all |

## Evidence and reliability

Each run uses mode `0700` and contains `run-state.json` (atomically replaced), `raw-artifacts/`, `commands.jsonl`, `scope-decisions.jsonl`, `report.md`, `report.json`, and `stages.csv`. Raw responses are not treated as findings; reports explicitly separate evidence from vulnerability claims. API discovery deduplicates origins, performs read-only OpenAPI/Swagger, GraphQL, SCIM Users/Groups, OIDC and Keycloak probes, and gives every response a unique body file. GraphQL introspection is off unless `--graphql-introspection` is supplied and never sends a mutation.

Child tools start in new process groups. Signals and deadlines stop scheduling work, terminate the group, escalate after `--kill-grace`, checkpoint, publish a partial report, retain evidence, print an exact resume command, and return nonzero. Heartbeats default to 30 seconds (below the one-minute acceptance ceiling).

## Scope

`--strict-scope` permits the seed and its subdomains. Repeat `--scope-include` and `--scope-exclude` for additional wildcard-style suffix rules; exclusions win. Every operational decision is logged. Redirect destinations are checked as new URLs before operational use.

## Development checks

```bash
python3 -m tests
python3 -m compileall -q autorecon_v8 tests
ruff check .
mypy autorecon_v8
shellcheck autorecon
./autorecon example.com --dry-run --skip nmap,ffuf --output-dir /tmp/autorecon-smoke
```

See [migration notes](docs/MIGRATION-v7.md), [v8 changelog](CHANGELOG-v8.md), [default configuration](config/default.json), and [scope example](config/scope.example.txt).
