# Migration from v7.4.0

The original Bash implementation is archived as `docs/autorecon-v7.4.0.sh`; it is not executed. Its useful raw DNS, host, HTTP, archive, JavaScript, API/identity, port, parameter, access-differential and tool-error evidence categories map to stage-owned `raw-artifacts/` directories.

## Confirmed v7 architectural defects

* Duplicate assignments and usage text make the effective version/configuration ambiguous (legacy lines 7–14 and 22–50).
* A process-substitution `tee` and an `EXIT HUP INT TERM` cleanup trap can wait on descendants and deletes the work directory even after failure/interruption (legacy lines 105–114).
* The timeout wrapper covers child commands but not Bash loops, sleeps, parsing, or the global run (legacy lines 116–132).
* Stage records are append-only TSV without atomic checkpoints or per-unit resume data (legacy lines 140–158).
* API probes use sequential `curl` invocations and shared aggregate files rather than bounded per-origin workers and uniquely named bodies (legacy lines 523–652).
* Report construction happens only at the bottom of the script, so an earlier signal cannot publish a partial report (legacy lines 850–929).

## Operational migration

Replace `./autorecon.sh --auto TARGET` with `./autorecon TARGET --auto --profile balanced`. Existing output is not imported because v7 has no trustworthy checkpoint format. Retain old reports as immutable evidence. Authentication headers were intentionally not carried into v8's initial CLI: place authorization in tool-specific controlled wrappers rather than command arguments/logs.
