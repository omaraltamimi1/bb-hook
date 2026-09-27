from __future__ import annotations
import argparse, sys
from .core import PROFILES, STAGE_IDS, Runner

def parser():
 p=argparse.ArgumentParser(prog="autorecon",description="AutoRecon v8 — Raccoon 4K")
 p.add_argument("target",nargs="?"); p.add_argument("--list-stages",action="store_true"); p.add_argument("--only",action="append"); p.add_argument("--skip",action="append"); p.add_argument("--from",dest="from_stage",choices=STAGE_IDS); p.add_argument("--until",choices=STAGE_IDS); p.add_argument("--resume"); p.add_argument("--restart-stage",choices=STAGE_IDS); p.add_argument("--keep-temp",action="store_true"); p.add_argument("--active",action="store_true"); p.add_argument("--passive",action="store_true"); p.add_argument("--dry-run",action="store_true"); p.add_argument("--auto",action="store_true");p.add_argument("--strict-stages",action="store_true",help="exit 2 if an unimplemented stage is scheduled to run");p.add_argument("--crawl-depth",type=int,default=3,help="maximum crawl depth (default: 3)");p.add_argument("--cookie-file",help="identity A: a Cookie header, an Authorization header, a cookie line, or a curl command");p.add_argument("--cookie-file-b",help="identity B, for a cross-role differential; omit for anon-vs-auth only");p.add_argument("--access-checks-max",type=int,default=0,help="cap access-checks targets; 0=default 40");p.add_argument("--arjun-max",type=int,default=0,help="cap arjun targets; 0=default 15");
 p.add_argument("--port-services",action="store_true",help="fingerprint services with nmap -sV -sC -Pn -T4 against ports naabu already confirmed open (opt-in; nmap is no longer its own stage)");
 p.add_argument("--ffuf-max-hosts",type=int,default=0,help="cap ffuf origins; 0=default 5, hard max applied in code");
 p.add_argument("--ffuf-threads",type=int,default=0,help="ffuf concurrency; clamped to 40");
 p.add_argument("--ffuf-max-time",type=int,default=0,help="seconds per origin; hard-capped at 120");
 p.add_argument("--ffuf-delay",type=float,default=0,help="seconds between ffuf requests");
 p.add_argument("--ffuf-recursion",action="store_true",help="enable ffuf recursion (off by default; depth is capped at 3)");
 p.add_argument("--ffuf-recursion-depth",type=int,default=0,help="ffuf recursion depth; hard-capped at 3");
 p.add_argument("--ffuf-wordlist",help="ffuf wordlist; falls back to seclists common.txt then config/sensitive-paths.txt");p.add_argument("--arjun-delay",type=float,default=0,help="seconds between arjun requests");p.add_argument("--arjun-passive",action="store_true",help="collect parameter names from passive sources only, without active probing");p.add_argument("--arjun-wordlist",help="arjun parameter wordlist; defaults to the bundled one"); p.add_argument("--strict-scope",action="store_true"); p.add_argument("--scope-include",action="append",default=[]); p.add_argument("--scope-exclude",action="append",default=[])
 p.add_argument("--profile",choices=PROFILES,default="balanced"); p.add_argument("--output-dir",default="./autorecon-results"); p.add_argument("--request-timeout",type=float); p.add_argument("--tool-timeout",type=float); p.add_argument("--stage-timeout",type=float); p.add_argument("--global-timeout",type=float,default=0); p.add_argument("--max-hosts",type=int); p.add_argument("--concurrency",type=int); p.add_argument("--rate-limit",type=float); p.add_argument("--kill-grace",type=float,default=5); p.add_argument("--heartbeat",type=float,default=30); p.add_argument("--graphql-introspection",action=argparse.BooleanOptionalAction,default=False)
 return p
def main(argv=None):
 p=parser(); a=p.parse_args(argv)
 if a.list_stages:
  from .core import DESCRIPTIONS,DEPS
  for s in STAGE_IDS: print(f"{s}\tdeps={','.join(DEPS[s]) or '-'}\t{DESCRIPTIONS[s]}")
  return 0
 if not a.target:p.error("target is required unless --list-stages is used")
 defaults=PROFILES[a.profile]
 for key in ("request_timeout","tool_timeout","stage_timeout","max_hosts","concurrency","rate_limit"):
  if getattr(a,key) is None:setattr(a,key,defaults[key])
 if min(a.request_timeout,a.tool_timeout,a.stage_timeout,a.max_hosts,a.concurrency,a.rate_limit)<=0:p.error("limits must be positive")
 try:return Runner(a).run()
 except (ValueError,OSError) as e: print(f"autorecon: error: {e}",file=sys.stderr); return 2
if __name__=="__main__":raise SystemExit(main())
