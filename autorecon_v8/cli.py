from __future__ import annotations
import argparse, sys
from .core import PROFILES, STAGE_IDS, Runner

def parser():
 p=argparse.ArgumentParser(prog="autorecon",description="AutoRecon v8 — Raccoon 4K")
 p.add_argument("target",nargs="?"); p.add_argument("--list-stages",action="store_true"); p.add_argument("--only",action="append"); p.add_argument("--skip",action="append"); p.add_argument("--from",dest="from_stage",choices=STAGE_IDS); p.add_argument("--until",choices=STAGE_IDS); p.add_argument("--resume"); p.add_argument("--restart-stage",choices=STAGE_IDS); p.add_argument("--keep-temp",action="store_true"); p.add_argument("--active",action="store_true"); p.add_argument("--passive",action="store_true"); p.add_argument("--dry-run",action="store_true"); p.add_argument("--auto",action="store_true");p.add_argument("--strict-stages",action="store_true",help="exit 2 if an unimplemented stage is scheduled to run");p.add_argument("--crawl-depth",type=int,default=3,help="maximum crawl depth (default: 3)"); p.add_argument("--strict-scope",action="store_true"); p.add_argument("--scope-include",action="append",default=[]); p.add_argument("--scope-exclude",action="append",default=[])
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
