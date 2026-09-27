from __future__ import annotations

import argparse
import concurrent.futures
import csv
import dataclasses
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlsplit, urlunsplit

STATUSES = {"pending", "running", "completed", "partial", "failed", "skipped", "interrupted"}
STAGE_IDS = ["dns", "subdomains", "dnsx", "tls", "httpx", "screenshots", "ports", "crawl", "archives", "corpus", "javascript", "api-discovery", "web-intelligence", "arjun", "nmap", "ffuf", "access-checks", "report"]
ACTIVE = {"screenshots", "ports", "crawl", "javascript", "api-discovery", "web-intelligence", "arjun", "nmap", "ffuf", "access-checks"}
DESCRIPTIONS = {
 "dns":"Collect DNS records", "subdomains":"Enumerate passive subdomains", "dnsx":"Resolve discovered names", "tls":"Collect TLS metadata", "httpx":"Identify HTTP origins", "screenshots":"Capture visual evidence", "ports":"Discover ports", "crawl":"Crawl live applications", "archives":"Collect archived URLs", "corpus":"Normalize and deduplicate URLs", "javascript":"Preserve and inspect JavaScript", "api-discovery":"Read-only API and identity probes", "web-intelligence":"Collect web metadata", "arjun":"Discover parameters", "nmap":"Validate exposed services", "ffuf":"Discover content", "access-checks":"Read-only access differentials", "report":"Publish reports"}
DEPS = {s: ([STAGE_IDS[i-1]] if i else []) for i,s in enumerate(STAGE_IDS)}
DEPS.update({"screenshots":["httpx"],"ports":["dnsx"],"crawl":["httpx"],"archives":["subdomains"],"corpus":["crawl","archives"],"javascript":["corpus"],"api-discovery":["httpx"],"web-intelligence":["httpx"],"arjun":["corpus"],"nmap":["ports"],"ffuf":["httpx"],"access-checks":["corpus"],"report":[]})
PROFILES: dict[str,dict[str,Any]] = {
 "passive":{"concurrency":4,"rate_limit":5.0,"request_timeout":10.0,"tool_timeout":300.0,"stage_timeout":600.0,"max_hosts":500,"skip":sorted(ACTIVE)},
 "fast":{"concurrency":8,"rate_limit":20.0,"request_timeout":8.0,"tool_timeout":300.0,"stage_timeout":600.0,"max_hosts":200,"skip":["screenshots","nmap","ffuf"]},
 "balanced":{"concurrency":10,"rate_limit":15.0,"request_timeout":12.0,"tool_timeout":900.0,"stage_timeout":1800.0,"max_hosts":1000,"skip":[]},
 "deep":{"concurrency":20,"rate_limit":10.0,"request_timeout":20.0,"tool_timeout":1800.0,"stage_timeout":7200.0,"max_hosts":5000,"skip":[]},
 "custom":{"concurrency":4,"rate_limit":5.0,"request_timeout":10.0,"tool_timeout":600.0,"stage_timeout":1200.0,"max_hosts":500,"skip":[]},
}

def now() -> str: return dt.datetime.now(dt.timezone.utc).isoformat()
def atomic_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); fd,tmp=tempfile.mkstemp(prefix=".state-",dir=path.parent)
    try:
        with os.fdopen(fd,"w") as f: json.dump(data,f,indent=2,sort_keys=True); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def normalize_target(raw: str) -> tuple[str,str]:
    if not raw or any(c in raw for c in "\r\n\0"): raise ValueError("target is empty or contains control characters")
    value=raw if "://" in raw else "https://"+raw
    u=urlsplit(value)
    if u.scheme not in {"http","https"} or not u.hostname or u.username or u.password: raise ValueError("target must be an HTTP(S) hostname/IP without credentials")
    host=u.hostname.rstrip(".").lower()
    try: ipaddress.ip_address(host)
    except ValueError:
        if re.fullmatch(r"[0-9.]+", host): raise ValueError(f"invalid IP address: {host}")
        if len(host)>253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",host): raise ValueError(f"invalid hostname: {host}")
    port=f":{u.port}" if u.port and u.port != (443 if u.scheme=="https" else 80) else ""
    return host,urlunsplit((u.scheme,host+port,u.path or "/",u.query,""))

def normalize_url(raw: str) -> str:
    u=urlsplit(raw.strip())
    if u.scheme.lower() not in {"http","https"} or not u.hostname: raise ValueError("not an HTTP URL")
    host=u.hostname.rstrip(".").lower(); port=u.port
    netloc=host+(f":{port}" if port and port != (443 if u.scheme.lower()=="https" else 80) else "")
    return urlunsplit((u.scheme.lower(),netloc,u.path or "/",u.query,""))
def origin(raw:str)->str:
    u=urlsplit(normalize_url(raw)); return urlunsplit((u.scheme,u.netloc,"","",""))
def unique_origins(items:Iterable[str])->list[str]:
    out=[]; seen=set()
    for item in items:
        try: o=origin(item)
        except ValueError: continue
        if o not in seen: seen.add(o); out.append(o)
    return out

class Scope:
    def __init__(self, seed:str, includes:Iterable[str]=(), excludes:Iterable[str]=(), strict:bool=True):
        self.seed=seed.lower(); self.includes=[x.lower().lstrip("*.") for x in includes] or [self.seed]; self.excludes=[x.lower().lstrip("*.") for x in excludes]; self.strict=strict
    @staticmethod
    def match(host:str,rule:str)->bool: return host==rule or host.endswith("."+rule)
    def decide(self,value:str)->tuple[bool,str]:
        try: host=urlsplit(value).hostname or value.split(":",1)[0]
        except ValueError: return False,"malformed"
        host=host.rstrip(".").lower()
        if any(self.match(host,x) for x in self.excludes): return False,"excluded by scope rule"
        if self.strict and not any(self.match(host,x) for x in self.includes): return False,"outside inclusion scope"
        return True,"included by scope rule" if self.strict else "strict scope disabled"

@dataclasses.dataclass
class StageState:
    id:str; name:str; description:str; dependencies:list[str]; inputs:list[str]=dataclasses.field(default_factory=list); outputs:list[str]=dataclasses.field(default_factory=list)
    status:str="pending"; started_at:str|None=None; ended_at:str|None=None; runtime_seconds:float=0; processed:int=0; total:int=0; exit_code:int|None=None; failure_reason:str|None=None; resume:str="not started"

class Interrupted(Exception): pass
class Deadline(Exception): pass

class Runner:
    def __init__(self,args:argparse.Namespace):
        self.args=args; self.host,self.seed=normalize_target(args.target); self.stop=threading.Event(); self.child:subprocess.Popen[str]|None=None
        self.started=time.monotonic(); self.started_at=now(); self.global_deadline=self.started+args.global_timeout if args.global_timeout else float("inf")
        self.out=Path(args.output_dir).resolve(); self.out.mkdir(parents=True,exist_ok=True); os.chmod(self.out,0o700)
        self.run_id=args.resume if args.resume not in (None,"last") else (self._last_id() if args.resume=="last" else dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+hashlib.sha256(self.seed.encode()).hexdigest()[:8])
        self.work=self.out/self.run_id; self.raw=self.work/"raw-artifacts"; self.raw.mkdir(parents=True,exist_ok=True); os.chmod(self.work,0o700)
        self.state_path=self.work/"run-state.json"; self.command_log=self.work/"commands.jsonl"; self.scope_log=self.work/"scope-decisions.jsonl"
        self.scope=Scope(self.host,args.scope_include,args.scope_exclude,args.strict_scope)
        self.current: str | None = None
        self.stages={s:StageState(s,s,DESCRIPTIONS[s],DEPS[s]) for s in STAGE_IDS}; self.current=None; self.selected,self.skip_reasons=select_stages(args)
        if self.state_path.exists(): self._load()
        signal.signal(signal.SIGINT,self._signal); signal.signal(signal.SIGTERM,self._signal)
    def _last_id(self)->str:
        link=self.out/"last"
        if not link.exists(): raise ValueError("no resumable last run")
        return link.read_text().strip()
    def _load(self)->None:
        old=json.loads(self.state_path.read_text())
        if old.get("target")!=self.seed: raise ValueError("resume target does not match original target")
        for sid,val in old["stages"].items(): self.stages[sid]=StageState(**val)
        for st in self.stages.values():
            if st.status in {"running","interrupted"}: st.status="pending"; st.resume="retrying interrupted unit"
        if self.args.restart_stage:
            found=False
            for sid in STAGE_IDS:
                if sid==self.args.restart_stage: found=True
                if found: self.stages[sid]=StageState(sid,sid,DESCRIPTIONS[sid],DEPS[sid],resume="invalidated by --restart-stage")
    def _signal(self,*_:Any)->None:
        self.stop.set()
        if self.child: self._terminate(self.child)
    def save(self)->None:
        atomic_json(self.state_path,{"version":1,"run_id":self.run_id,"target":self.seed,"started_at":self.started_at,"updated_at":now(),"stages":{k:dataclasses.asdict(v) for k,v in self.stages.items()}})
    def log_scope(self,value:str)->bool:
        allowed,reason=self.scope.decide(value)
        with self.scope_log.open("a") as f: f.write(json.dumps({"timestamp":now(),"value":value,"allowed":allowed,"reason":reason})+"\n")
        return allowed
    def check(self,deadline:float)->None:
        if self.stop.is_set(): raise Interrupted()
        if time.monotonic()>min(deadline,self.global_deadline): raise Deadline()
    def _terminate(self,p:subprocess.Popen[str])->None:
        if p.poll() is not None:return
        try: os.killpg(p.pid,signal.SIGTERM); p.wait(timeout=self.args.kill_grace)
        except (ProcessLookupError,subprocess.TimeoutExpired):
            try: os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError: pass
    def command(self,stage:str,cmd:list[str],target:str,deadline:float,output:Path,cwd:Path|None=None)->int:
        rec={"timestamp":now(),"stage":stage,"command":cmd,"target":target,"dry_run":self.args.dry_run}
        with self.command_log.open("a") as f:f.write(json.dumps(rec)+"\n")
        if self.args.dry_run: print("[dry-run]",subprocess.list2cmdline(cmd)); return 0
        err=self.raw/stage/(output.name+".stderr"); err.parent.mkdir(parents=True,exist_ok=True); output.parent.mkdir(parents=True,exist_ok=True)
        with output.open("a") as out,err.open("a") as ef:
            p=subprocess.Popen(cmd,stdout=out,stderr=ef,text=True,start_new_session=True,cwd=str(cwd) if cwd else None); self.child=p; start=time.monotonic(); next_beat=start
            try:
                while p.poll() is None:
                    self.check(min(deadline,start+self.args.tool_timeout))
                    if time.monotonic()>=next_beat:
                        print(f"[{stage}] tool={cmd[0]} PID={p.pid} target={target} elapsed={fmt(time.monotonic()-start)} deadline={fmt(max(0,min(deadline,start+self.args.tool_timeout)-time.monotonic()))}",flush=True); next_beat=time.monotonic()+min(30,self.args.heartbeat)
                    time.sleep(.1)
                if self.stop.is_set(): raise Interrupted()
                return int(p.returncode or 0)
            except (Interrupted,Deadline): self._terminate(p); raise
            finally:self.child=None
    def write_lines(self,path:Path,values:Iterable[str])->None:
        existing=set(path.read_text().splitlines()) if path.exists() else set(); existing.update(x for x in values if x); path.parent.mkdir(parents=True,exist_ok=True); path.write_text("".join(x+"\n" for x in sorted(existing)))
    def run(self)->int:
        (self.out/"last").write_text(self.run_id); rc=0
        try:
            for sid in STAGE_IDS:
                st=self.stages[sid]
                if sid not in self.selected:
                    st.status="skipped"; st.failure_reason=self.skip_reasons.get(sid,"not selected"); st.ended_at=now(); self.save(); continue
                if st.status=="completed" and sid!="report": print(f"[{sid}] reused valid completed artifact",flush=True); continue
                bad=[d for d in st.dependencies if self.stages[d].status in {"failed","interrupted"}]
                if bad: st.status="skipped"; st.failure_reason="dependency failed: "+",".join(bad); self.save(); continue
                self.execute(st)
                if st.status=="failed": rc=1
        except (Interrupted,KeyboardInterrupt): rc=130; self.mark_current("interrupted","signal received",130)
        except Deadline: rc=124; self.mark_current("partial","stage or global deadline expired",124)
        except Exception as e: rc=1; self.mark_current("failed",f"{type(e).__name__}: {e}",1)
        finally:
            self.generate_reports(rc); self.save()
        if rc: print(f"Resume with: autorecon {self.seed} --resume {self.run_id} --output-dir {self.out}",file=sys.stderr)
        elif not self.args.keep_temp: shutil.rmtree(self.work/"tmp",ignore_errors=True)
        return rc
    def mark_current(self,status:str,reason:str,rc:int)->None:
        if self.current:
            st=self.stages[self.current]; st.status=status; st.failure_reason=reason; st.exit_code=rc; st.ended_at=now(); st.resume="retry incomplete units"; self.save()
    def execute(self,st:StageState)->None:
        self.current=st.id; st.status="running"; st.started_at=now(); start=time.monotonic(); deadline=min(self.global_deadline,start+self.args.stage_timeout); self.save()
        try:
            if st.id=="report": self.generate_reports(0)
            elif st.id=="api-discovery": self.api_stage(st,deadline)
            elif st.id=="screenshots": self.screenshot_stage(st,deadline)
            else: self.generic_stage(st,deadline)
            if st.status=="running": st.status="completed"; st.exit_code=0; st.resume="completed artifacts reusable"
        except Deadline: st.status="partial" if st.processed else "failed"; st.exit_code=124; st.failure_reason="stage deadline expired"; st.resume="retry remaining units"
        except Interrupted: st.status="interrupted"; st.exit_code=130; st.failure_reason="signal received"; st.resume="retry remaining units"; raise
        finally: st.ended_at=now(); st.runtime_seconds=round(time.monotonic()-start,3); self.save(); self.current=None
    def inputs(self,sid:str)->list[str]:
        discovered=self.read("subdomains")
        resolved=self.read("dnsx")
        hosts=resolved or discovered or [self.host]
        mapping={"dnsx":discovered+[self.host],"tls":hosts,"httpx":hosts,"screenshots":self.read("httpx"),"ports":hosts,"crawl":self.read("httpx"),"archives":discovered+[self.host],"corpus":self.read("crawl")+self.read("archives"),"javascript":self.read("corpus"),"api-discovery":self.read("httpx") or [self.seed],"web-intelligence":self.read("httpx"),"arjun":self.read("corpus"),"nmap":self.read("ports"),"ffuf":self.read("httpx"),"access-checks":self.read("corpus")}
        values=[]
        for value in mapping.get(sid,[self.host]):
            if value and value not in values and self.scope.decide(value)[0]: values.append(value)
        return values[:self.args.max_hosts]
    def read(self,sid:str)->list[str]:
        p=self.raw/sid/"normalized.txt"; return p.read_text().splitlines() if p.exists() else []
    def generic_stage(self,st:StageState,deadline:float)->None:
        values=self.inputs(st.id); st.total=len(values); dest=self.raw/st.id/"normalized.txt"; st.inputs=[str(x) for x in values]; st.outputs=[str(dest)]
        tool={"dns":"dig","subdomains":"subfinder","dnsx":"dnsx","tls":"tlsx","httpx":"httpx","screenshots":"httpx","ports":"naabu","crawl":"katana","archives":"gau","javascript":"curl","web-intelligence":"curl","arjun":"arjun","nmap":"nmap","ffuf":"ffuf","access-checks":"curl"}.get(st.id)
        if not values: st.status="skipped"; st.failure_reason="empty input"; return
        if tool and not shutil.which(tool): st.status="skipped"; st.failure_reason=f"missing external tool: {tool}"; return
        if self.args.dry_run: self.write_lines(dest,values); st.processed=st.total; return
        # Safe bounded adapters; raw stdout remains separate from normalized evidence.
        input_file=self.raw/st.id/"inputs.txt"
        self.write_lines(input_file,values)
        cmds={"dns":[tool,"+short",self.host],"subdomains":[tool,"-silent","-d",self.host],"dnsx":[tool,"-silent","-l",str(input_file)],"tls":[tool,"-silent","-l",str(input_file)],"httpx":[tool,"-silent","-l",str(input_file)],"ports":[tool,"-silent","-list",str(input_file)],"archives":[tool,"--subs",self.host]}
        if st.id in cmds:
            raw=self.raw/st.id/"stdout.txt"; rc=self.command(st.id,[str(x) for x in cmds[st.id]],values[0],deadline,raw); st.exit_code=rc
            lines=raw.read_text(errors="replace").splitlines() if raw.exists() else []
            self.write_lines(dest,lines); st.processed=st.total
            if rc: st.status="partial" if lines else "failed"; st.failure_reason=f"tool exited {rc}"
        else:
            # Complex active integrations retain a deterministic candidate list for explicit operator/tool follow-up.
            for i,v in enumerate(values,1): self.check(deadline); self.log_scope(v); self.write_lines(dest,[v]); st.processed=i; print(f"[{st.id}] {i}/{st.total} {v} | elapsed={fmt(time.monotonic()-(deadline-self.args.stage_timeout))}",flush=True)
    def screenshot_stage(self,st:StageState,deadline:float)->None:
        values=[v for v in self.inputs(st.id) if v]; dest=self.raw/st.id/"normalized.txt"; st.total=len(values); st.inputs=values; st.outputs=[str(dest)]
        if not values: st.status="skipped"; st.failure_reason="no live HTTP origins from httpx"; return
        if self.args.dry_run: self.write_lines(dest,values); st.processed=st.total; return
        tool=shutil.which("httpx")
        if not tool: st.status="skipped"; st.failure_reason="missing external tool: httpx"; return
        root=self.raw/st.id; root.mkdir(parents=True,exist_ok=True)
        input_file=root/"inputs.txt"; self.write_lines(input_file,values)
        browser=next((c for c in ("chromium","chromium-browser","google-chrome","google-chrome-stable") if shutil.which(c)),None)
        shot_timeout=max(5,int(self.args.request_timeout))
        cmd=[tool,"-silent","-l",str(input_file),"-screenshot","-screenshot-timeout",str(shot_timeout),"-threads",str(max(1,self.args.concurrency)),"-no-color"]
        if browser: cmd+=["-system-chrome"]
        else: cmd+=["-no-screenshot-full-page"]
        stdout=root/"stdout.txt"; rc=self.command(st.id,cmd,self.host,deadline,stdout,cwd=root); st.exit_code=rc
        shots=sorted(str(p) for p in root.rglob("*.png"))
        if not shots:
            st.status="skipped"; st.processed=0
            st.failure_reason="no screenshot captured" + ("" if browser else " and no local chrome/chromium found for -system-chrome")
            if rc: st.failure_reason+=f"; httpx exited {rc}"
            return
        self.write_lines(dest,shots); st.outputs=[str(p) for p in shots[:200]]+[str(root)]
        st.processed=len(shots); print(f"[screenshots] captured {len(shots)} image(s) under {root}",flush=True)
        if rc: st.status="partial"; st.failure_reason=f"httpx exited {rc} but {len(shots)} image(s) were captured"
    def api_stage(self,st:StageState,deadline:float)->None:
        origins=[o for o in unique_origins(self.inputs(st.id)) if self.log_scope(o)][:self.args.max_hosts]; st.total=len(origins); st.inputs=origins
        if self.args.dry_run: st.processed=st.total; self.write_lines(self.raw/st.id/"normalized.txt",origins); return
        probes=[("openapi","/openapi.json"),("swagger","/swagger.json"),("graphql","/graphql"),("scim-users","/scim/v2/Users?count=1"),("scim-groups","/scim/v2/Groups?count=1"),("oidc","/.well-known/openid-configuration"),("keycloak","/realms/master/.well-known/openid-configuration")]
        lock=threading.Lock(); results=[]
        def one(idx:int,o:str)->None:
            local=[]
            for name,path in probes:
                self.check(deadline)
                if name=="graphql" and not self.args.graphql_introspection: method,body="GET",None
                elif name=="graphql": method,body="POST",json.dumps({"query":"query IntrospectionQuery { __schema { queryType { name } } }"}).encode()
                else: method,body="GET",None
                u=urlsplit(urljoin(o,path)); assert u.hostname is not None
                conn=(http.client.HTTPSConnection if u.scheme=="https" else http.client.HTTPConnection)(u.hostname,u.port,timeout=min(self.args.request_timeout,max(.1,deadline-time.monotonic())))
                try:
                    conn.request(method,urlunsplit(("","",u.path,u.query,"")),body=body,headers={"Content-Type":"application/json","User-Agent":"AutoRecon/8"}); resp=conn.getresponse(); data=resp.read(2_000_000)
                    p=self.raw/st.id/f"{idx:05d}-{name}.body"; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(data)
                    local.append({"origin":o,"probe":name,"url":urljoin(o,path),"status":resp.status,"bytes":len(data),"body":str(p),"timestamp":now()})
                except (OSError,http.client.HTTPException) as e: local.append({"origin":o,"probe":name,"error":str(e),"timestamp":now()})
                finally: conn.close()
            with lock: results.extend(local); st.processed+=1; self.save(); print(f"[api-discovery] {st.processed}/{st.total} {o} | elapsed={fmt(time.monotonic()-(deadline-self.args.stage_timeout))} | ETA={eta(st.processed,st.total,st.runtime_seconds)}",flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.concurrency) as ex:
            futures=[]
            for i,o in enumerate(origins): self.check(deadline); futures.append(ex.submit(one,i,o))
            for f in futures: self.check(deadline); f.result(timeout=max(.1,deadline-time.monotonic()))
        out=self.raw/st.id/"metrics.jsonl"; out.write_text("".join(json.dumps(x)+"\n" for x in results)); st.outputs=[str(out)]
    def generate_reports(self,rc:int)->None:
        self.work.mkdir(parents=True,exist_ok=True); stages=[dataclasses.asdict(self.stages[s]) for s in STAGE_IDS]; resume=f"autorecon {self.seed} --resume {self.run_id} --output-dir {self.out}"
        report={"version":"8.0.0","run_id":self.run_id,"target":self.seed,"status":"completed" if rc==0 else "partial","started_at":self.started_at,"generated_at":now(),"resume_command":resume,"evidence":{"raw":str(self.raw),"commands":str(self.command_log),"scope":str(self.scope_log)},"vulnerability_claims":[],"stages":stages}
        atomic_json(self.work/"report.json",report)
        with (self.work/"stages.csv").open("w",newline="") as f:
            w=csv.writer(f); w.writerow(["stage","status","processed","total","runtime_seconds","exit_code","reason"]); w.writerows([[s["id"],s["status"],s["processed"],s["total"],s["runtime_seconds"],s["exit_code"],s["failure_reason"]] for s in stages])
        lines=[f"# AutoRecon v8 — Raccoon 4K\n\nTarget: `{self.seed}`  \nRun: `{self.run_id}`  \nStatus: **{report['status']}**\n", "## Stage summary\n", "| Stage | Status | Progress | Runtime | Reason |\n|---|---|---:|---:|---|"]
        lines += [f"| {s['id']} | {s['status']} | {s['processed']}/{s['total']} | {s['runtime_seconds']}s | {s['failure_reason'] or ''} |" for s in stages]
        lines += ["\n## Evidence\n",f"- Raw evidence: `{self.raw}`",f"- Commands: `{self.command_log}`",f"- Scope decisions: `{self.scope_log}`","\n## Vulnerability claims\n\nNo automated candidate is represented as a validated vulnerability.",f"\n## Resume\n\n`{resume}`\n"]
        (self.work/"report.md").write_text("\n".join(lines))

def fmt(sec:float)->str:
    sec=max(0,int(sec)); return f"{sec//3600:02d}:{sec%3600//60:02d}:{sec%60:02d}"
def eta(done:int,total:int,elapsed:float)->str: return fmt((elapsed/max(done,1))*(total-done))
def csvset(values:list[str]|None)->set[str]: return {x for v in values or [] for x in v.split(",") if x}
def select_stages(args:argparse.Namespace)->tuple[set[str],dict[str,str]]:
    selected=set(STAGE_IDS); reasons={}
    only=csvset(args.only); skip=csvset(args.skip)|set(PROFILES[args.profile]["skip"])
    unknown=(only|skip|({args.restart_stage} if args.restart_stage else set()))-set(STAGE_IDS)
    if unknown: raise ValueError("unknown stage(s): "+",".join(sorted(unknown)))
    if only: selected=only|{"report"}; reasons.update({s:"not selected by --only" for s in set(STAGE_IDS)-selected})
    if args.from_stage: selected-={s for s in STAGE_IDS[:STAGE_IDS.index(args.from_stage)]}; reasons.update({s:f"before --from {args.from_stage}" for s in set(STAGE_IDS)-selected})
    if args.until: selected-={s for s in STAGE_IDS[STAGE_IDS.index(args.until)+1:]}; reasons.update({s:f"after --until {args.until}" for s in set(STAGE_IDS)-selected})
    for s in skip: selected.discard(s); reasons[s]="explicitly skipped" if s in csvset(args.skip) else f"disabled by {args.profile} profile"
    if args.passive:
        for s in ACTIVE:selected.discard(s);reasons[s]="disabled by --passive"
    return selected,reasons
