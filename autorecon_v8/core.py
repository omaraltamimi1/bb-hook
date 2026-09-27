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
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

STATUSES = {"pending", "running", "completed", "partial", "failed", "skipped", "interrupted", "unimplemented"}
STAGE_IDS = ["dns", "subdomains", "dnsx", "tls", "httpx", "screenshots", "ports", "crawl", "archives", "corpus", "javascript", "api-discovery", "web-intelligence", "arjun", "nmap", "ffuf", "access-checks", "report"]
ACTIVE = {"screenshots", "ports", "crawl", "javascript", "api-discovery", "web-intelligence", "arjun", "nmap", "ffuf", "access-checks"}
DESCRIPTIONS = {
 "dns":"Collect DNS records", "subdomains":"Enumerate passive subdomains", "dnsx":"Resolve discovered names", "tls":"Collect TLS metadata", "httpx":"Identify HTTP origins", "screenshots":"Capture visual evidence", "ports":"Discover ports", "crawl":"Crawl live applications", "archives":"Collect archived URLs", "corpus":"Normalize and deduplicate URLs", "javascript":"Preserve and inspect JavaScript", "api-discovery":"Read-only API and identity probes", "web-intelligence":"Collect web metadata", "arjun":"Discover parameters", "nmap":"Validate exposed services", "ffuf":"Discover content", "access-checks":"Read-only access differentials", "report":"Publish reports"}
DEPS = {s: ([STAGE_IDS[i-1]] if i else []) for i,s in enumerate(STAGE_IDS)}
DEPS.update({"screenshots":["httpx"],"ports":["dnsx"],"crawl":["httpx"],"archives":["subdomains"],"corpus":["crawl","archives"],"javascript":["corpus"],"api-discovery":["httpx"],"web-intelligence":["httpx"],"arjun":["corpus"],"nmap":["ports"],"ffuf":["httpx"],"access-checks":["corpus"],"report":[]})
# Stages with a real implementation: a cmds entry in generic_stage, a method dispatched from
# execute(), or report generation. Every other stage is routed out of the generic fallback and
# reported as unimplemented instead of silently completing. Derived from STAGE_IDS so a newly
# added stage cannot escape classification.
STAGE_IMPLEMENTED = {"dns", "subdomains", "dnsx", "tls", "httpx", "ports", "archives", "corpus", "crawl", "api-discovery", "javascript", "access-checks", "report"}
UNIMPLEMENTED = tuple(s for s in STAGE_IDS if s not in STAGE_IMPLEMENTED)
assert not (STAGE_IMPLEMENTED & set(UNIMPLEMENTED)) and set(STAGE_IMPLEMENTED) | set(UNIMPLEMENTED) == set(STAGE_IDS), "stage classification does not partition STAGE_IDS"

PROFILES: dict[str,dict[str,Any]] = {
 "passive":{"concurrency":4,"rate_limit":5.0,"request_timeout":10.0,"tool_timeout":300.0,"stage_timeout":600.0,"max_hosts":500,"skip":sorted(ACTIVE)},
 "fast":{"concurrency":8,"rate_limit":20.0,"request_timeout":8.0,"tool_timeout":300.0,"stage_timeout":600.0,"max_hosts":200,"skip":["screenshots","nmap","ffuf"]},
 "balanced":{"concurrency":10,"rate_limit":15.0,"request_timeout":12.0,"tool_timeout":900.0,"stage_timeout":1800.0,"max_hosts":1000,"skip":[]},
 "deep":{"concurrency":20,"rate_limit":10.0,"request_timeout":20.0,"tool_timeout":1800.0,"stage_timeout":7200.0,"max_hosts":5000,"skip":[]},
 "custom":{"concurrency":4,"rate_limit":5.0,"request_timeout":10.0,"tool_timeout":600.0,"stage_timeout":1200.0,"max_hosts":500,"skip":[]},
}

SOURCE_MAP_RE = re.compile(r"[ \t]*(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*'\"]+)")
JS_MAX_BYTES = 4_000_000
JS_EXTS = (".js", ".mjs")


def source_map_refs(text: str) -> list[str]:
    """Return sourceMappingURL targets declared by a bundle, in order, deduped.

    Accepts both the //# form and the /*# */ form, with @ as a legacy variant.
    """
    refs: list[str] = []
    for ref in SOURCE_MAP_RE.findall(text or ""):
        ref = ref.strip()
        if ref and ref not in refs:
            refs.append(ref)
    return refs


CORPUS_JS_EXTS = (".js", ".mjs")
CORPUS_STATIC_EXTS = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff",
                      ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3", ".wav", ".avi",
                      ".mov", ".zip", ".gz", ".tar", ".rar", ".7z", ".pdf", ".doc", ".docx", ".xls",
                      ".xlsx", ".ppt", ".pptx", ".csv", ".rss", ".atom")
CORPUS_API_HINTS = ("/api", "/v1", "/v2", "/v3", "/graphql", "/graphiql", "/rest", "/rpc", "/json",
                    "/service", "/internal", "/admin", "/swagger", "/openapi", "/.well-known", "/oauth",
                    "/token", "/auth", "/webhook", "/callback", "/ws", "/socket.io")
ID_SEGMENT_RE = re.compile(r"^(?:\d+|[0-9a-f]{16,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\d{4,})$", re.IGNORECASE)
ID_PARAM_RE = re.compile(r"(?:^|[?&#])(?:id|uuid|guid|key|code|token|no|num|number|ref|q|search)$", re.IGNORECASE)


def canonical_url(raw: str) -> str | None:
    """
    Canonicalise a discovered URL for the corpus.

    Wraps normalize_url (lowercase scheme and host, drop default port, drop
    fragment) and adds path tidying: collapse repeated slashes, resolve '.' and
    '..' segments, strip a trailing slash except at the root, and sort query
    parameters so ?a=1&b=2 and ?b=2&a=1 collapse to one entry.

    The query is left untouched when it does not parse cleanly, because
    re-encoding an odd query can change what the endpoint actually does.
    Returns None when the value is not a usable HTTP(S) URL.
    """
    try:
        u = urlsplit(normalize_url(raw))
    except ValueError:
        return None
    if not u.hostname:
        return None
    segments: list[str] = []
    for segment in u.path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    path = "/" + "/".join(segments)
    query = u.query
    if query:
        try:
            pairs = parse_qsl(query, keep_blank_values=True)
            if pairs and all(key for key, _ in pairs):
                query = urlencode(sorted(pairs), doseq=False)
        except ValueError:
            pass
    return urlunsplit((u.scheme.lower(), u.netloc.lower(), path, query, ""))


def is_static_url(value: str) -> bool:
    try:
        return urlsplit(value).path.lower().endswith(CORPUS_STATIC_EXTS)
    except ValueError:
        return False


def is_api_url(value: str) -> bool:
    try:
        u = urlsplit(value)
    except ValueError:
        return False
    path = u.path.lower()
    if path.endswith((".json", ".xml", ".graphql")):
        return True
    if u.query and any(h in u.query.lower() for h in ("api", "format=json", "callback", "jsonp")):
        return True
    return any(h in path for h in CORPUS_API_HINTS)


def has_parameters(value: str) -> bool:
    """True when the URL carries a query parameter or an id-like path segment."""
    try:
        u = urlsplit(value)
    except ValueError:
        return False
    if u.query:
        for pair in u.query.split("&"):
            if not pair:
                continue
            key, _, _val = pair.partition("=")
            if key and (("=" in pair) or ID_PARAM_RE.search("?" + key)):
                return True
    return any(ID_SEGMENT_RE.match(segment) for segment in u.path.split("/") if segment)


CRAWL_DEFAULT_DEPTH = 3
CRAWL_NATIVE_MAX_URLS = 500
CRAWL_JS_EXTS = (".js", ".mjs")
LINK_ATTR_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'<>\s]{2,2048})["']""", re.IGNORECASE)
SKIP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "#", "blob:")


def extract_links(html: str, base: str) -> list[str]:
    """Absolute, same-page link targets found in an HTML document, in document order."""
    out: list[str] = []
    for ref in LINK_ATTR_RE.findall(html or ""):
        ref = ref.strip()
        if not ref or ref.lower().startswith(SKIP_SCHEMES):
            continue
        try:
            absolute = urljoin(base, ref)
        except ValueError:
            continue
        try:
            absolute = canonical_url(absolute)
        except ValueError:
            continue
        if absolute and absolute not in out:
            out.append(absolute)
    return out


def crawl_scope_pattern(hosts: Iterable[str]) -> str | None:
    """
    Build a katana -cs regex covering exactly the hosts in scope.

    katana's default -fs rdn follows the whole root domain, which over-collects
    when a program authorises one subdomain but not its siblings. Passing -cs
    narrows the crawler to the hosts the run was actually scoped to.
    """
    alternatives = sorted({h.strip().lower().rstrip(".") for h in hosts if h and h.strip()})
    if not alternatives:
        return None
    return "(" + "|".join(re.escape(h) for h in alternatives) + ")"


ACCESS_CHECKS_DEFAULT_MAX = 40
ACCESS_BODY_LIMIT = 512_000
STACK_TRACE_RE = re.compile(r"(?:Traceback \(most recent call last\)|at [\w.$]+\([^)]*:\d+\)|java\.lang\.|Exception in thread|ORA-\d{5}|SQLSTATE\[|panic:|goroutine \d+ \[)", re.IGNORECASE)


def load_credentials(filename: str) -> dict[str, str]:
    """
    Read one identity from a file and return the request headers it implies.

    Accepts the shapes an operator actually has to hand: a raw cookie line, a
    'Cookie: ...' header, a pasted curl command, or a raw 'Authorization: ...'
    value. Values are used verbatim; nothing is redacted.
    """
    path = Path(filename).expanduser()
    if not path.is_file():
        raise ValueError(f"credential file does not exist: {path}")
    raw = path.read_text(errors="replace").strip()
    if not raw:
        raise ValueError(f"credential file is empty: {path}")
    auth = re.search(r"(?im)^\s*Authorization\s*:\s*(.+?)\s*$", raw)
    if auth:
        return {"Authorization": auth.group(1).strip().strip("^\"'")}
    cookie = re.search(r"(?im)\bCookie\s*:\s*([^\r\n]+)", raw)
    if cookie:
        return {"Cookie": cookie.group(1).strip().rstrip("^\"'").strip()}
    curl_b = re.search(r"(?:^|\s)(?:-b|--cookie)\s+['\"]?([^'\"\n]+)", raw)
    if curl_b:
        return {"Cookie": curl_b.group(1).strip()}
    if "\n" in raw or "\r" in raw:
        raise ValueError("credential file must hold one Cookie header, one Authorization header, a cookie line, or a curl command")
    if any(char in raw for char in "\r\0"):
        raise ValueError("invalid credential value")
    lowered = raw.lower()
    if lowered.startswith(("bearer ", "basic ", "token ", "digest ")):
        return {"Authorization": raw}
    return {"Cookie": raw}


def response_signature(status: int, body: bytes, content_type: str = "") -> dict[str, Any]:
    """Comparable fingerprint of a response: status, length, digest, and JSON shape."""
    length = len(body or b"")
    digest = hashlib.sha256(body or b"").hexdigest()
    keys: list[str] = []
    if "json" in (content_type or "").lower() or (body or b"")[:1] in (b"{", b"["):
        try:
            parsed = json.loads((body or b"").decode("utf-8", "ignore"))
            if isinstance(parsed, dict):
                keys = sorted(str(k) for k in parsed)[:64]
        except (ValueError, TypeError):
            keys = []
    return {"status": status, "length": length, "sha256": digest, "json_keys": keys,
            "stack_trace": bool(STACK_TRACE_RE.search((body or b"").decode("utf-8", "ignore")[:20000]))}


def access_signals(states: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Compare per-identity response signatures and emit candidate signals.

    These are CANDIDATES, not findings. Two authenticated identities returning an
    identical body is the precondition for IDOR, but the tool cannot prove the two
    identities are different principals, nor that the object is meant to be
    private. Every signal therefore carries a confidence and an explicit
    false-positive risk, and each includes the next step a human must take.
    """
    out: list[dict[str, Any]] = []
    anon = states.get("anon") or {}
    a = states.get("a") or {}
    b = states.get("b") or {}
    ok = lambda s: bool(s) and isinstance(s.get("status"), int) and 200 <= s["status"] < 300

    if anon and a and anon.get("status") != a.get("status"):
        out.append({"signal": "auth_required", "severity": "info", "confidence": "n/a",
                    "false_positive_risk": "none, this is correct behaviour",
                    "detail": f"anonymous {anon.get('status')} vs identity-a {a.get('status')}",
                    "verify": "no action, the endpoint correctly requires authentication"})

    if ok(anon) and ok(a) and anon.get("sha256") == a.get("sha256"):
        out.append({"signal": "anon_matches_auth", "severity": "high", "confidence": "medium",
                    "false_positive_risk": "public endpoint, or a cache serving one variant to both",
                    "detail": "anonymous and authenticated responses are byte-identical",
                    "verify": "request the same URL with no credentials and confirm the body is the authenticated body, not a public stub"})

    if ok(a) and ok(b):
        if a.get("sha256") == b.get("sha256") and a.get("status") == b.get("status"):
            out.append({"signal": "identical_across_identities", "severity": "high", "confidence": "medium",
                        "false_positive_risk": "the two identities may be the same account, or the object may be public by design",
                        "detail": f"identity-a and identity-b both returned {a.get('status')} with an identical {a.get('length')}-byte body",
                        "verify": "confirm a and b are distinct accounts, then swap the object id in the URL between them and confirm b still receives a's object"})
        elif a.get("length") != b.get("length"):
            out.append({"signal": "length_differs_across_identities", "severity": "medium", "confidence": "low",
                        "false_positive_risk": "per-user state such as a name or cart count changes the length legitimately",
                        "detail": f"identity-a {a.get('length')} bytes vs identity-b {b.get('length')} bytes",
                        "verify": "diff the two bodies field by field and identify any field that is not the requester's own"})
        else:
            out.append({"signal": "same_status_different_content", "severity": "medium", "confidence": "low",
                        "false_positive_risk": "timestamps, request ids or nonces in the body change the digest",
                        "detail": "identical status and length but different body digest",
                        "verify": "diff the bodies and ignore volatile fields before drawing a conclusion"})

    leaked=[label for label,sig in states.items() if sig and sig.get("stack_trace")]
    if leaked:
        out.append({"signal": "verbose_error", "severity": "low", "confidence": "medium",
                    "false_positive_risk": "a generic error page that happens to contain a stack frame in a sample body",
                    "detail": "stack-trace or exception signature in the response body, seen by: "+",".join(sorted(leaked)),
                    "verify": "capture the full body and confirm it discloses internal paths, versions or query fragments"})
    return out

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
        self.identities={"anon":{},"a":{},"b":{}}
        if getattr(args,"cookie_file",None): self.identities["a"]=load_credentials(args.cookie_file)
        if getattr(args,"cookie_file_b",None): self.identities["b"]=load_credentials(args.cookie_file_b)
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
        blocked=[s for s in STAGE_IDS if s in self.selected and s in UNIMPLEMENTED]
        if blocked:
            print("autorecon: warning: unimplemented stage(s) scheduled: "+", ".join(blocked)+" -- these will be reported as unimplemented, not completed",file=sys.stderr,flush=True)
            if getattr(self.args,"strict_stages",False):
                print("autorecon: --strict-stages set, refusing to run with unimplemented stage(s)",file=sys.stderr,flush=True)
                return 2
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
        except Exception as e: rc=1; self.mark_current("failed",f"{type(e).__name__}: {e}",1); print(f"autorecon: unexpected error: {type(e).__name__}: {e}",file=sys.stderr,flush=True)
        finally:
            self.generate_reports(rc); self.save()
        if rc: print(f"Resume with: autorecon {self.seed} --resume {self.run_id} --output-dir {self.out}",file=sys.stderr)
        elif not self.args.keep_temp: shutil.rmtree(self.work/"tmp",ignore_errors=True)
        return rc
    def mark_current(self,status:str,reason:str,rc:int)->None:
        if self.current:
            st=self.stages[self.current]; st.status=status; st.failure_reason=reason; st.exit_code=rc; st.ended_at=now(); st.resume="retry incomplete units"; self.save()
    def execute(self,st:StageState)->None:
        self.current=st.id; st.status="running"; st.failure_reason=None; st.exit_code=None; st.started_at=now(); start=time.monotonic(); deadline=min(self.global_deadline,start+self.args.stage_timeout); self.save()
        try:
            if st.id=="report": self.generate_reports(0)
            elif st.id=="api-discovery": self.api_stage(st,deadline)
            elif st.id=="javascript": self.javascript_stage(st,deadline)
            elif st.id=="corpus": self.corpus_stage(st,deadline)
            elif st.id=="crawl": self.crawl_stage(st,deadline)
            elif st.id=="access-checks": self.access_checks_stage(st,deadline)
            else: self.generic_stage(st,deadline)
            if st.status=="running": st.status="completed"; st.exit_code=0; st.resume="completed artifacts reusable"
        except Deadline: st.status="partial" if st.processed else "failed"; st.exit_code=124; st.failure_reason="stage deadline expired"; st.resume="retry remaining units"
        except Interrupted: st.status="interrupted"; st.exit_code=130; st.failure_reason="signal received"; st.resume="retry remaining units"; raise
        except Exception as e:
            st.status="partial" if st.processed else "failed"; st.exit_code=1
            st.failure_reason=f"{type(e).__name__}: {e}"; st.resume="retry remaining units"
            print(f"[{st.id}] unexpected error: {st.failure_reason}",file=sys.stderr,flush=True)
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
        if st.id in UNIMPLEMENTED:
            st.status="unimplemented"; st.failure_reason="no runner on this branch; candidates listed for manual follow-up"
            self.write_lines(dest,values)
            print(f"[{st.id}] unimplemented: no runner for this stage, {len(values)} candidate(s) listed for manual follow-up",flush=True)
            return
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
            raise RuntimeError(f"stage {st.id!r} reached the generic fallback but is classified as implemented; add a cmds entry or a dispatch branch")
    def _http_get(self,url:str,deadline:float,limit:int=JS_MAX_BYTES)->tuple[int,bytes]:
        u=urlsplit(url)
        if not u.hostname: return 0,b""
        timeout=max(.1,min(self.args.request_timeout,deadline-time.monotonic()))
        conn=(http.client.HTTPSConnection if u.scheme=="https" else http.client.HTTPConnection)(u.hostname,u.port,timeout=timeout)
        try:
            conn.request("GET",urlunsplit(("", "",u.path or "/",u.query,"")),headers={"User-Agent":"AutoRecon/8","Accept":"*/*"})
            resp=conn.getresponse(); return resp.status,resp.read(limit)
        except (OSError,http.client.HTTPException) as e:
            return 0,str(e).encode()
        finally: conn.close()
    def javascript_stage(self,st:StageState,deadline:float)->None:
        raw_inputs=self.inputs(st.id)
        values=[v for v in raw_inputs if urlsplit(v).path.lower().endswith(JS_EXTS)]
        seen=set(); values=[v for v in values if not (v in seen or seen.add(v))]
        root=self.raw/st.id; dest=root/"normalized.txt"; st.total=len(values); st.inputs=values
        if not values:
            st.status="skipped"; st.failure_reason="no javascript URLs in corpus"; st.outputs=[str(dest)]; self.write_lines(dest,[]); return
        if self.args.dry_run: self.write_lines(dest,values); st.processed=st.total; st.outputs=[str(dest)]; return
        root.mkdir(parents=True,exist_ok=True); input_file=root/"inputs.txt"; self.write_lines(input_file,values)
        bundles:list[str]=[]; maps:list[str]=[]; refs:list[str]=[]; rows:list[tuple[str,str,str,str]]=[]
        lock=threading.Lock()
        def one(idx:int,url:str)->None:
            self.check(deadline)
            status,body=self._http_get(url,deadline)
            entry=[str(idx),url,str(status),str(len(body)),"","",""]
            if status==200 and body:
                name=f"{idx:05d}-"+re.sub(r"[^A-Za-z0-9._-]","_",urlsplit(url).path.rsplit("/",1)[-1] or "bundle.js")[:120]
                if not name.endswith(JS_EXTS): name+=".js"
                bundle=root/name; bundle.write_bytes(body); entry[4]=str(bundle)
                found=source_map_refs(body[-8192:].decode("utf-8","ignore")) or source_map_refs(body.decode("utf-8","ignore"))
                if found:
                    target=urljoin(url,found[0]); entry[5]=target; entry[6]=found[0]
                    # A bundle controls this URL, so it is untrusted input: re-check scope before fetching.
                    if self.scope.decide(target)[0]:
                        mstatus,mbody=self._http_get(target,deadline)
                        if mstatus==200 and mbody:
                            mname=name[:-3]+".js.map"; mpath=root/mname; mpath.write_bytes(mbody); entry[6]=str(mpath)
            with lock: rows.append((entry[1],entry[2],entry[4],entry[6])); st.processed+=1
            if entry[4]: bundles.append(entry[4])
            if entry[5]: refs.append("\t".join([url,found[0],entry[5],entry[6] if entry[6].startswith(str(root)) else ""]))
            if entry[6].startswith(str(root)): maps.append(entry[6])
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,self.args.concurrency)) as ex:
            futures=[ex.submit(one,i,u) for i,u in enumerate(values)]
            for f in futures:
                self.check(deadline)
                try: f.result(timeout=max(.1,deadline-time.monotonic()))
                except (Deadline,Interrupted): raise
                except Exception as e: print(f"[javascript] {type(e).__name__}: {e}",file=sys.stderr,flush=True)
        self.write_lines(dest,[("\t".join(r)) for r in sorted(set(rows))])
        self.write_lines(root/"bundles.txt",sorted(set(bundles)))
        self.write_lines(root/"maps.txt",sorted(set(maps)))
        self.write_lines(root/"source-map-refs.txt",sorted(set(refs)))
        st.outputs=[str(dest),str(root/"bundles.txt"),str(root/"maps.txt"),str(root/"source-map-refs.txt")]
        print(f"[javascript] {st.processed}/{st.total} bundle(s), {len(set(maps))} source map(s)",flush=True)
        if st.processed<st.total:
            st.status="partial"; st.failure_reason=f"{st.total-st.processed} bundle(s) did not complete"
    def corpus_stage(self,st:StageState,deadline:float)->None:
        raw_inputs=self.inputs(st.id); root=self.raw/st.id
        dest=root/"normalized.txt"; st.total=len(raw_inputs); st.inputs=[str(x) for x in raw_inputs]
        canonical:dict[str,str]={}
        for value in raw_inputs:
            self.check(deadline)
            if not isinstance(value,str): continue
            for candidate in (value.strip(), *value.split()):
                if not candidate: continue
                url=canonical_url(candidate)
                if not url: continue
                if not self.scope.decide(url)[0]: continue
                canonical[url]=url
                break
        if not canonical:
            st.status="skipped"; st.failure_reason="no in-scope HTTP URLs from crawl/archives"
            st.outputs=[str(dest)]; self.write_lines(dest,[]); return
        if self.args.dry_run:
            self.write_lines(dest,sorted(canonical)); st.processed=st.total
            st.outputs=[str(dest)]; return
        root.mkdir(parents=True,exist_ok=True)
        signal=sorted(canonical); static=[u for u in signal if is_static_url(u)]
        signal=[u for u in signal if u not in set(static)]
        javascript=[u for u in signal if urlsplit(u).path.lower().endswith(CORPUS_JS_EXTS)]
        api=[u for u in signal if is_api_url(u)]
        params=[u for u in signal if has_parameters(u)]
        plain=[u for u in signal if not is_api_url(u) and not has_parameters(u) and not urlsplit(u).path.lower().endswith(CORPUS_JS_EXTS)]
        self.write_lines(dest,signal)
        self.write_lines(root/"javascript.txt",javascript)
        self.write_lines(root/"api.txt",api)
        self.write_lines(root/"params.txt",params)
        self.write_lines(root/"static.txt",static)
        self.write_lines(root/"plain.txt",plain)
        self.write_lines(root/"origins.txt",unique_origins(signal))
        self.write_lines(root/"classify.tsv",[f"{kind}\t{len(items)}\t{path}" for kind,items,path in
            (("javascript",javascript,"javascript.txt"),("api",api,"api.txt"),("params",params,"params.txt"),
             ("plain",plain,"plain.txt"),("static",static,"static.txt"))])
        st.outputs=[str(p) for p in (dest,root/"javascript.txt",root/"api.txt",root/"params.txt",root/"plain.txt",root/"static.txt",root/"origins.txt",root/"classify.tsv")]
        st.processed=st.total
        print(f"[corpus] {len(signal)} canonical URL(s): {len(javascript)} js, {len(api)} api, {len(params)} parameterized, {len(plain)} plain, {len(static)} static excluded",flush=True)
    def crawl_scope_pattern(self)->str|None:
        hosts=[self.host]+[h for h in self.args.scope_include if h]
        for line in self.read("dnsx")+self.read("httpx"):
            host=urlsplit(line if "://" in line else "//"+line).hostname
            if host: hosts.append(host)
        return crawl_scope_pattern(hosts)
    def crawl_native(self,seeds:list[str],deadline:float,cap:int)->list[str]:
        """Bounded same-scope BFS used when katana is unavailable."""
        found:set[str]=set(seeds); queue=[(s,0) for s in seeds]; ordered=list(seeds)
        while queue and len(found)<cap:
            url,depth=queue.pop(0)
            if depth>=self.args.crawl_depth: continue
            self.check(deadline)
            status,body=self._http_get(url,deadline,limit=2_000_000)
            if status!=200 or not body: continue
            links=extract_links(body[:2_000_000].decode("utf-8","ignore"),url)
            for link in links:
                if not self.scope.decide(link)[0]: continue
                if link in found: continue
                found.add(link); ordered.append(link); queue.append((link,depth+1))
                if len(found)>=cap: break
        return ordered
    def crawl_stage(self,st:StageState,deadline:float)->None:
        seeds=[v for v in self.inputs(st.id) if v]
        root=self.raw/st.id; dest=root/"normalized.txt"; st.total=len(seeds); st.inputs=seeds
        if not seeds:
            st.status="skipped"; st.failure_reason="no live HTTP origins from httpx"
            st.outputs=[str(dest)]; self.write_lines(dest,[]); return
        if self.args.dry_run:
            self.write_lines(dest,seeds); st.processed=st.total; st.outputs=[str(dest)]; return
        root.mkdir(parents=True,exist_ok=True)
        input_file=root/"inputs.txt"; self.write_lines(input_file,seeds)
        tool=shutil.which("katana"); scope_pattern=self.crawl_scope_pattern()
        if tool:
            # katana has no -l flag: -u/-list takes targets, and also accepts a file path,
            # which avoids ARG_MAX for large seed sets. -e cdn drops CDN hosts, -duc skips
            # the update check, -nc disables ANSI colouring in the captured stdout.
            cmd=[tool,"-silent","-u",str(input_file),"-d",str(max(1,self.args.crawl_depth)),
                 "-c",str(max(1,self.args.concurrency)),"-rl",str(max(1,int(self.args.rate_limit))),
                 "-timeout",str(max(1,int(self.args.request_timeout))),"-e","cdn","-duc","-nc"]
            if scope_pattern: cmd+=["-cs",scope_pattern]
            stdout=root/"katana.txt"
            rc=self.command(st.id,cmd,self.host,deadline,stdout,cwd=root); st.exit_code=rc
            engine="katana"
            lines=stdout.read_text(errors="replace").splitlines() if stdout.exists() else []
            discovered=[line.strip() for line in lines if line.strip().startswith(("http://","https://"))]
        else:
            engine="native"; rc=0
            discovered=self.crawl_native(seeds,deadline,CRAWL_NATIVE_MAX_URLS)
            st.failure_reason=None
        # Scope.decide is the enforcement point. katana is told -cs as a first filter, but the
        # crawler follows attacker-influenced links, so nothing it emits is trusted.
        kept=[u for u in dict.fromkeys(discovered) if self.scope.decide(u)[0]]
        dropped=len(discovered)-len(kept)
        self.write_lines(dest,kept)
        self.write_lines(root/"dropped-out-of-scope.txt",[u for u in dict.fromkeys(discovered) if u not in set(kept)])
        st.outputs=[str(dest),str(root/"dropped-out-of-scope.txt")]+([str(root/"katana.txt")] if engine=="katana" else [])
        st.processed=len(kept)
        print(f"[crawl] {engine}: {len(kept)} in-scope URL(s) from {len(seeds)} seed(s), {dropped} dropped as out-of-scope",flush=True)
        if engine=="native" and not tool:
            st.failure_reason="katana not installed; used the bounded native crawler instead"
        if rc and not kept:
            st.status="failed"; st.failure_reason=f"{engine} exited {rc} and produced no in-scope URLs"
    def _probe(self,url:str,headers:dict[str,str],deadline:float)->dict[str,Any]:
        """One read-only GET with an explicit header set. Redirects are never followed."""
        u=urlsplit(url)
        if not u.hostname: return {"status":0,"length":0,"sha256":"","json_keys":[],"stack_trace":False,"location":"","error":"no host"}
        timeout=max(.1,min(self.args.request_timeout,deadline-time.monotonic()))
        conn=(http.client.HTTPSConnection if u.scheme=="https" else http.client.HTTPConnection)(u.hostname,u.port,timeout=timeout)
        send={"User-Agent":"AutoRecon/8","Accept":"*/*",**headers}
        try:
            conn.request("GET",urlunsplit(("", "",u.path or "/",u.query,"")),headers=send)
            resp=conn.getresponse(); body=resp.read(ACCESS_BODY_LIMIT)
            sig=response_signature(resp.status,body,resp.headers.get("Content-Type") or "")
            sig["location"]=resp.headers.get("Location") or ""
            return sig
        except (OSError,http.client.HTTPException) as e:
            return {"status":0,"length":0,"sha256":"","json_keys":[],"stack_trace":False,"location":"","error":f"{type(e).__name__}: {e}"}
        finally: conn.close()
    def access_check_targets(self)->tuple[list[str],list[str]]:
        """Targets from the corpus partitions this stage cares about, with provenance."""
        params=[v for v in self.read_partition("params.txt") if v]
        api=[v for v in self.read_partition("api.txt") if v]
        ordered:list[str]=[]; seen=set()
        for url in params+api:
            if url not in seen: seen.add(url); ordered.append(url)
        return ordered,["params.txt","api.txt"]
    def read_partition(self,name:str)->list[str]:
        p=self.raw/"corpus"/name
        return [ln.strip() for ln in p.read_text(errors="replace").splitlines() if ln.strip()] if p.exists() else []
    def access_checks_stage(self,st:StageState,deadline:float)->None:
        root=self.raw/st.id; dest=root/"normalized.txt"
        candidates,provenance=self.access_check_targets()
        if not candidates:
            st.status="skipped"; st.failure_reason="no parameterized or API targets in corpus"
            st.outputs=[str(dest)]; self.write_lines(dest,[]); return
        cap=int(getattr(self.args,"access_checks_max",0) or ACCESS_CHECKS_DEFAULT_MAX)
        targets=candidates[:cap]; refused_scope=[u for u in candidates[cap:]]
        if not self.identities.get("a"):
            st.status="skipped"; st.failure_reason="no --cookie-file supplied, so there is no authenticated state to compare against"
            st.outputs=[str(dest)]; self.write_lines(dest,[]); return
        if self.args.dry_run:
            self.write_lines(dest,targets); st.processed=len(targets); st.outputs=[str(dest)]; return
        root.mkdir(parents=True,exist_ok=True)
        self.write_lines(root/"inputs.txt",targets)
        states_available=[s for s in ("anon","a","b") if s=="anon" or self.identities.get(s)]
        findings:list[dict[str,Any]]=[]; rows:list[str]=[]; refused:list[str]=[]
        for url in targets:
            self.check(deadline)
            if not self.scope.decide(url)[0]:
                refused.append(url); continue
            observed={s:self._probe(url,self.identities.get(s) or {},deadline) for s in states_available}
            for label,sig in observed.items():
                location=sig.get("location") or ""
                if location:
                    absolute=urljoin(url,location)
                    if not self.scope.decide(absolute)[0]:
                        refused.append(absolute)
                        sig["location"]=f"{absolute} [REFUSED: out of scope]"
            signals=access_signals(observed)
            for sig in signals:
                findings.append({"url":url,"source":next((p for p in provenance if True),""),"identity_states":states_available,
                                 "observed":{k:{kk:vv for kk,vv in v.items() if kk!="error"} for k,v in observed.items()},**sig})
            rows.append("\t".join([url]+[str(observed[s].get("status",0)) for s in states_available]
                                   +[str(observed[s].get("length",0)) for s in states_available]
                                   +[",".join(s["signal"] for s in signals) or "none"]))
            st.processed+=1
        self.write_lines(dest,rows)
        suppressed=[f for f in findings if f["signal"]=="auth_required"]
        real=[f for f in findings if f["signal"]!="auth_required"]
        def table(path:Path,header:list[str],rows:list[list[str]])->None:
            # write_lines() sorts and set-dedupes, which would move a header row and drop repeats.
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text("\n".join(["\t".join(header)]+["\t".join(r) for r in rows])+"\n")
        table(root/"anomalies.tsv",["url","signal","severity","confidence","false_positive_risk","detail","verify"],
              [[f["url"],f["signal"],f["severity"],f["confidence"],f["false_positive_risk"],f["detail"],f["verify"]] for f in real])
        table(root/"suppressed.tsv",["url","signal","reason"],
              [[f["url"],f["signal"],f["false_positive_risk"]] for f in suppressed])
        self.write_lines(root/"refused.txt",sorted(set(refused)))
        atomic_json(root/"findings.json",{"generated_at":now(),"run_id":self.run_id,"target":self.seed,
            "identity_states":states_available,"targets_considered":len(targets),"targets_probed":st.processed,
            "candidates":candidates,"candidates_not_probed":len(candidates)-len(targets),
            "refused_out_of_scope":sorted(set(refused)),"suppressed":suppressed,"candidates_flagged":real,
            "disclaimer":"candidates only; none of these is a validated vulnerability. Two authenticated identities returning an identical body is the precondition for IDOR, not proof. Confirm the identities are distinct accounts and that the object is meant to be private before reporting."})
        st.outputs=[str(dest),str(root/"anomalies.tsv"),str(root/"findings.json"),str(root/"suppressed.tsv"),str(root/"refused.txt")]
        print(f"[access-checks] {st.processed}/{len(targets)} target(s) probed across {len(states_available)} state(s): {len(real)} candidate(s), {len(suppressed)} suppressed, {len(set(refused))} refused out-of-scope",flush=True)
        if refused: st.failure_reason=f"{len(set(refused))} out-of-scope target(s) or callback(s) refused"
        if not real: st.status="completed"
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
