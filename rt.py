import pathlib

p = pathlib.Path("/tmp/opencode/main-wt/autorecon_v8/core.py")
s = p.read_text()

# 1. a plain-text atomic writer; atomic_json is json-only
o = "def normalize_target(raw: str) -> tuple[str,str]:"
assert s.count(o) == 1, f"anchor: {s.count(o)}"
s = s.replace(o, '''def atomic_text(path: Path, content: str) -> None:
    """Write text atomically.

    atomic_json is json-specific, and a half-written result.txt is worse than none: it is the file
    a human reads to decide what to chase, so a truncated write that looks complete is the one
    failure mode worth spending a temp file on.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".result-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


''' + o, 1)

# 2. the result.txt writer, called at the end of report generation
o = "    def generate_reports(self,rc:int)->None:"
assert s.count(o) == 1, f"generate_reports: {s.count(o)}"
s = s.replace(o, '''    def write_result_txt(self,status:str,resume:str,stages:list[dict[str,Any]])->Path|None:
        """
        One clean human-readable result.txt: the file a human reads to decide what to chase.

        Written to the run directory always, and mirrored to the shared evidence mount
        best-effort. Only non-empty sections appear, so an empty section never implies a finding
        that was not there. Everything in it is a candidate, never a validated vulnerability.
        """
        sep="="*72; sep2="-"*72
        def section(title:str,lines:list[str])->list[str]:
            return ["",f"[{title}]"]+lines if lines else []
        def read_stage(sid:str)->list[str]:
            return [l.strip() for l in self.read(sid) if l.strip() and not l.strip().startswith(";")]

        dns=read_stage("dns")
        subdomains=sorted(set(read_stage("subdomains")+read_stage("dnsx")))
        live=read_stage("httpx")
        ports=read_stage("ports")
        interesting=[u for u in self.read("corpus") if HIGH_VALUE_URL_RE.search(u)]

        # The money sections. These are candidates produced by the stages added after the
        # original result.txt design, and they are what a bounty run is actually read for.
        ac=self.raw/"access-checks"
        candidates:list[str]=[]
        if (ac/"anomalies.tsv").exists():
            for line in (ac/"anomalies.tsv").read_text(errors="replace").splitlines()[1:]:
                c=line.split("\\t")
                if len(c)>=5 and c[1]:
                    candidates.append(f"  [{c[2]}/{c[3]}] {c[1]}\\n      {c[0]}\\n      {c[5] if len(c)>5 else ''}".rstrip())
        suppressed_count=0
        if (ac/"suppressed.tsv").exists():
            suppressed_count=max(0,len([l for l in (ac/"suppressed.tsv").read_text(errors="replace").splitlines()[1:] if l.strip()]))
        paths=read_stage("ffuf")
        endpoints=read_stage("web-intelligence")

        stage_rows=[]
        for row in stages:
            if row["status"]=="pending": continue
            runtime=fmt(row["runtime_seconds"]) if row["runtime_seconds"] else "-"
            items=str(row["processed"]) if row["processed"] else "-"
            reason=f"  ({row['failure_reason']})" if row["failure_reason"] else ""
            stage_rows.append(f"  {row['id']:<20} {row['status']:<14} {items:>6} items   {runtime}{reason}")

        out=[sep,f"  AutoRecon v{__version__} -- {self.seed}",f"  Run    : {self.run_id}",
             f"  Status : {status}",f"  Started: {self.started_at}",sep]
        out+=section("DNS RECORDS",[f"  {x}" for x in dns])
        out+=section("SUBDOMAINS",[f"  {x}" for x in subdomains])
        out+=section("LIVE HOSTS",[f"  {x}" for x in live])
        out+=section("OPEN PORTS",[f"  {x}" for x in ports])
        out+=section("INTERESTING URLS",[f"  {x}" for x in interesting])
        out+=section("ACCESS-CHECK CANDIDATES (not validated vulnerabilities)",candidates)
        if suppressed_count:
            out+=["",f"[SUPPRESSED AS CORRECT BEHAVIOUR]  {suppressed_count} route(s) - see access-checks/suppressed.tsv"]
        out+=section("DISCOVERED PATHS (ffuf candidates)",[f"  {x}" for x in paths])
        out+=section("DISCOVERED ENDPOINTS (web-intelligence candidates)",[f"  {x}" for x in endpoints])
        if stage_rows: out+=["","[STAGE SUMMARY]"]+stage_rows
        out+=["",sep2,f"  Resume: {resume}",
              "  Every item above is a candidate. Confirm the identities are distinct accounts and",
              "  that the object is meant to be private before reporting anything as a finding.",sep,""]
        content="\\n".join(out)
        run_txt=self.work/"result.txt"
        atomic_text(run_txt,content)
        print(f"[report] result.txt -> {run_txt}",flush=True)
        if getattr(self.args,"no_kali_share",False):
            return run_txt
        share=Path(KALI_SHARE_RESULTS)
        target=share/f"{re.sub(r'[^A-Za-z0-9._-]','_',self.host)}-{self.run_id}.txt"
        try:
            share.mkdir(parents=True,exist_ok=True)
            atomic_text(target,content)
            print(f"[report] result.txt -> {target}",flush=True)
        except OSError as e:
            # A missing share mount must never fail a run that already has its result.
            print(f"[report] shared evidence mount unavailable ({e}); result is in {run_txt}",flush=True)
        return run_txt

''' + o, 1)

# 3. call it
o = '        (self.work/"report.md").write_text("\\n".join(lines))'
assert s.count(o) == 1, f"report.md write: {s.count(o)}"
s = s.replace(o, o + '''
        try:
            self.write_result_txt(report["status"],resume,stages)
        except OSError as e:
            # report.json and report.md are already on disk; a result.txt failure must not lose them.
            print(f"[report] result.txt could not be written: {e}",file=sys.stderr,flush=True)''', 1)

# 4. the resume variable must be assigned before the report is written
_gen = s.index("    def generate_reports(self,rc:int)->None:")
_write = s.index('        (self.work/"report.md").write_text', _gen)
assert "resume=" in s[_gen:_write], "resume is not assigned before the report is written"

# 5. constants
o = "SECURITY_HEADERS = ("
assert s.count(o) == 1
s = s.replace(o, '''KALI_SHARE_RESULTS = "/mnt/KaliShare/autorecon-results"
# Paths worth a human glance in a result file. Deliberately narrow: a result.txt that lists
# everything is the same as one that lists nothing.
HIGH_VALUE_URL_RE = re.compile(
    r"(\\.git/HEAD|\\.env|wp-config\\.php|/admin/?|/phpmyadmin|/_cat/|/actuator|/__debug__"
    r"|/graphql|/graphiql|/openapi|/swagger|/api/|/v\\d+/|/internal|/private|/backup)",
    re.IGNORECASE)
''' + o, 1)

# 6. __version__ import
o = "from pathlib import Path"
assert s.count(o) == 1
if "from . import __version__" not in s:
    s = s.replace(o, o + "\nfrom . import __version__", 1)

p.write_text(s)
print("result.txt implemented")
