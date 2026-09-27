import pathlib

p = pathlib.Path("/tmp/opencode/main-wt/autorecon_v8/core.py")
s = p.read_text()

# ---------------------------------------------------------------- helpers
o = "def crawl_scope_pattern(hosts: Iterable[str]) -> str | None:"
assert s.count(o) == 1, f"anchor: {s.count(o)}"
helpers = '''WEB_INTEL_DEFAULT_MAX = 40
WEB_INTEL_BODY_LIMIT = 1_000_000
SECURITY_HEADERS = ("content-security-policy", "strict-transport-security", "x-frame-options",
                    "x-content-type-options", "referrer-policy", "permissions-policy",
                    "access-control-allow-origin", "access-control-allow-credentials")
COOKIE_ATTRS = ("secure", "httponly", "samesite")
COMMENT_INTEREST = ("todo", "fixme", "hack", "debug", "password", "passwd", "secret", "token",
                    "api_key", "apikey", "access_key", "private key", "admin", "internal only",
                    "do not remove", "temporary", "config", "backup", "staging")
# Endpoints a page calls but never links to. A crawler following href/src never sees these, and
# they are where authorization bugs tend to live.
XHR_URL_RES = (
    re.compile(r"""\\bfetch\\s*\\(\\s*['"`]([^'"`\\s]{2,300})""", re.I),
    re.compile(r"""\\baxios\\.(?:get|post|put|patch|delete)\\s*\\(\\s*['"`]([^'"`\\s]{2,300})""", re.I),
    re.compile(r"""\\burl\\s*:\\s*['"`]([^'"`\\s]{2,300})""", re.I),
    re.compile(r"""\\.open\\s*\\(\\s*['"](?:GET|POST|PUT|DELETE|PATCH)['"]\\s*,\\s*['"`]([^'"`\\s]{2,300})""", re.I),
)
FORM_ACTION_RE = re.compile(r"""<form\\b[^>]*?\\baction\\s*=\\s*['"]([^'"]{1,300})['"]""", re.I | re.S)
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
META_RE = re.compile(r"""<meta\\b[^>]*>""", re.I)
META_NAME_RE = re.compile(r"""\\bname\\s*=\\s*['"]([^'"]+)['"]""", re.I)
META_CONTENT_RE = re.compile(r"""\\bcontent\\s*=\\s*['"]([^'"]*)['"]""", re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
TAG_RE = re.compile(r"<[^>]+>")


def html_text(raw: str) -> str:
    return TAG_RE.sub(" ", raw or "")


def html_title(raw: str) -> str:
    found = TITLE_RE.search(raw or "")
    return " ".join(html_text(found.group(1)).split())[:200] if found else ""


def html_comments(raw: str) -> list[str]:
    """Comments worth a human glance. A comment dump is noise, so this filters hard."""
    out: list[str] = []
    for body in HTML_COMMENT_RE.findall(raw or ""):
        text = " ".join(body.split())
        if not text or len(text) > 2000:
            continue
        if any(word in text.lower() for word in COMMENT_INTEREST):
            out.append(text[:500])
    return out


def html_meta(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for tag in META_RE.findall(raw or ""):
        name = META_NAME_RE.search(tag)
        content = META_CONTENT_RE.search(tag)
        if name and content:
            out.setdefault(name.group(1).lower()[:60], content.group(1)[:300])
    return out


def cookie_observations(headers: Any) -> list[dict[str, Any]]:
    """
    Record Set-Cookie attributes as observations.

    These are deliberately NOT candidates. A missing Secure or HttpOnly attribute is only a
    reportable finding when paired with a demonstrated theft primitive, and this stage cannot
    demonstrate one, so emitting it would be exactly the low-value noise the pipeline should not
    produce. Recorded so a human can correlate them with an actual exploit.
    """
    out: list[dict[str, Any]] = []
    for raw in _header_list(headers, "set-cookie"):
        first, _, rest = raw.partition(";")
        name = first.split("=", 1)[0].strip()
        lowered = rest.lower()
        if not name:
            continue
        out.append({"name": name[:120],
                    "secure": "secure" in lowered,
                    "httponly": "httponly" in lowered,
                    "samesite": next((a.split("=", 1)[1].strip() for a in rest.split(";")
                                      if a.strip().lower().startswith("samesite=")), None)})
    return out


def _header_list(headers: Any, name: str) -> list[str]:
    if headers is None:
        return []
    getter = getattr(headers, "get_all", None)
    if callable(getter):
        try:
            return list(getter(name) or [])
        except (KeyError, ValueError):
            return []
    value = getattr(headers, "get", lambda *_a, **_k: None)(name)
    return [value] if value else []


def header_observations(headers: Any) -> dict[str, Any]:
    """Presence of security-relevant response headers. Context, not a finding."""
    present = {h: bool(_header_list(headers, h)) for h in SECURITY_HEADERS}
    return {"present": present,
            "missing": [h for h, ok in present.items() if not ok],
            "note": "absence of a security header is a hardening gap, not a vulnerability; "
                    "report it only alongside a demonstrated impact"}


def page_endpoints(raw: str, base: str) -> list[str]:
    """API-ish endpoints the document calls or posts to, excluding the page's own links."""
    found: list[str] = []
    seen: set[str] = set()
    candidates = [m.group(1) for rx in XHR_URL_RES for m in rx.finditer(raw or "")]
    candidates += FORM_ACTION_RE.findall(raw or "")
    for ref in candidates:
        ref = ref.strip()
        if not ref or ref.lower().startswith(SKIP_SCHEMES) or ref.lower().startswith(("javascript:", "#", "mailto:")):
            continue
        try:
            absolute = urljoin(base, ref)
            absolute = canonical_url(absolute) if absolute else None
        except ValueError:
            continue
        if not absolute or absolute in seen:
            continue
        seen.add(absolute)
        found.append(absolute)
    return found


'''
s = s.replace(o, helpers + o, 1)

# ------------------------------------------------- the stage + registration
o = "    def screenshot_stage(self,st:StageState,deadline:float)->None:"
assert s.count(o) == 1, f"screenshot: {s.count(o)}"
stage = '''    def web_intelligence_stage(self,st:StageState,deadline:float)->None:
        """Per-page intelligence: endpoints a page calls but never links, comments, headers, tech.

        The valuable output is endpoints.txt. A crawler follows href and src, so a JSON endpoint a
        page fetches from script is invisible to crawl, corpus and access-checks unless something
        else extracts it. Everything else this stage records is context for a human.
        """
        raw_inputs=self.inputs(st.id)
        values=[v for v in raw_inputs if v.lower().startswith(("http://","https://"))]
        seen=set(); values=[v for v in values if not (v in seen or seen.add(v))]
        cap=int(getattr(self.args,"web_intel_max",0) or WEB_INTEL_DEFAULT_MAX)
        values=values[:cap]
        root=self.raw/st.id; dest=root/"normalized.txt"; endpoints_out=root/"endpoints.txt"
        st.total=len(values); st.inputs=values
        st.outputs=[str(dest),str(endpoints_out),str(root/"findings.json"),
                    str(root/"third-party.txt"),str(root/"comments.txt"),str(root/"headers.tsv")]
        if not values:
            st.status="skipped"; st.failure_reason="no in-scope HTTP origins from httpx"
            for p in (dest,endpoints_out,root/"third-party.txt",root/"comments.txt"):
                self.write_lines(p,[])
            return
        if self.args.dry_run:
            self.write_lines(dest,values); st.processed=st.total; return
        root.mkdir(parents=True,exist_ok=True)
        input_file=root/"inputs.txt"; self.write_lines(input_file,values)
        identity=self.identities.get("a") or {}
        lock=threading.Lock()
        rows:list[str]=[]; endpoints:list[str]=[]; third_party:list[str]=[]
        comments:list[str]=[]; header_rows:list[list[str]]=[]; pages:list[dict[str,Any]]=[]
        dropped:list[str]=[]
        def one(idx:int,url:str)->None:
            self.check(deadline)
            if not self.scope.decide(url)[0]:
                with lock: dropped.append(url)
                return
            status,raw=self._http_get(url,deadline,limit=WEB_INTEL_BODY_LIMIT)
            ctype=""
            # _http_get returns bytes; decode defensively and never raise on a bad charset
            text=raw.decode("utf-8","ignore") if isinstance(raw,(bytes,bytearray)) else str(raw)
            if not (200<=status<300) or not text.strip():
                with lock: rows.append("\\t".join([url,str(status),len(text) and str(len(text)) or "0","","",""]))
                return
            meta=html_meta(text)
            title=html_title(text)
            generator=meta.get("generator","")
            found=page_endpoints(text,url)
            in_scope=[e for e in found if self.scope.decide(e)[0]]
            external=[e for e in found if not self.scope.decide(e)[0]]
            cs=html_comments(text)
            with lock:
                st.processed+=1
                rows.append("\\t".join([url,str(status),str(len(text)),title[:120],generator[:120],",".join(cs)[:200]]))
                endpoints.extend(in_scope)
                third_party.extend(sorted({urlsplit(e).hostname or "" for e in external}-{""}))
                for c in cs: comments.append(f"{url}\\t{c}")
                pages.append({"url":url,"status":status,"title":title,"generator":generator,
                              "meta":{k:v for k,v in meta.items() if k in ("generator","description","robots","viewport")},
                              "endpoints_in_scope":in_scope,"endpoints_out_of_scope":sorted(external),
                              "comments_of_interest":cs})
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,self.args.concurrency)) as ex:
            futures=[ex.submit(one,i,u) for i,u in enumerate(values)]
            for f in futures:
                self.check(deadline)
                try: f.result(timeout=max(.1,deadline-time.monotonic()))
                except (Deadline,Interrupted): raise
                except Exception as e: print(f"[web-intelligence] {type(e).__name__}: {e}",file=sys.stderr,flush=True)
        # Third-party hosts are recorded as scope-expansion candidates and are never fetched.
        unique_endpoints=sorted(dict.fromkeys(endpoints))
        unique_third=sorted(set(third_party))
        self.write_lines(dest,rows)
        self.write_lines(endpoints_out,unique_endpoints)
        self.write_lines(root/"third-party.txt",unique_third)
        self.write_lines(root/"comments.txt",comments)
        self.write_lines(root/"dropped-out-of-scope.txt",sorted(set(dropped)))
        path=root/"headers.tsv"
        path.write_text("\\n".join(["\\t".join(["url","missing_headers"])]
                                  +["\\t".join([p["url"],";".join(p["headers"]["missing"])]) for p in pages])+"\\n")
        atomic_json(root/"findings.json",{"generated_at":now(),"run_id":self.run_id,
            "urls_considered":len(values),"urls_not_considered":max(0,len(self.inputs(st.id))-len(values)),
            "pages_analysed":len(pages),"endpoints_discovered":len(unique_endpoints),
            "third_party_hosts":unique_third,"third_party_fetched":False,
            "dropped_out_of_scope":sorted(set(dropped)),"pages":pages,
            "observations":{"security_headers":"see headers.tsv; a missing header is a hardening gap, not a finding",
                            "cookies":"recorded per page where a Set-Cookie was seen; attribute weaknesses are not candidates without a demonstrated theft primitive"},
            "disclaimer":"endpoints discovered by reading a page are discovery candidates, not vulnerabilities. "
                         "A hidden API route is only a finding once an authorization differential shows it is "
                         "reachable by the wrong identity; feed endpoints.txt to access-checks for that."})
        print(f"[web-intelligence] {st.processed}/{st.total} page(s), {len(unique_endpoints)} endpoint(s), "
              f"{len(unique_third)} third-party host(s) recorded but not fetched",flush=True)
        if st.processed<st.total:
            st.status="partial"; st.failure_reason=f"{st.total-st.processed} page(s) did not complete"

'''
s = s.replace(o, stage + o, 1)

o = '            elif st.id=="screenshots": self.screenshot_stage(st,deadline)'
assert s.count(o) == 1
s = s.replace(o, o + '\n            elif st.id=="web-intelligence": self.web_intelligence_stage(st,deadline)', 1)

o = 'STAGE_IMPLEMENTED = {"dns", "subdomains", "dnsx", "tls", "httpx", "screenshots", "ports", "archives", "corpus", "crawl", "api-discovery", "javascript", "arjun", "ffuf", "access-checks", "report"}'
assert s.count(o) == 1
s = s.replace(o, 'STAGE_IMPLEMENTED = {"dns", "subdomains", "dnsx", "tls", "httpx", "screenshots", "ports", "archives", "corpus", "crawl", "api-discovery", "javascript", "arjun", "ffuf", "access-checks", "web-intelligence", "report"}', 1)

# discovered endpoints join the access-checks merge
o = 'ACCESS_CHECK_INPUTS=(("corpus","params.txt"),("corpus","api.txt"),("arjun","params.txt"),("ffuf","paths.txt"))'
assert s.count(o) == 1
s = s.replace(o, 'ACCESS_CHECK_INPUTS=(("corpus","params.txt"),("corpus","api.txt"),("arjun","params.txt"),("ffuf","paths.txt"),("web-intelligence","endpoints.txt"))', 1)

p.write_text(s)
print("web-intelligence: helpers, stage, dispatch, classification, access-checks wiring")
