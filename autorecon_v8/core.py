from __future__ import annotations

import argparse
import concurrent.futures
import csv
import dataclasses
import datetime as dt
import hashlib
import http.client
import ipaddress
import math
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
from . import __version__
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

STATUSES = {"pending", "running", "completed", "partial", "failed", "skipped", "interrupted", "unimplemented"}
STAGE_IDS = ["dns", "subdomains", "dnsx", "tls", "httpx", "screenshots", "ports", "crawl", "archives", "corpus", "javascript", "api-discovery", "web-intelligence", "arjun", "ffuf", "access-checks", "report"]
ACTIVE = {"screenshots", "ports", "crawl", "javascript", "api-discovery", "web-intelligence", "arjun", "ffuf", "access-checks"}
DESCRIPTIONS = {
 "dns":"Collect DNS records", "subdomains":"Enumerate passive subdomains", "dnsx":"Resolve discovered names", "tls":"Collect TLS metadata", "httpx":"Identify HTTP origins", "screenshots":"Capture visual evidence", "ports":"Discover ports", "crawl":"Crawl live applications", "archives":"Collect archived URLs", "corpus":"Normalize and deduplicate URLs", "javascript":"Preserve and inspect JavaScript", "api-discovery":"Read-only API and identity probes", "web-intelligence":"Collect web metadata", "arjun":"Discover parameters", "nmap":"Validate exposed services", "ffuf":"Discover content", "access-checks":"Read-only access differentials", "report":"Publish reports"}
# Which stage reads which producer's artifact, at artifact granularity.
#
# This is the single source of truth for the data flow. DEPS is derived from it, and a consumer
# that ran without one of its inputs says so. It exists because the dependency metadata had
# drifted from reality: access-checks reads four producers, not one, so --list-stages and every
# report understated the graph, and a run started with --from access-checks produced a clean
# "0 candidates" with nothing indicating its inputs had never been generated. That is the worst
# shape a false negative can take - it looks like a result rather than an absence of one.
STAGE_INPUTS: dict[str, tuple[tuple[str, str], ...]] = {
    "screenshots": (("httpx", "normalized.txt"),),
    "ports": (("dnsx", "normalized.txt"),),
    "crawl": (("httpx", "normalized.txt"),),
    "corpus": (("crawl", "normalized.txt"), ("archives", "normalized.txt")),
    "javascript": (("corpus", "normalized.txt"),),
    "api-discovery": (("httpx", "normalized.txt"),),
    "web-intelligence": (("httpx", "normalized.txt"),),
    "arjun": (("corpus", "normalized.txt"),),
    "ffuf": (("corpus", "origins.txt"),),
    "access-checks": (("corpus", "params.txt"), ("corpus", "api.txt"),
                      ("arjun", "params.txt"), ("ffuf", "paths.txt"),
                      ("web-intelligence", "endpoints.txt")),
}


def missing_inputs(raw: Path, stage_id: str) -> list[str]:
    """Declared (producer, artifact) inputs for this stage that are absent or empty."""
    out: list[str] = []
    for producer, artifact in STAGE_INPUTS.get(stage_id, ()):
        path = raw / producer / artifact
        try:
            empty = not path.read_text(errors="replace").strip()
        except OSError:
            empty = True
        if empty:
            out.append(f"{producer}/{artifact}")
    return out


DEPS = {s: ([STAGE_IDS[i-1]] if i else []) for i,s in enumerate(STAGE_IDS)}
DEPS.update({"screenshots":["httpx"],"ports":["dnsx"],"crawl":["httpx"],"archives":["subdomains"],"corpus":["crawl","archives"],"javascript":["corpus"],"api-discovery":["httpx"],"web-intelligence":["httpx"],"arjun":["corpus"],"ffuf":["corpus"],"access-checks":["corpus"],"report":[]})
# Fold the declared artifact-level inputs into the dependency metadata. Positional neighbours are
# kept so the graph still reads as a pipeline, but a stage now also lists every producer it
# actually consumes. Sorted by pipeline position to keep --list-stages readable.
DEPS={s:sorted(set(v)|{producer for producer,_ in STAGE_INPUTS.get(s,())},
                key=lambda x:STAGE_IDS.index(x) if x in STAGE_IDS else 99) for s,v in DEPS.items()}
# Stages with a real implementation: a cmds entry in generic_stage, a method dispatched from
# execute(), or report generation. Every other stage is routed out of the generic fallback and
# reported as unimplemented instead of silently completing. Derived from STAGE_IDS so a newly
# added stage cannot escape classification.
# Stage removed from the graph but still named by artifacts written by older runs. Keeping the
# tombstone means a resume of such a run reports it as retired instead of raising KeyError.
DEPRECATED_STAGES = {"nmap": "folded into the ports stage; run it with --port-services"}
STAGE_IMPLEMENTED = {"dns", "subdomains", "dnsx", "tls", "httpx", "screenshots", "ports", "archives", "corpus", "crawl", "api-discovery", "javascript", "arjun", "ffuf", "access-checks", "web-intelligence", "report"}
UNIMPLEMENTED = tuple(s for s in STAGE_IDS if s not in STAGE_IMPLEMENTED)
assert not (STAGE_IMPLEMENTED & set(UNIMPLEMENTED)) and set(STAGE_IMPLEMENTED) | set(UNIMPLEMENTED) == set(STAGE_IDS), "stage classification does not partition STAGE_IDS"

PROFILES: dict[str,dict[str,Any]] = {
 "passive":{"concurrency":4,"rate_limit":5.0,"request_timeout":10.0,"tool_timeout":300.0,"stage_timeout":600.0,"max_hosts":500,"skip":sorted(ACTIVE)},
 "fast":{"concurrency":8,"rate_limit":20.0,"request_timeout":8.0,"tool_timeout":300.0,"stage_timeout":600.0,"max_hosts":200,"skip":["screenshots","ffuf"]},
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


def future_timeout(deadline:float,ceiling:float)->float:
    """Bounded wait for a worker future.

    self.global_deadline is float("inf") when --global-timeout is 0, which is the default, so
    deadline - now is infinite and Future.result(timeout=inf) raises OverflowError. That is raised
    on the collecting thread rather than inside the worker, and is swallowed by the per-future
    handler, so it masks whatever the worker was actually doing. Clamping keeps the wait meaningful
    and turns a masked failure into a real timeout.
    """
    try:
        remaining=deadline-time.monotonic()
    except (TypeError,OverflowError):
        return max(.1,ceiling)
    if not (remaining>0) or math.isinf(remaining) or math.isnan(remaining):
        return max(.1,ceiling)
    return max(.1,min(remaining,ceiling))


WEB_INTEL_DEFAULT_MAX = 40
WEB_INTEL_BODY_LIMIT = 1_000_000
KALI_SHARE_RESULTS = "/mnt/KaliShare/autorecon-results"
# Paths worth a human glance in a result file. Deliberately narrow: a result.txt that lists
# everything is the same as one that lists nothing.
HIGH_VALUE_URL_RE = re.compile(
    r"(\.git/HEAD|\.env|wp-config\.php|/admin/?|/phpmyadmin|/_cat/|/actuator|/__debug__"
    r"|/graphql|/graphiql|/openapi|/swagger|/api/|/v\d+/|/internal|/private|/backup)",
    re.IGNORECASE)
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
    re.compile(r"""\bfetch\s*\(\s*['"`]([^'"`\s]{2,300})""", re.I),
    re.compile(r"""\baxios\.(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`\s]{2,300})""", re.I),
    re.compile(r"""\burl\s*:\s*['"`]([^'"`\s]{2,300})""", re.I),
    re.compile(r"""\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"`]([^'"`\s]{2,300})""", re.I),
)
FORM_ACTION_RE = re.compile(r"""<form\b[^>]*?\baction\s*=\s*['"]([^'"]{1,300})['"]""", re.I | re.S)
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
META_RE = re.compile(r"""<meta\b[^>]*>""", re.I)
META_NAME_RE = re.compile(r"""\bname\s*=\s*['"]([^'"]+)['"]""", re.I)
META_CONTENT_RE = re.compile(r"""\bcontent\s*=\s*['"]([^'"]*)['"]""", re.I)
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

    # When anonymous and two distinct authenticated principals all receive byte-identical 2xx
    # bodies, the endpoint is serving a public representation. The two signals this would
    # otherwise raise - anon_matches_auth and identical_across_identities, both high severity -
    # are right when anonymous matches only identity A while A differs from B, because then
    # anonymous is being handed the privileged user's body. When all three match, raising them
    # buries a real IDOR under every shared config endpoint on the host, so this case is
    # classified and suppressed instead.
    if ("anon" in states and "a" in states and "b" in states
            and anon.get("status") == a.get("status") == b.get("status")
            and anon.get("sha256") and anon.get("sha256") == a.get("sha256") == b.get("sha256")):
        return [{"signal": "public_shared_resource", "severity": "info", "confidence": "n/a",
                 "false_positive_risk": "none, an identical anonymous response is expected for a public resource",
                 "detail": f"anonymous, identity-a and identity-b all returned {anon.get('status')} "
                           f"with the same {anon.get('length')}-byte body",
                 "verify": "no action; confirm the route is meant to be public, and if it is not then "
                           "an unauthenticated read is the finding to pursue"}]

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

ARJUN_DEFAULT_MAX = 15

FFUF_DEFAULT_MAX_HOSTS = 5
FFUF_DEFAULT_MAX_TIME = 120
FFUF_MAX_RECURSION_DEPTH = 3
FFUF_WORDLIST_CANDIDATES = (
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "config/sensitive-paths.txt",
)


def ffuf_wordlist(preferred: str | None = None) -> str | None:
    """First wordlist that actually exists, so ffuf is never handed a missing path."""
    if preferred:
        return preferred if Path(preferred).is_file() else None
    for candidate in FFUF_WORDLIST_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return None


def naabu_open_ports(payload: str) -> dict[str, list[int]]:
    """
    Parse naabu's -list output into {host: [port, ...]}.

    naabu prints one "host:port" per line and nothing else on this path, so a line that is not
    a host and a numeric port is skipped rather than coerced into a bogus target.
    """
    out: dict[str, list[int]] = {}
    for line in (payload or "").splitlines():
        token = line.strip()
        if not token or ":" not in token:
            continue
        host, _, port = token.rpartition(":")
        host = host.strip().strip("[]")
        if not host or not port.isdigit():
            continue
        number = int(port)
        if not 1 <= number <= 65535:
            continue
        out.setdefault(host, [])
        if number not in out[host]:
            out[host].append(number)
    return out


def nmap_services(payload: str) -> list[dict[str, Any]]:
    """
    Parse nmap -oX XML into per-port service records.

    XML is requested rather than the human-readable table because the table format is not
    stable across nmap builds, and a banner is only useful here if the port it came from is
    unambiguous.
    """
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(payload or "")
    except ET.ParseError:
        return []
    out: list[dict[str, Any]] = []
    for host in root.iter("host"):
        address = host.find("./address")
        ip = address.get("addr") if address is not None else None
        if not ip:
            continue
        for port_el in host.iter("port"):
            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else None
            if state != "open":
                continue
            number = port_el.get("portid")
            if not number or not number.isdigit():
                continue
            service_el = port_el.find("service")
            banner_el = port_el.find("./script/output")
            out.append({
                "host": ip,
                "port": int(number),
                "protocol": port_el.get("protocol") or "tcp",
                "service": service_el.get("name") if service_el is not None else None,
                "product": service_el.get("product") if service_el is not None else None,
                "version": service_el.get("version") if service_el is not None else None,
                "extrainfo": service_el.get("extrainfo") if service_el is not None else None,
                "banner": (banner_el.text or "").strip() if banner_el is not None else None,
            })
    return out


def ffuf_results(payload: str) -> list[dict[str, Any]]:
    """
    Parse ffuf's -of json into result records.

    ffuf writes {"results": [...]} on success and an empty object when nothing matched, and
    it can emit a bare array depending on build. All three are accepted; anything else is
    treated as no results rather than guessed at.
    """
    try:
        data = json.loads(payload or "{}")
    except (ValueError, TypeError):
        return []
    rows: Any = data
    if isinstance(data, dict):
        rows = data.get("results")
    if not isinstance(rows, list):
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        url = row.get("url")
        if not isinstance(url, str) or not url:
            continue
        out.append({"url": url, "status": row.get("status"), "length": row.get("length"),
                    "words": row.get("words"), "lines": row.get("lines"),
                    "content_type": row.get("content-type") or row.get("content_type"),
                    "redirect": row.get("redirectlocation") or row.get("redirect")})
    return out


def arjun_parse(payload: str) -> list[tuple[str, list[str], str]]:
    """
    Parse arjun's -o JSON into (base_url, parameter names, method) triples.

    arjun's JSON is {url: {"params": [...], "method": "GET", "headers": {...}}}.
    Entries without a usable parameter list are dropped, and a url that does not
    parse is skipped rather than guessed at.
    """
    try:
        data = json.loads(payload or "{}")
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[tuple[str, list[str], str]] = []
    for url, entry in data.items():
        if not isinstance(entry, dict):
            continue
        params = entry.get("params")
        if isinstance(params, str):
            params = [params]
        if not isinstance(params, list) or not params:
            continue
        names = [str(p).strip() for p in params if str(p).strip()]
        if not names:
            continue
        try:
            parsed = urlsplit(str(url))
        except ValueError:
            continue
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            continue
        out.append((str(url), names, str(entry.get("method") or "GET").upper()))
    return out


def query_param_names(url: str) -> set[str]:
    try:
        return {k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True) if k}
    except ValueError:
        return set()


def with_params(url: str, names: list[str]) -> str:
    """Rebuild a target URL carrying the discovered parameter names, order preserved."""
    try:
        u = urlsplit(url)
    except ValueError:
        return url
    existing = []
    try:
        existing = parse_qsl(u.query, keep_blank_values=True)
    except ValueError:
        existing = []
    have = {k for k, _ in existing}
    pairs = list(existing) + [(n, "1") for n in names if n not in have]
    return urlunsplit((u.scheme, u.netloc, u.path, urlencode(pairs), ""))


def now() -> str: return dt.datetime.now(dt.timezone.utc).isoformat()
def atomic_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); fd,tmp=tempfile.mkstemp(prefix=".state-",dir=path.parent)
    try:
        with os.fdopen(fd,"w") as f: json.dump(data,f,indent=2,sort_keys=True); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def atomic_text(path: Path, content: str) -> None:
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
            elif st.id=="arjun": self.arjun_stage(st,deadline)
            elif st.id=="ports": self.ports_stage(st,deadline)
            elif st.id=="ffuf": self.ffuf_stage(st,deadline)
            elif st.id=="screenshots": self.screenshot_stage(st,deadline)
            elif st.id=="web-intelligence": self.web_intelligence_stage(st,deadline)
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
        mapping={"dnsx":discovered+[self.host],"tls":hosts,"httpx":hosts,"screenshots":self.read("httpx"),"ports":hosts,"crawl":self.read("httpx"),"archives":discovered+[self.host],"corpus":self.read("crawl")+self.read("archives"),"javascript":self.read("corpus"),"api-discovery":self.read("httpx") or [self.seed],"web-intelligence":self.read("httpx"),"arjun":self.read("corpus"),"ffuf":self.read("httpx"),"access-checks":self.read("corpus")}
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
        tool={"dns":"dig","subdomains":"subfinder","dnsx":"dnsx","tls":"tlsx","httpx":"httpx","screenshots":"httpx","ports":"naabu","crawl":"katana","archives":"gau","javascript":"curl","web-intelligence":"curl","arjun":"arjun","ffuf":"ffuf","access-checks":"curl"}.get(st.id)
        if not values: st.status="skipped"; st.failure_reason="empty input"; return
        if tool and not shutil.which(tool): st.status="skipped"; st.failure_reason=f"missing external tool: {tool}"; return
        if self.args.dry_run: self.write_lines(dest,values); st.processed=st.total; return
        # Safe bounded adapters; raw stdout remains separate from normalized evidence.
        input_file=self.raw/st.id/"inputs.txt"
        self.write_lines(input_file,values)
        cmds={"dns":[tool,"+short",self.host],"subdomains":[tool,"-silent","-d",self.host],"dnsx":[tool,"-silent","-l",str(input_file)],"tls":[tool,"-silent","-l",str(input_file)],"httpx":[tool,"-silent","-l",str(input_file)],"archives":[tool,"--subs",self.host]}
        if st.id in cmds:
            raw=self.raw/st.id/"stdout.txt"; rc=self.command(st.id,[str(x) for x in cmds[st.id]],values[0],deadline,raw); st.exit_code=rc
            lines=raw.read_text(errors="replace").splitlines() if raw.exists() else []
            self.write_lines(dest,lines); st.processed=st.total
            if rc: st.status="partial" if lines else "failed"; st.failure_reason=f"tool exited {rc}"
        else:
            raise RuntimeError(f"stage {st.id!r} reached the generic fallback but is classified as implemented; add a cmds entry or a dispatch branch")
    def _http_get(self,url:str,deadline:float,limit:int=JS_MAX_BYTES,with_headers:bool=False):
        u=urlsplit(url)
        if not u.hostname: return 0,b""
        timeout=max(.1,min(self.args.request_timeout,deadline-time.monotonic()))
        conn=(http.client.HTTPSConnection if u.scheme=="https" else http.client.HTTPConnection)(u.hostname,u.port,timeout=timeout)
        try:
            conn.request("GET",urlunsplit(("", "",u.path or "/",u.query,"")),headers={"User-Agent":"AutoRecon/8","Accept":"*/*"})
            resp=conn.getresponse(); body=resp.read(limit)
            # Headers are opt-in: most callers only need the body, and returning a 3-tuple
            # unconditionally would break every existing call site.
            return (resp.status,body,resp.headers) if with_headers else (resp.status,body)
        except (OSError,http.client.HTTPException) as e:
            body=str(e).encode(); return (0,body,None) if with_headers else (0,body)
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
                try: f.result(timeout=future_timeout(deadline,self.args.tool_timeout))
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
        canonical:dict[str,str]={}; rejected:list[str]=[]
        for value in raw_inputs:
            self.check(deadline)
            if not isinstance(value,str): continue
            for candidate in (value.strip(), *value.split()):
                if not candidate: continue
                url=canonical_url(candidate)
                if not url: continue
                if not self.scope.decide(url)[0]:
                    # Record the refusal. crawl already writes dropped-out-of-scope.txt, and
                    # corpus filtering silently made the two stages disagree about what happened
                    # to a hostile URL that arrived through an archive feed rather than the crawler.
                    rejected.append(url); continue
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
        self.write_lines(root/"dropped-out-of-scope.txt",rejected)
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
    # Signals that describe correct behaviour: recorded, never raised as candidates.
    SUPPRESSED_SIGNALS={"auth_required","public_shared_resource"}
    # Read from the one table rather than restating it, so the dependency metadata and the
    # consumer can never disagree about what this stage reads.
    ACCESS_CHECK_INPUTS=STAGE_INPUTS["access-checks"]
    def access_check_targets(self)->tuple[list[str],list[str]]:
        """Targets from every partition this stage cares about, with provenance.

        Sources are read from their own stage directories and merged in memory, so no stage
        writes into another stage's artifacts and each producer stays independently
        auditable. corpus owns the canonical partitions; arjun contributes parameter names it
        discovered by probing, which corpus could not know before arjun ran.
        """
        ordered:list[str]=[]; seen=set(); provenance:list[str]=[]
        for stage,name in self.ACCESS_CHECK_INPUTS:
            values=[v for v in self.read_partition(name,stage) if v]
            if not values: continue
            provenance.append(f"{stage}/{name}")
            for url in values:
                if url not in seen: seen.add(url); ordered.append(url)
        return ordered,provenance
    def read_partition(self,name:str,stage:str="corpus")->list[str]:
        p=self.raw/stage/name
        return [ln.strip() for ln in p.read_text(errors="replace").splitlines() if ln.strip()] if p.exists() else []
    def access_checks_stage(self,st:StageState,deadline:float)->None:
        root=self.raw/st.id; dest=root/"normalized.txt"
        candidates,provenance=self.access_check_targets()
        if not candidates:
            # The absent-input check has to happen here too. This is precisely the path a
            # --from access-checks run takes, and it is the one where a missing producer is most
            # likely to be the whole explanation for an empty result.
            gap=missing_inputs(self.raw,st.id)
            st.status="skipped"
            st.failure_reason=("no parameterized or API targets in corpus"
                               + (f"; {len(gap)} declared input(s) absent or empty ({', '.join(gap)}); "
                                  "an empty result is not evidence of safety" if gap else ""))
            st.outputs=[str(dest)]
            self.write_lines(dest,[])
            # Written even on the skip path. A missing findings.json is indistinguishable from a
            # stage that crashed, and this is the run shape where an operator most needs to know
            # the inputs were never generated.
            atomic_json(root/"findings.json",{"generated_at":now(),"run_id":self.run_id,"target":self.seed,
                "skipped":True,"reason":st.failure_reason,
                "identity_states":[s for s in ("anon","a","b") if s=="anon" or self.identities.get(s)],
                "targets_considered":0,"targets_probed":0,"candidates":[],
                "declared_inputs_missing":gap,"inputs_complete":not gap,
                "suppressed":[],"candidates_flagged":[],
                "disclaimer":"no verdict was formed: the stage had no candidate targets. A zero-candidate "
                             "result is not evidence that the endpoint is safe, and is especially not evidence "
                             "of that when a declared input was never generated."})
            st.outputs.append(str(root/"findings.json"))
            if gap:
                print(f"[access-checks] WARNING: {len(gap)} declared input(s) absent or empty: "
                      f"{', '.join(gap)}; an empty result is not evidence of safety",
                      file=sys.stderr,flush=True)
            return
        cap=int(getattr(self.args,"access_checks_max",0) or ACCESS_CHECKS_DEFAULT_MAX)
        targets=candidates[:cap]; refused_scope=[u for u in candidates[cap:]]
        if not self.identities.get("a"):
            st.status="skipped"; st.failure_reason="no --cookie-file supplied, so there is no authenticated state to compare against"
            st.outputs=[str(dest)]; self.write_lines(dest,[]); return
        if self.args.dry_run:
            self.write_lines(dest,targets); st.processed=len(targets); st.outputs=[str(dest)]; return
        root.mkdir(parents=True,exist_ok=True)
        self.write_lines(root/"inputs.txt",targets)
        absent_inputs=missing_inputs(self.raw,st.id)
        if absent_inputs:
            # Recorded before any verdict, so a zero-candidate result is distinguishable from the
            # inputs never having been generated. A run resumed with --from access-checks, or one
            # where ffuf was skipped or capped to zero, would otherwise report a clean empty result.
            print(f"[access-checks] WARNING: {len(absent_inputs)} declared input(s) absent or empty: "
                  f"{', '.join(absent_inputs)}; a zero-candidate result is not evidence of safety",
                  file=sys.stderr,flush=True)
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
        suppressed=[f for f in findings if f["signal"] in self.SUPPRESSED_SIGNALS]
        real=[f for f in findings if f["signal"] not in self.SUPPRESSED_SIGNALS]
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
            "declared_inputs_missing":absent_inputs,"inputs_complete":not absent_inputs,
            "disclaimer":"candidates only; none of these is a validated vulnerability. Two authenticated identities returning an identical body is the precondition for IDOR, not proof. Confirm the identities are distinct accounts and that the object is meant to be private before reporting."})
        st.outputs=[str(dest),str(root/"anomalies.tsv"),str(root/"findings.json"),str(root/"suppressed.tsv"),str(root/"refused.txt")]
        print(f"[access-checks] {st.processed}/{len(targets)} target(s) probed across {len(states_available)} state(s): {len(real)} candidate(s), {len(suppressed)} suppressed, {len(set(refused))} refused out-of-scope",flush=True)
        notes=[]
        if absent_inputs:
            notes.append(f"{len(absent_inputs)} declared input(s) absent or empty ({', '.join(absent_inputs)}); "
                         "a zero-candidate result is not evidence of safety")
        if refused:
            notes.append(f"{len(set(refused))} out-of-scope target(s) or callback(s) refused")
        if notes: st.failure_reason="; ".join(notes)
        if not real: st.status="completed"
    def web_intelligence_stage(self,st:StageState,deadline:float)->None:
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
            status,raw,headers=self._http_get(url,deadline,limit=WEB_INTEL_BODY_LIMIT,with_headers=True)
            ctype=""
            # _http_get returns bytes; decode defensively and never raise on a bad charset
            text=raw.decode("utf-8","ignore") if isinstance(raw,(bytes,bytearray)) else str(raw)
            if not (200<=status<300) or not text.strip():
                with lock: rows.append("\t".join([url,str(status),len(text) and str(len(text)) or "0","","",""]))
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
                rows.append("\t".join([url,str(status),str(len(text)),title[:120],generator[:120],",".join(cs)[:200]]))
                endpoints.extend(in_scope)
                third_party.extend(sorted({urlsplit(e).hostname or "" for e in external}-{""}))
                for c in cs: comments.append(f"{url}\t{c}")
                pages.append({"url":url,"status":status,"title":title,"generator":generator,
                              "headers":header_observations(headers),
                              "cookies":cookie_observations(headers),
                              "meta":{k:v for k,v in meta.items() if k in ("generator","description","robots","viewport")},
                              "endpoints_in_scope":in_scope,"endpoints_out_of_scope":sorted(external),
                              "comments_of_interest":cs})
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,self.args.concurrency)) as ex:
            futures=[ex.submit(one,i,u) for i,u in enumerate(values)]
            for f in futures:
                self.check(deadline)
                try: f.result(timeout=future_timeout(deadline,self.args.tool_timeout))
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
        path.write_text("\n".join(["\t".join(["url","missing_headers"])]
                                  +["\t".join([p["url"],";".join(p["headers"]["missing"])]) for p in pages])+"\n")
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

    def screenshot_stage(self,st:StageState,deadline:float)->None:
        """Headless screenshot capture via httpx, which is how the other HTTP stages run.

        httpx needs a rendering engine for -screenshot. -system-chrome reuses a locally installed
        browser, which avoids shipping one; where no local browser exists httpx would try to
        download one mid-run, so -no-screenshot-full-page is used instead and the missing browser
        is reported rather than silently producing nothing.
        """
        values=[v for v in self.inputs(st.id) if v]; root=self.raw/st.id; dest=root/"normalized.txt"
        st.total=len(values); st.inputs=values; st.outputs=[str(dest)]
        if not values:
            st.status="skipped"; st.failure_reason="no live HTTP origins from httpx"; self.write_lines(dest,[]); return
        tool=shutil.which("httpx")
        if not tool:
            st.status="skipped"; st.failure_reason="missing external tool: httpx"; self.write_lines(dest,[]); return
        if self.args.dry_run:
            self.write_lines(dest,values); st.processed=st.total; return
        root.mkdir(parents=True,exist_ok=True)
        input_file=root/"inputs.txt"; self.write_lines(input_file,values)
        browser=next((c for c in ("chromium","chromium-browser","google-chrome","google-chrome-stable") if shutil.which(c)),None)
        shot_timeout=max(5,int(self.args.request_timeout))
        # -t is clamped: httpx defaults to 50 threads, and every one of them may drive a browser.
        cmd=[tool,"-silent","-l",str(input_file),"-screenshot","-screenshot-timeout",str(shot_timeout),
             "-t",str(max(1,min(self.args.concurrency,10))),"-nc"]
        if browser: cmd+=["-system-chrome"]
        else: cmd+=["-no-screenshot-full-page"]
        stdout=root/"stdout.txt"; rc=self.command(st.id,cmd,self.host,deadline,stdout,cwd=root); st.exit_code=rc
        shots=sorted(str(p) for p in root.rglob("*.png"))
        if not shots:
            st.status="skipped"; st.processed=0
            st.failure_reason="no screenshot captured"+("" if browser else " and no local chrome/chromium found for -system-chrome")
            if rc: st.failure_reason+=f"; httpx exited {rc}"
            self.write_lines(dest,[]); return
        self.write_lines(dest,shots); st.outputs=[str(dest)]+[str(p) for p in shots[:200]]
        st.processed=len(shots)
        print(f"[screenshots] captured {len(shots)} image(s) under {root}",flush=True)
        if rc: st.status="partial"; st.failure_reason=f"httpx exited {rc} but {len(shots)} image(s) were captured"

    def ports_stage(self,st:StageState,deadline:float)->None:
        hosts=self.inputs(st.id); st.total=len(hosts); st.inputs=[str(x) for x in hosts]
        root=self.raw/st.id; dest=root/"normalized.txt"; st.outputs=[str(dest)]
        if not hosts:
            st.status="skipped"; st.failure_reason="empty input"; self.write_lines(dest,[]); return
        naabu=shutil.which("naabu")
        if not naabu:
            st.status="skipped"; st.failure_reason="missing external tool: naabu"; self.write_lines(dest,[]); return
        if self.args.dry_run: self.write_lines(dest,hosts); st.processed=st.total; return
        root.mkdir(parents=True,exist_ok=True)
        input_file=root/"inputs.txt"; self.write_lines(input_file,hosts)
        raw=root/"stdout.txt"
        rc=self.command(st.id,[naabu,"-silent","-list",str(input_file)],hosts[0],deadline,raw); st.exit_code=rc
        opened=naabu_open_ports(raw.read_text(errors="replace") if raw.exists() else "")
        self.write_lines(dest,[f"{h}:{p}" for h,ports in opened.items() for p in ports])
        st.processed=st.total
        if rc and not opened:
            st.status="failed"; st.failure_reason=f"naabu exited {rc} and reported no open ports"; return
        if not getattr(self.args,"port_services",False):
            return
        if not opened:
            st.status="partial"; st.failure_reason="service detection requested but naabu confirmed no open port to scan"; return
        nmap=shutil.which("nmap")
        if not nmap:
            st.status="partial"; st.failure_reason="service detection requested but missing external tool: nmap"; return
        services=[]; refused=[]
        for host,ports in opened.items():
            self.check(deadline)
            if time.monotonic()>=deadline:
                st.status="partial"; st.failure_reason="stage deadline reached before every host was fingerprinted"; break
            if not self.scope.decide(host if "://" in host else f"http://{host}")[0]:
                refused.append(host); continue
            xml_out=root/(re.sub(r"[^A-Za-z0-9]+","_",host)+".nmap.xml")
            # -p is passed the exact ports naabu already confirmed, so nmap cannot widen the scan
            # on its own; -Pn skips host discovery because naabu proved the host is up; -T4 is the
            # fastest sane template; -sV/-sC are what the opt-in is for.
            cmd=[nmap,"-sV","-sC","-Pn","-T4","-p",",".join(str(x) for x in ports),"-oX",str(xml_out),host]
            rc2=self.command(f"{st.id}-services",cmd,host,deadline,root/"services-stdout.txt")
            if rc2: st.exit_code=rc2
            services.extend(nmap_services(xml_out.read_text(errors="replace") if xml_out.exists() else ""))
        if refused: self.write_lines(root/"refused.txt",refused)
        atomic_json(root/"services.json",{"generated_at":now(),"run_id":self.run_id,
            "nmap_flags":"-sV -sC -Pn -T4","scan_scope":"ports confirmed open by naabu only",
            "hosts_fingerprinted":len(opened)-len(refused),"hosts_refused":refused,"services":services,
            "disclaimer":"service and version banners are fingerprinting data, not vulnerabilities. A banner exposes software and version; a finding requires a demonstrated weakness in that version."})
        self.write_lines(root/"services.tsv",[f"{r['host']}\t{r['port']}\t{r['protocol']}\t{r['service']}\t{r['product']}\t{r['version']}" for r in services])
        st.outputs.append(str(root/"services.json"))
        print(f"[{st.id}] naabu: {len(opened)} host(s) with open ports; services: {len(services)} port record(s)",flush=True)
    def ffuf_stage(self,st:StageState,deadline:float)->None:
        origins=[u for u in self.read_partition("origins.txt") if u.lower().startswith(("http://","https://"))]
        seen=set(); hosts=[u for u in origins if not (u in seen or seen.add(u))]
        root=self.raw/st.id; dest=root/"normalized.txt"; paths_out=root/"paths.txt"
        cap=int(getattr(self.args,"ffuf_max_hosts",0) or FFUF_DEFAULT_MAX_HOSTS)
        hosts=hosts[:cap]; st.total=len(hosts); st.inputs=hosts
        if not hosts:
            st.status="skipped"; st.failure_reason="no in-scope HTTP origins from corpus"
            st.outputs=[str(dest)]; self.write_lines(dest,[]); self.write_lines(paths_out,[]); return
        tool=shutil.which("ffuf")
        if not tool:
            st.status="skipped"; st.failure_reason="missing external tool: ffuf"
            st.outputs=[str(dest)]; self.write_lines(dest,[]); self.write_lines(paths_out,[]); return
        wordlist=ffuf_wordlist(getattr(self.args,"ffuf_wordlist",None))
        if not wordlist:
            st.status="skipped"; st.failure_reason="no ffuf wordlist found; set --ffuf-wordlist"
            st.outputs=[str(dest)]; self.write_lines(dest,[]); self.write_lines(paths_out,[]); return
        if self.args.dry_run:
            self.write_lines(dest,hosts); st.processed=st.total; st.outputs=[str(dest)]; return
        root.mkdir(parents=True,exist_ok=True)
        # Bound every axis ffuf exposes. Its own defaults are unsafe for an unattended run:
        # 40 threads, no overall time limit, and a match list that includes 403 and 500.
        threads=max(1,min(int(getattr(self.args,"ffuf_threads",0) or 0) or self.args.concurrency,40))
        per_host=max(5,min(int(getattr(self.args,"ffuf_max_time",0) or FFUF_DEFAULT_MAX_TIME),FFUF_DEFAULT_MAX_TIME))
        delay=max(0.0,float(getattr(self.args,"ffuf_delay",0) or 0))
        recurse=bool(getattr(self.args,"ffuf_recursion",False))
        depth=max(1,min(int(getattr(self.args,"ffuf_recursion_depth",0) or 1),FFUF_MAX_RECURSION_DEPTH)) if recurse else 0
        identity=self.identities.get("a") or {}
        discovered:list[str]=[]; records:list[dict[str,Any]]=[]
        for origin in hosts:
            self.check(deadline)
            if time.monotonic()>=deadline:
                st.status="partial"; st.failure_reason="stage deadline reached before all origins were fuzzed"; break
            out_file=root/(re.sub(r"[^A-Za-z0-9]+","_",origin)+".json")
            cmd=[tool,"-u",origin.rstrip("/")+"/FUZZ","-w",wordlist,"-o",str(out_file),"-of","json",
                 "-noninteractive","-s","-ac","-mc","all","-fc","404",
                 "-t",str(threads),"-timeout",str(max(1,int(self.args.request_timeout))),
                 "-maxtime",str(per_host)]
            if delay: cmd+=["-p",str(delay)]
            if recurse:
                # ffuf requires -u to end in the FUZZ keyword for recursion to apply.
                cmd+=["-recursion","-recursion-depth",str(depth),"-recursion-strategy","default"]
            for k,v in identity.items(): cmd+=["-H",f"{k}: {v}"]
            rc=self.command(st.id,cmd,self.host,deadline,root/"stdout.txt",cwd=root); st.exit_code=rc
            payload=out_file.read_text(errors="replace") if out_file.exists() else ""
            rows=ffuf_results(payload)
            st.processed+=1
            if not rows and rc not in (0,1):
                print(f"[ffuf] {origin}: no parseable results (exit {rc})",flush=True)
            for row in rows:
                url=row["url"]
                if not self.scope.decide(url)[0]:
                    self.write_lines(root/"refused.txt",[f"{origin}\t{url}"]); continue
                discovered.append(url)
                records.append({**row,"origin":origin,"in_scope":True})
        unique=sorted(dict.fromkeys(discovered))
        self.write_lines(dest,[f"{r['origin']}\t{r['status']}\t{r['length']}\t{r['url']}" for r in records])
        self.write_lines(paths_out,unique)
        atomic_json(root/"findings.json",{"generated_at":now(),"run_id":self.run_id,"wordlist":wordlist,
            "origins_fuzzed":st.processed,"origins_skipped":max(0,st.total-st.processed),
            "threads":threads,"per_host_max_time":per_host,"recursion":recurse,"recursion_depth":depth,
            "match_codes":"all","filter_codes":"404","autocalibrated":True,"identity":sorted(identity) or ["anonymous"],
            "results":records,
            "disclaimer":"paths ffuf matched are discovery candidates, not vulnerabilities. A 200 on a hidden path is not authorization bypass; correlate with access-checks and confirm the path is not intended to be public."})
        st.outputs=[str(dest),str(paths_out),str(root/"findings.json")]
        print(f"[ffuf] {st.processed}/{st.total} origin(s), {len(unique)} unique path(s), {len(records)} match(es), t={threads} maxtime={per_host}s/host recursion={depth}",flush=True)
        if not unique and st.status=="pending" and not st.failure_reason:
            st.failure_reason="ffuf matched no path on any origin"

    def arjun_stage(self,st:StageState,deadline:float)->None:
        pool=[v for v in self.read("corpus") if v.lower().startswith(("http://","https://"))]
        seen=set(); targets=[v for v in pool if not (v in seen or seen.add(v))]
        root=self.raw/st.id; dest=root/"normalized.txt"
        cap=int(getattr(self.args,"arjun_max",0) or ARJUN_DEFAULT_MAX)
        targets=targets[:cap]
        st.total=len(targets); st.inputs=targets
        if not targets:
            st.status="skipped"; st.failure_reason="no HTTP URLs in corpus to probe"
            st.outputs=[str(dest)]; self.write_lines(dest,[]); return
        tool=shutil.which("arjun")
        if not tool:
            st.status="skipped"; st.failure_reason="missing external tool: arjun"
            st.outputs=[str(dest)]; self.write_lines(dest,[]); return
        if self.args.dry_run:
            self.write_lines(dest,targets); st.processed=st.total; st.outputs=[str(dest)]; return
        root.mkdir(parents=True,exist_ok=True)
        input_file=root/"inputs.txt"; self.write_lines(input_file,targets)
        json_out=root/"arjun.json"; text_out=root/"arjun.txt"
        headers_file=root/"arjun-headers.txt"
        identity=self.identities.get("a") or {}
        self.write_lines(headers_file,[f"{k}: {v}" for k,v in identity.items()])
        cmd=[tool,"-i",str(input_file),"-o",str(json_out),"-oT",str(text_out),"-q",
             "-t",str(max(1,min(self.args.concurrency,10))),
             "-T",str(max(1,int(self.args.request_timeout)))]
        delay=max(0.0,float(getattr(self.args,"arjun_delay",0) or 0))
        if delay: cmd+=["-d",str(delay)]
        if identity: cmd+=["--headers",str(headers_file)]
        if getattr(self.args,"arjun_passive",False): cmd+=["--passive"]
        if getattr(self.args,"arjun_wordlist",None): cmd+=["-w",str(self.args.arjun_wordlist)]
        rc=self.command(st.id,cmd,self.host,deadline,root/"stdout.txt",cwd=root); st.exit_code=rc
        payload=json_out.read_text(errors="replace") if json_out.exists() else ""
        triples=arjun_parse(payload)
        rows:list[str]=[]; inventory:list[dict[str,Any]]=[]; discovered:list[str]=[]
        enriched_params:list[str]=[]; enriched_api:list[str]=[]
        for url,names,method in triples:
            self.check(deadline)
            if not self.scope.decide(url)[0]: continue
            fresh=[n for n in names if n not in query_param_names(url)]
            rebuilt=with_params(url,names)
            if not self.scope.decide(rebuilt)[0]: continue
            discovered.append(rebuilt)
            rows.append("\t".join([url,method,",".join(names),str(len(fresh)),rebuilt]))
            inventory.append({"url":url,"method":method,"params":names,"new_params":fresh,"probed_url":rebuilt})
            if fresh:
                for name in fresh: enriched_params.append(f"{url}{'&' if '?' in url else '?'}{name}=1")
                if is_api_url(url): enriched_api.append(rebuilt)
        self.write_lines(dest,rows)
        atomic_json(root/"params.json",{"generated_at":now(),"run_id":self.run_id,"targets_probed":len(targets),
            "targets_with_params":len(inventory),"candidates_not_probed":max(0,len(self.read("corpus"))-len(targets)),
            "parameters":inventory,
            "disclaimer":"parameter names discovered by differential probing. A name here is not a vulnerability; combine it with the authorization differential in access-checks.","own_artifact_directory":"arjun","corpus_artifacts_modified":False,"consumed_by":["access-checks:corpus/params.txt","access-checks:corpus/api.txt","access-checks:arjun/params.txt"]})
        # arjun owns its artifacts. corpus/classify.tsv and corpus counts stay truthful because
        # nothing downstream of corpus is rewritten after the fact; consumers merge instead.
        self.write_lines(root/"params.txt",enriched_params)
        self.write_lines(root/"api.txt",enriched_api)
        st.outputs=[str(dest),str(root/"params.json"),str(root/"params.txt"),str(root/"api.txt")]
        st.processed=len(targets)
        new_names=sorted({n for item in inventory for n in item["new_params"]})
        print(f"[arjun] {len(targets)} target(s) probed, {len(inventory)} carried parameters, {len(new_names)} new name(s): {', '.join(new_names[:12]) or 'none'}",flush=True)
        if not inventory:
            if rc: st.status="partial"; st.failure_reason=f"arjun exited {rc} and reported no parameters"
            else: st.status="completed"; st.failure_reason="arjun reported no parameters on any target"
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
            for f in futures: self.check(deadline); f.result(timeout=future_timeout(deadline,self.args.tool_timeout))
        out=self.raw/st.id/"metrics.jsonl"; out.write_text("".join(json.dumps(x)+"\n" for x in results)); st.outputs=[str(out)]
    def write_result_txt(self,status:str,resume:str,stages:list[dict[str,Any]])->Path|None:
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
                c=line.split("\t")
                if len(c)>=5 and c[1]:
                    candidates.append(f"  [{c[2]}/{c[3]}] {c[1]}\n      {c[0]}\n      {c[5] if len(c)>5 else ''}".rstrip())
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
        content="\n".join(out)
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
        try:
            self.write_result_txt(report["status"],resume,stages)
        except OSError as e:
            # report.json and report.md are already on disk; a result.txt failure must not lose them.
            print(f"[report] result.txt could not be written: {e}",file=sys.stderr,flush=True)

def fmt(sec:float)->str:
    sec=max(0,int(sec)); return f"{sec//3600:02d}:{sec%3600//60:02d}:{sec%60:02d}"
def eta(done:int,total:int,elapsed:float)->str: return fmt((elapsed/max(done,1))*(total-done))
def csvset(values:list[str]|None)->set[str]: return {x for v in values or [] for x in v.split(",") if x}
def select_stages(args:argparse.Namespace)->tuple[set[str],dict[str,str]]:
    selected=set(STAGE_IDS); reasons={}
    only=csvset(args.only); skip=csvset(args.skip)|set(PROFILES[args.profile]["skip"])
    unknown=(only|skip|({args.restart_stage} if args.restart_stage else set()))-set(STAGE_IDS)
    # A name that used to be a stage is not an error: scripts and saved resumes still name it.
    # Report it as retired so the operator is told where the work went instead of hitting a
    # bare "unknown stage" that gives no clue.
    retired=sorted(unknown&set(DEPRECATED_STAGES))
    unknown-=set(DEPRECATED_STAGES)
    if unknown: raise ValueError("unknown stage(s): "+",".join(sorted(unknown)))
    for s in retired: reasons[s]=f"retired: {DEPRECATED_STAGES[s]}"
    if only: selected=only|{"report"}; reasons.update({s:"not selected by --only" for s in set(STAGE_IDS)-selected})
    if args.from_stage: selected-={s for s in STAGE_IDS[:STAGE_IDS.index(args.from_stage)]}; reasons.update({s:f"before --from {args.from_stage}" for s in set(STAGE_IDS)-selected})
    if args.until: selected-={s for s in STAGE_IDS[STAGE_IDS.index(args.until)+1:]}; reasons.update({s:f"after --until {args.until}" for s in set(STAGE_IDS)-selected})
    for s in skip: selected.discard(s); reasons.setdefault(s,"explicitly skipped" if s in csvset(args.skip) else f"disabled by {args.profile} profile")
    if args.passive:
        for s in ACTIVE:selected.discard(s);reasons[s]="disabled by --passive"
    return selected,reasons
