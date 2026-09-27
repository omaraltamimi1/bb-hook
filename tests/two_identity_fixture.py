"""Deterministic two-identity fixture for the access-checks differential.

The stage's whole value is comparing one URL across three authentication contexts. Argv tests
cannot touch that: a matrix regression that emitted zero candidates for a vulnerable endpoint
would pass every argument assertion in the suite. These fixtures pin the matrix itself.

Three contexts, distinguished only by a session cookie:

    anonymous  no Cookie header
    identity A session=A  admin, tenant A
    identity B session=B  non-admin, tenant B

Every body is a fixed literal. No timestamps, no request ids, no ordering that varies between
runs, because a digest comparison is only meaningful if the digests are stable.

The five routes are the five outcomes the matrix has to tell apart. Three of them are the
interesting failure modes; the other two are the cases a naive differential gets wrong by
flagging everything, which is why they are here at all.
"""

import http.server
import json
import threading
import urllib.parse


# A's record set. Identity B reaching this body is the vulnerability under test, so it is a
# fixed literal and not derived from the requester.
TENANT_A_RECORDS = {
    "tenant": "A",
    "records": [
        {"id": 101, "owner": "a@example.test", "email": "a@example.test", "plan": "enterprise-annual"},
        {"id": 102, "owner": "a@example.test", "email": "a@example.test", "plan": "enterprise-annual"},
        {"id": 103, "owner": "a@example.test", "email": "a@example.test", "plan": "enterprise-annual"},
    ],
}

PROFILE_A = {
    "user": "a@example.test",
    "tenant": "A",
    "display_name": "Identity A Administrator Account",
    "roles": ["owner", "admin", "billing"],
    "mfa_enabled": True,
}

# Deliberately a different length from PROFILE_A so the matrix sees a length differential and
# does not mistake a correct per-tenant response for a shared one.
PROFILE_B = {
    "user": "b@example.test",
    "tenant": "B",
    "display_name": "B",
    "roles": ["member"],
    "mfa_enabled": False,
}

PUBLIC_CONFIG = {
    "service": "fixture",
    "api_version": "v1",
    "features": {"access_checks": True, "corpus": True, "ffuf": True},
    "maintenance_window": "sunday 02:00 UTC",
}

# Two payloads with the SAME byte length and DIFFERENT content. A stage that compared response
# lengths instead of digests would call these identical and miss a same-length leak, so the
# fixture has to make that mistake observable.
EQUAL_LENGTH_A = {"order": 9001, "reference": "AAAAAAAAAAAA", "state": "settled"}
EQUAL_LENGTH_B = {"order": 9002, "reference": "BBBBBBBBBBBB", "state": "settled"}

# Served with the same bytes to anonymous, but with the status flipped to 401. This models
# status-only enforcement where the auth middleware sets the code and forgets the body, and it
# is the case that separates "identical bytes" from "identical response": the stage must not
# classify this as a public resource, because anonymous is not being served a 200.
STATUS_ONLY_BODY = {"tenant": "A", "records": ["r-1", "r-2", "r-3"], "seats": 12}

DASHBOARD_A = {
    "tenant": "A",
    "widgets": ["revenue", "churn", "usage", "audit", "billing"],
    "seats_used": 412,
    "seats_total": 500,
}


def _json(payload, status=200, headers=None):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return status, body, {"Content-Type": "application/json", **(headers or {})}


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    """The application under test. Routing is a table so each case is one readable entry."""

    protocol_version = "HTTP/1.1"
    server_version = "AutoReconFixture/1"

    def log_message(self, *args):
        pass  # the suite asserts on artifacts, not on stderr noise

    # -- identity -------------------------------------------------------
    def session(self):
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "session":
                return value
        return ""

    def _send(self, status, body, headers=None):
        self.send_response(status)
        for name, value in (headers or {"Content-Type": "application/json"}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        session = self.session()
        # Recorded so a test can assert which routes were actually requested, per identity.
        self.server.hits.append({"path": path, "session": session or "anon"})
        handler = {
            "/api/v1/tenants/A/records/101": self.records_101,
            "/api/v1/profile": self.profile,
            "/api/v1/config/public": self.public_config,
            "/api/v1/private/dashboard": self.dashboard,
            "/redirect": self.redirect,
            "/api/v1/orders/equal-length": self.equal_length,
            "/api/v1/status-only-enforcement": self.status_only_enforcement,
            "/app": self.app_page,
        }.get(path)
        if handler is None:
            status, body, headers = _json({"error": "not found"}, 404)
            return self._send(status, body, headers)
        handler(session, query)

    # -- case 1: identity_b_accesses_a_private -------------------------
    def records_101(self, session, _query):
        """
        The true positive. A and B are both authorised to *something* on this host, but the
        object belongs to tenant A, and B receives A's body. Anonymous is refused.

        B is answered 200 on purpose: a differential that only compared A to anonymous would
        never see this, which is the whole reason identity B exists.
        """
        if session not in ("A", "B"):
            return self._send(*_json({"error": "unauthorized"}, 401))
        # Both identities get the same tenant-A payload. That identical body across two
        # authenticated principals is the precondition for IDOR.
        return self._send(*_json(TENANT_A_RECORDS))

    # -- case 2: properly_scoped_multitenant ---------------------------
    def profile(self, session, _query):
        """Correct per-tenant behaviour: A sees A, B sees B, anonymous is refused."""
        if session == "A":
            return self._send(*_json(PROFILE_A))
        if session == "B":
            return self._send(*_json(PROFILE_B))
        return self._send(*_json({"error": "unauthorized"}, 401))

    # -- case 3: public_resource ---------------------------------------
    def public_config(self, session, _query):
        """Identical body for every context including anonymous. Not a finding."""
        return self._send(*_json(PUBLIC_CONFIG))

    # -- case 4: auth_enforced -----------------------------------------
    def dashboard(self, session, _query):
        """
        Correct enforcement with a deliberate split: A is an admin so gets 200, B is a member so
        gets 403, anonymous gets 401.

        B being 403 matters. If B also received 200 the stage would emit an A-versus-B signal and
        this case would stop isolating the anonymous-versus-authenticated suppression.
        """
        if session == "A":
            return self._send(*_json(DASHBOARD_A))
        if session == "B":
            return self._send(*_json({"error": "forbidden"}, 403))
        return self._send(*_json({"error": "unauthorized"}, 401))

    # -- discriminating case: same length, different content -----------
    def equal_length(self, session, _query):
        """A and B get different payloads that happen to be the same byte length."""
        if session == "A":
            return self._send(*_json(EQUAL_LENGTH_A))
        if session == "B":
            return self._send(*_json(EQUAL_LENGTH_B))
        return self._send(*_json({"error": "unauthorized"}, 401))

    # -- discriminating case: same bytes, different status -------------
    def status_only_enforcement(self, session, _query):
        """
        The same body bytes are returned to every caller, but anonymous gets 401.

        A digest-only comparison would call this a public resource. It is not: the status differs,
        so anonymous is not being served the authenticated response, and the identical bytes are
        themselves the finding.
        """
        if session in ("A", "B"):
            return self._send(*_json(STATUS_ONLY_BODY))
        return self._send(*_json(STATUS_ONLY_BODY, 401))

    def app_page(self, _session, _query):
        """An HTML page whose endpoints are only discoverable by reading it."""
        body = APP_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # A cookie with no Secure and no HttpOnly. Recorded as an observation only: an attribute
        # weakness is not reportable without a demonstrated theft primitive.
        self.send_header("Set-Cookie", "session=fixture; Path=/")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- case 5: untrusted_redirect ------------------------------------
    def redirect(self, _session, query):
        """
        Returns a redirect to whatever the caller asked for, which is the server-side request
        forgery primitive. The stage must refuse the callback rather than probe it.
        """
        target = (query.get("to") or [""])[0]
        if not target:
            return self._send(*_json({"error": "missing to"}, 400))
        return self._send(302, b"", {"Location": target})


# A page whose interesting content is only reachable by reading it: the endpoints below are
# fetched from script or posted to, never linked, so a crawler following href/src misses all of
# them. One points off-host, which the stage must record without ever fetching.
APP_HTML = """<!doctype html><html><head><title>Fixture App</title>
<meta name="generator" content="FixtureCMS 1.2">
<meta name="description" content="fixture application"></head>
<body>
<form action="/api/v1/session" method="post"><input name="user"></form>
<script>
fetch('/api/v1/internal/accounts');
fetch('http://third-party.invalid/collect');
axios.post("/api/v1/internal/transfer");
</script>
<!-- TODO: debug endpoint /api/v1/internal/dump must be removed before release -->
<!-- layout tweak -->
</body></html>"""


class ExternalServer(http.server.BaseHTTPRequestHandler):
    """Stands in for a third-party host. Must never be touched."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        # Any request here is a scope failure. Recording it makes the claim checkable rather
        # than an assertion about code that was never run.
        self.server.hits.append(self.path)
        body = b'{"internal":"you should never see this"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _Server:
    def __init__(self, handler):
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_port
        self.hits = []
        self.httpd.hits = self.hits
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        return False

    @property
    def origin(self):
        return f"http://127.0.0.1:{self.port}"


def serve():
    """Context manager yielding the fixture application server."""
    return _Server(FixtureHandler)


def serve_external():
    """Context manager yielding the must-not-be-touched server."""
    return _Server(ExternalHandlerProxy)


class ExternalHandlerProxy(ExternalServer):
    pass
