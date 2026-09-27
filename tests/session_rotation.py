"""A session that rotates mid-run must be visible in the artifacts, not just in memory.

The cookie jar used to be read from --cookie-file once at startup and never touched again. A target
that reissues its session partway through - which is what session rotation is - silently downgraded
the rest of the run to anonymous, and nothing recorded that it had happened. A report built from
half-anonymous evidence is indistinguishable from a fully authenticated one, and that is precisely
the distinction an access-check candidate has to be able to rely on.

Values are never asserted on. They live in a 0600 file under the run directory and nowhere else; what
the artifacts carry is cookie names, a hash, and the rotation count.
"""
import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from autorecon_v8.cli import apply_profile_defaults, parser
from autorecon_v8.core import CookieJar, Runner

INITIAL = "Cookie: sessionid=original-value; csrftoken=abc\n"
ROTATED = "rotated-value"
SECRET = "RACCOON-JAR-SENTINEL-d41f8a2c"


class TestCookieJarMechanics(unittest.TestCase):
    def setUp(self):
        self.jar = CookieJar()
        self.jar.seed("example.com", {"Cookie": "sessionid=original; csrftoken=abc"})

    def test_the_seeded_session_is_sent(self):
        self.assertIn("sessionid=original", self.jar.header_for("example.com"))

    def test_hosts_do_not_share_a_session(self):
        self.jar.seed("other.com", {"Cookie": "sessionid=different"})
        self.assertIn("sessionid=original", self.jar.header_for("example.com"))
        self.assertNotIn("sessionid=original", self.jar.header_for("other.com"))

    def test_a_host_with_no_session_gets_no_cookie_header(self):
        self.assertEqual(self.jar.header_for("unknown.com"), "",
                         "a cookie was invented for a host that was never seeded")

    def test_absorbing_a_set_cookie_replaces_the_value(self):
        self.jar.absorb("example.com", [f"sessionid={ROTATED}; Path=/; HttpOnly"])
        self.assertIn(f"sessionid={ROTATED}", self.jar.header_for("example.com"))
        self.assertNotIn("original", self.jar.header_for("example.com"))

    def test_rotation_is_counted(self):
        self.assertEqual(self.jar.rotations, 0)
        self.jar.absorb("example.com", [f"sessionid={ROTATED}"])
        self.assertEqual(self.jar.rotations, 1, "a reissued cookie was not counted as a rotation")
        self.jar.absorb("example.com", [f"sessionid={ROTATED}"])
        self.assertEqual(self.jar.rotations, 1, "an unchanged cookie was counted as a rotation")

    def test_the_reported_state_holds_names_and_a_hash_but_no_values(self):
        self.jar.absorb("example.com", [f"sessionid={SECRET}"])
        blob = json.dumps(self.jar.state())
        self.assertNotIn(SECRET, blob, "the jar's reported state contains a cookie value")
        self.assertNotIn("original", blob, "the jar's reported state contains a cookie value")
        self.assertIn("sessionid", blob, "the jar's reported state does not name the cookies")
        self.assertEqual(self.jar.state()["rotations"], 1,
                         "the reported state does not carry the rotation count")

    def test_hosts_are_keyed_independently_not_shared(self):
        """A single global slot looks identical to a per-host jar until two hosts are used."""
        self.jar.seed("other.com", {"Cookie": "sessionid=other"})
        self.jar.absorb("other.com", ["sessionid=other-rotated"])
        self.assertIn("sessionid=original", self.jar.header_for("example.com"),
                      "another host's rotation overwrote this host's session")
        self.assertIn("sessionid=other-rotated", self.jar.header_for("other.com"))

    def test_absorbing_nothing_changes_nothing(self):
        before = self.jar.header_for("example.com")
        self.jar.absorb("example.com", [])
        self.assertEqual(self.jar.header_for("example.com"), before)

    def test_a_malformed_set_cookie_does_not_corrupt_the_jar(self):
        self.jar.absorb("example.com", ["", "=novalue", "novalue"])
        self.assertIn("sessionid=original", self.jar.header_for("example.com"),
                      "a malformed Set-Cookie destroyed a working session")

    def test_concurrent_absorbs_do_not_lose_cookies(self):
        jar = CookieJar()
        jar.seed("example.com", {"Cookie": "sessionid=original"})

        def worker(n):
            for i in range(50):
                jar.absorb("example.com", [f"k{n}x{i}=v{i}"])
        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        names = jar.names("example.com")
        for n in range(4):
            for i in (0, 49):
                self.assertIn(f"k{n}x{i}", names, f"a concurrent write lost k{n}x{i}")


class TestRotationIsVisible(unittest.TestCase):
    """Driven against a real local server, because the bug is about what a live response does."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(shutil.rmtree, "/dev/shm/autorecon-results", ignore_errors=True)
        self.jar_file = Path(self.tmp) / "cookies.txt"
        self.jar_file.write_text(INITIAL)
        self.jar_file.chmod(0o600)

    def serve(self, reissue: bool):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"ok":true}'
                self.send_response(200)
                if reissue:
                    self.send_header("Set-Cookie", f"sessionid={SECRET}; Path=/; HttpOnly")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def runner(self, port):
        run = Runner(apply_profile_defaults(parser().parse_args(
            ["127.0.0.1", "--output-dir", self.tmp, "--cookie-file", str(self.jar_file)])))
        run.seed = f"http://127.0.0.1:{port}"
        return run

    def deadline(self):
        import time
        return time.monotonic() + 30

    def test_a_reissued_cookie_is_adopted(self):
        port = self.serve(reissue=True)
        run = self.runner(port)
        status, _ = run._http_get(run.seed, self.deadline())
        self.assertEqual(status, 200)
        self.assertIn(SECRET, run.jar.header_for("127.0.0.1"),
                      "the reissued session was not adopted")
        self.assertEqual(run.jar.rotations, 1, "the rotation was not counted")

    def test_the_rotation_survives_into_the_persisted_jar(self):
        port = self.serve(reissue=True)
        run = self.runner(port)
        run._http_get(run.seed, self.deadline())
        path = run.persist_jar()
        self.assertTrue(path and path.exists(), "the live session was not written for a resume")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600,
                         "a file holding live credentials is not 0600")
        self.assertIn(SECRET, path.read_text(), "the resume jar does not carry the new session")

    def test_the_rotation_is_reported_without_the_value(self):
        port = self.serve(reissue=True)
        run = self.runner(port)
        run._http_get(run.seed, self.deadline())
        summary = run.auth_summary()
        self.assertIn("rotated", summary, f"a rotated session is not reported: {summary!r}")
        self.assertNotIn(SECRET, summary, "the session value was printed")
        self.assertNotIn("original", summary, "the session value was printed")

    def test_a_stable_session_is_reported_as_stable(self):
        port = self.serve(reissue=False)
        run = self.runner(port)
        run._http_get(run.seed, self.deadline())
        summary = run.auth_summary()
        self.assertNotIn("rotated", summary, f"a session that never moved was reported as moved: {summary!r}")

    def test_report_json_records_the_rotation_and_no_value(self):
        from autorecon_v8.core import STAGE_IDS, StageState
        port = self.serve(reissue=True)
        run = self.runner(port)
        run._http_get(run.seed, self.deadline())
        run.stages = {s: StageState(id=s, name=s, description="", dependencies=[]) for s in STAGE_IDS}
        run.generate_reports(0)
        blob = (Path(run.work) / "report.json").read_text()
        self.assertIn("rotations", blob, "report.json does not record whether the session moved")
        self.assertNotIn(SECRET, blob, "report.json holds a live cookie value")
        self.assertNotIn("original-value", blob, "report.json holds a live cookie value")

    def test_result_txt_warns_that_the_run_spans_two_sessions(self):
        from autorecon_v8.core import STAGE_IDS, StageState
        port = self.serve(reissue=True)
        run = self.runner(port)
        run._http_get(run.seed, self.deadline())
        run.stages = {s: StageState(id=s, name=s, description="", dependencies=[]) for s in STAGE_IDS}
        run.generate_reports(0)
        text = (Path(run.work) / "result.txt").read_text()
        self.assertIn("rotated", text,
                      "result.txt does not say the evidence spans more than one session")
        self.assertNotIn(SECRET, text, "result.txt holds a live cookie value")


if __name__ == "__main__":
    unittest.main(verbosity=2)
