"""web-intelligence: the endpoints a page calls but never links.

The valuable output is endpoints.txt. crawl follows href and src, so a JSON endpoint a page fetches
from script is invisible to crawl, corpus and access-checks unless something extracts it. These
tests pin that extraction, and pin the two things that must NOT happen: a third-party host being
fetched, and a hardening observation being dressed up as a finding.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from autorecon_v8.cli import apply_profile_defaults, parser
from autorecon_v8.core import (
    Runner, cookie_observations, header_observations, html_comments, html_meta,
    html_title, page_endpoints,
)
from tests.two_identity_fixture import serve, serve_external


class ParserCases(unittest.TestCase):
    """The extraction helpers, offline. Malformed input is skipped, never coerced."""

    HTML = (
        '<html><head><title>  Spaced   Title </title>'
        '<meta name="generator" content="FixtureCMS 1.2"></head><body>'
        '<form action="/api/v1/session"></form>'
        '<script>fetch("/api/v1/a");axios.get("/api/v1/b");var url="/api/v1/c";</script>'
        '<!-- TODO: remove /api/v1/debug --><!-- nothing here --></body></html>'
    )

    def test_title_is_collapsed_and_trimmed(self):
        self.assertEqual(html_title(self.HTML), "Spaced Title")
        self.assertEqual(html_title(""), "")
        self.assertEqual(html_title("<html></html>"), "")

    def test_meta_generator_extracted(self):
        self.assertEqual(html_meta(self.HTML).get("generator"), "FixtureCMS 1.2")
        self.assertEqual(html_meta(""), {})

    def test_comments_are_filtered_not_dumped(self):
        found = html_comments(self.HTML)
        self.assertEqual(found, ["TODO: remove /api/v1/debug"])
        self.assertNotIn("nothing here", " ".join(found))

    def test_oversized_comment_is_dropped(self):
        self.assertEqual(html_comments("<!-- " + "x" * 5000 + " -->"), [])

    def test_endpoints_resolved_against_the_page_url(self):
        found = page_endpoints(self.HTML, "https://example.com/a/b")
        self.assertIn("https://example.com/api/v1/a", found)
        self.assertIn("https://example.com/api/v1/session", found)

    def test_non_fetchable_references_are_skipped(self):
        html = '<form action="javascript:void(0)"></form><a href="mailto:a@b.c">x</a>'
        self.assertEqual(page_endpoints(html, "https://example.com/"), [])

    def test_empty_input_is_safe_for_every_parser(self):
        self.assertEqual(page_endpoints("", "https://x/"), [])
        self.assertEqual(html_comments(""), [])
        self.assertEqual(html_meta(""), {})
        self.assertEqual(html_title(None or ""), "")


class _Headers:
    def __init__(self, mapping):
        self.mapping = mapping

    def get_all(self, name):
        return list(self.mapping.get(name.lower(), []))


class ObservationCases(unittest.TestCase):
    """Header and cookie data are context for a human, never candidates."""

    def test_missing_headers_are_listed_as_context(self):
        result = header_observations(_Headers({"content-security-policy": "default-src 'self'"}))
        self.assertIn("content-security-policy", result["present"])
        self.assertNotIn("content-security-policy", result["missing"])
        self.assertIn("strict-transport-security", result["missing"])
        self.assertIn("not a vulnerability", result["note"])

    def test_cookie_attributes_are_parsed(self):
        rows = cookie_observations(_Headers({"set-cookie": ["a=1; Path=/; Secure; HttpOnly; SameSite=Lax"]}))
        self.assertEqual(rows, [{"name": "a", "secure": True, "httponly": True, "samesite": "Lax"}])

    def test_missing_cookie_attributes_are_recorded_as_false(self):
        rows = cookie_observations(_Headers({"set-cookie": ["b=2; Path=/"]}))
        self.assertEqual(rows[0]["secure"], False)
        self.assertEqual(rows[0]["httponly"], False)
        self.assertIsNone(rows[0]["samesite"])

    def test_absent_headers_do_not_raise(self):
        self.assertEqual(cookie_observations(None), [])
        self.assertEqual(cookie_observations(_Headers({})), [])
        self.assertTrue(header_observations(None)["missing"])


class StageCases(unittest.TestCase):
    """The stage against a live page that hides its endpoints in script."""

    @classmethod
    def setUpClass(cls):
        cls.app = serve()
        cls.app.__enter__()
        cls.external = serve_external()
        cls.external.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.external.__exit__(None, None, None)
        cls.app.__exit__(None, None, None)

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.external.hits.clear()
        self.app.hits.clear()

    def run_stage(self, max_pages=0):
        argv = ["127.0.0.1", "--strict-scope", "--scope-include", "127.0.0.1",
                "--output-dir", self.tmp]
        if max_pages:
            argv += ["--web-intel-max", str(max_pages)]
        args = apply_profile_defaults(parser().parse_args(argv))
        subprocess.run([sys.executable, "-m", "autorecon_v8", "127.0.0.1", "--dry-run",
                        "--only", "httpx", "--output-dir", self.tmp], capture_output=True, timeout=180)
        args.resume = (Path(self.tmp) / "last").read_text().strip()
        run = Runner(args)
        raw = Path(run.raw)
        (raw / "httpx").mkdir(parents=True, exist_ok=True)
        (raw / "httpx" / "normalized.txt").write_text(self.app.origin + "/app\n")
        st = run.stages["web-intelligence"]
        st.status = "pending"
        run.web_intelligence_stage(st, run.global_deadline)
        root = raw / "web-intelligence"
        return st, root

    def test_discovers_endpoints_that_are_never_linked(self):
        st, root = self.run_stage()
        found = (root / "endpoints.txt").read_text().split()
        self.assertTrue(any("/api/v1/internal/accounts" in u for u in found),
                        f"a script-fetched endpoint was missed: {found}")
        self.assertTrue(any("/api/v1/internal/transfer" in u for u in found))
        self.assertTrue(any("/api/v1/session" in u for u in found), "the form action was missed")

    def test_third_party_host_is_recorded_but_never_fetched(self):
        st, root = self.run_stage()
        third = (root / "third-party.txt").read_text().split()
        self.assertIn("third-party.invalid", third, "the off-host reference was not recorded")
        self.assertNotIn("third-party.invalid", (root / "endpoints.txt").read_text(),
                         "an off-host reference leaked into the in-scope endpoint list")
        payload = json.loads((root / "findings.json").read_text())
        self.assertIs(payload["third_party_fetched"], False)
        self.assertEqual(self.external.hits, [],
                         f"the stage fetched a third-party host: {self.external.hits}")

    def test_discovery_is_not_presented_as_a_finding(self):
        st, root = self.run_stage()
        payload = json.loads((root / "findings.json").read_text())
        self.assertIn("not vulnerabilities", payload["disclaimer"])
        self.assertIn("not a finding", payload["observations"]["security_headers"])
        self.assertIn("theft primitive", payload["observations"]["cookies"])
        self.assertNotIn("candidates", payload)

    def test_comments_of_interest_are_captured(self):
        st, root = self.run_stage()
        body = (root / "comments.txt").read_text()
        self.assertIn("TODO", body)
        self.assertIn("/api/v1/internal/dump", body)
        self.assertNotIn("layout tweak", body)

    def test_page_metadata_is_recorded(self):
        st, root = self.run_stage()
        payload = json.loads((root / "findings.json").read_text())
        page = payload["pages"][0]
        self.assertEqual(page["title"], "Fixture App")
        self.assertEqual(page["generator"], "FixtureCMS 1.2")

    def test_discovered_endpoints_reach_access_checks(self):
        st, root = self.run_stage()
        targets, provenance = Runner(args=None, output_dir=self.tmp) if False else (None, None)
        # reuse the same run by rebuilding through the harness
        args = apply_profile_defaults(parser().parse_args(
            ["127.0.0.1", "--strict-scope", "--scope-include", "127.0.0.1", "--output-dir", self.tmp]))
        args.resume = (Path(self.tmp) / "last").read_text().strip()
        run = Runner(args)
        merged, prov = run.access_check_targets()
        self.assertIn("web-intelligence/endpoints.txt", prov,
                      "the stage's endpoints are not declared to the access-checks consumer")
        self.assertTrue(any("/api/v1/internal/accounts" in u for u in merged),
                        "a discovered endpoint did not reach access-checks")

    def test_absent_producer_directory_does_not_break_access_checks(self):
        args = apply_profile_defaults(parser().parse_args(
            ["127.0.0.1", "--strict-scope", "--scope-include", "127.0.0.1", "--output-dir", self.tmp]))
        subprocess.run([sys.executable, "-m", "autorecon_v8", "127.0.0.1", "--dry-run",
                        "--only", "httpx", "--output-dir", self.tmp], capture_output=True, timeout=180)
        args.resume = (Path(self.tmp) / "last").read_text().strip()
        run = Runner(args)
        self.assertFalse((Path(run.raw) / "web-intelligence").exists())
        merged, prov = run.access_check_targets()
        self.assertIsInstance(merged, list)
        self.assertNotIn("web-intelligence/endpoints.txt", prov)

    def test_no_pages_skips_with_a_reason(self):
        args = apply_profile_defaults(parser().parse_args(
            ["127.0.0.1", "--output-dir", self.tmp]))
        subprocess.run([sys.executable, "-m", "autorecon_v8", "127.0.0.1", "--dry-run",
                        "--only", "httpx", "--output-dir", self.tmp], capture_output=True, timeout=180)
        args.resume = (Path(self.tmp) / "last").read_text().strip()
        run = Runner(args)
        (Path(run.raw) / "httpx").mkdir(parents=True, exist_ok=True)
        (Path(run.raw) / "httpx" / "normalized.txt").write_text("")
        st = run.stages["web-intelligence"]
        st.status = "pending"
        run.web_intelligence_stage(st, run.global_deadline)
        self.assertEqual(st.status, "skipped")
        self.assertIn("no in-scope HTTP origins", st.failure_reason)

    def test_worker_failure_is_reported_not_masked(self):
        """
        Regression test for a masked failure.

        With --global-timeout at its default of 0 the global deadline is float("inf"), so an
        unbounded Future.result(timeout=inf) raises OverflowError on the collecting thread. That
        exception replaces whatever the worker raised, and the per-future handler prints it and
        moves on, so the stage reports success while the real error never reaches the log.
        """
        import contextlib
        import io
        import time
        real = Runner._http_get

        def boom(self, url, deadline, limit=0, with_headers=False):
            # The masking only happens when the worker is still running when result() is called.
            # If the future is already resolved, result() raises the worker's own error and the
            # bug never shows, which is why this sleeps: without it the test passes against the
            # broken code about as often as it fails.
            time.sleep(0.25)
            raise RuntimeError("worker boom")

        Runner._http_get = boom
        self.addCleanup(setattr, Runner, "_http_get", real)
        args = apply_profile_defaults(parser().parse_args(
            ["127.0.0.1", "--strict-scope", "--scope-include", "127.0.0.1", "--output-dir", self.tmp]))
        subprocess.run([sys.executable, "-m", "autorecon_v8", "127.0.0.1", "--dry-run",
                        "--only", "httpx", "--output-dir", self.tmp], capture_output=True, timeout=180)
        args.resume = (Path(self.tmp) / "last").read_text().strip()
        run = Runner(args)
        raw = Path(run.raw)
        (raw / "httpx").mkdir(parents=True, exist_ok=True)
        (raw / "httpx" / "normalized.txt").write_text(self.app.origin + "/app\n")
        st = run.stages["web-intelligence"]
        st.status = "pending"
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            # deliberately the infinite global deadline, which is what a caller gets by default
            run.web_intelligence_stage(st, run.global_deadline)
        logged = buf.getvalue()
        self.assertIn("worker boom", logged, f"the worker's real error was masked; stderr was: {logged!r}")
        self.assertNotIn("OverflowError", logged,
                         "an infinite deadline reached Future.result unbounded")

    def test_page_cap_is_recorded(self):
        st, root = self.run_stage(max_pages=1)
        payload = json.loads((root / "findings.json").read_text())
        self.assertEqual(payload["urls_considered"], 1)
        self.assertEqual(st.total, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
