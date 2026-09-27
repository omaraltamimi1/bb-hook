"""A live credential must never appear in a file under the run directory.

Redaction existed for the resume command and for nothing else. commands.jsonl writes the argv of
every subprocess as-is, and the stages that hold an authenticated session pass headers to httpx,
katana, ffuf and arjun - so the question is not whether a cookie could reach an artifact, it is
whether one already has.

Asserted the only way that settles it: run with a real credential file whose value is a
recognizable string, then walk every file in the run directory and assert that string is nowhere.
Not the report writers specifically, not a list of files believed to be safe - the whole tree, so a
new artifact that starts echoing the session fails here on its first commit.

The literal is distinctive on purpose. A test using a realistic-looking cookie value would pass
against a redaction that only matches a real cookie's shape.
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
from autorecon_v8.core import CookieJar, Runner, StageState

# Distinctive, and not shaped like a real session value, so a shape-based redactor cannot pass this
# by accident and a real one cannot be quietly narrowed to cookies.
SECRET = "RACCOON-SENTINEL-4f2b91d7-not-a-real-cookie"
SECRET_B = "RACCOON-SENTINEL-B-c3a8e510-second-identity"


def credential_file(directory: Path, name: str, value: str) -> Path:
    path = directory / name
    path.write_text(f"Cookie: sessionid={value}; Path=/\n")
    path.chmod(0o600)
    return path


def walk(root: Path):
    for path in root.rglob("*"):
        if path.is_file():
            yield path


def contents(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except (OSError, UnicodeDecodeError):
        return ""


class TestSecretsNeverReachArtifacts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(shutil.rmtree, "/dev/shm/autorecon-results", ignore_errors=True)
        self.jar = credential_file(Path(self.tmp), "cookies.txt", SECRET)
        self.jar_b = credential_file(Path(self.tmp), "cookies-b.txt", SECRET_B)

    def build(self, extra=(), identity_b=False):
        argv = ["127.0.0.1", "--output-dir", self.tmp, "--dry-run", "--cookie-file", str(self.jar),
                *extra]
        if identity_b:
            argv += ["--cookie-file-b", str(self.jar_b)]
        args = apply_profile_defaults(parser().parse_args(argv))
        run = Runner(args)
        run.command = lambda *a, **k: 0          # no subprocess: the argv is what gets recorded
        return run

    def leaks(self, needle: str):
        """Every file under the run directory that contains the literal, relative to the run dir."""
        return sorted(str(p.relative_to(self.run.work)) for p in walk(self.run.work)
                      if needle in contents(p))

    def test_the_credential_is_absent_from_every_artifact(self):
        self.run = self.build(identity_b=True)
        self.run.run()
        self.assertEqual(self.leaks(SECRET), [],
                         f"the session value reached: {self.leaks(SECRET)}")

    def test_a_command_log_cannot_hold_the_session(self):
        """commands.jsonl records the argv of every subprocess, and those argv carry headers.

        Drawn directly rather than by running a stage, so this asserts the logger rather than
        whichever stages happened to be selected.
        """
        self.run = self.build()
        # build() stubs command() out; this test is about the logger inside it, so put it back.
        self.run.command = Runner.command.__get__(self.run, Runner)
        for cmd in (["httpx", "-H", f"Cookie: sessionid={SECRET}", "-u", "https://example.com"],
                    ["arjun", "-H", f"Cookie: sessionid={SECRET}", "-u", "https://example.com"]):
            self.run.command("httpx", cmd, "https://example.com", 0.0, self.run.raw / "out.txt")
        rows = [json.loads(line) for line in self.run.command_log.read_text().splitlines() if line.strip()]
        self.assertEqual(len(rows), 2, "the command logger did not record both calls")
        for row in rows:
            self.assertNotIn(SECRET, json.dumps(row), f"a recorded argv held the session: {row}")

    def test_a_second_identity_is_protected_too(self):
        """A two-account run is the normal case, and both jars are live credentials."""
        self.run = self.build(identity_b=True)
        self.run.run()
        self.assertEqual(self.leaks(SECRET_B), [],
                         f"identity B's session value reached: {self.leaks(SECRET_B)}")

    def test_the_run_still_records_that_it_was_authenticated(self):
        """Redaction must not become "pretend it was anonymous".

        A report that hides the session also hides that there was one, and an operator reading it
        cannot tell an authenticated run from an anonymous one.
        """
        self.run = self.build()
        self.run.run()
        combined = contents(self.run.work / "report.json") + contents(self.run.work / "result.txt")
        self.assertNotIn(SECRET, combined)
        # The identity's fingerprint, not the word "auth". "authenticated: no" contains "auth" too,
        # so a substring check on the word is satisfied by the negative case it is meant to refute.
        self.assertIn(self.run.auth_state["a"]["credential_id"], combined,
                      "the run was authenticated but nothing in the artifacts says which identity "
                      "or that one was used at all")
        self.assertNotIn("anonymous run", combined,
                         "an authenticated run is labelled anonymous")
        self.assertIn("identities_distinct", contents(self.run.work / "report.json"),
                      "report.json does not record whether the two identities were actually distinct")

    def test_result_txt_labels_an_authenticated_run_as_authenticated(self):
        """report.json is machine-read. result.txt is the file a human opens, and it is the one
        that has to say the evidence came from a logged-in session."""
        self.run = self.build()
        self.run.run()
        text = contents(self.run.work / "result.txt")
        self.assertIn("identity A", text,
                      "result.txt does not name the identity the run was authenticated as")
        self.assertNotIn("anonymous run", text,
                         "an authenticated run is labelled anonymous in the human-facing artifact")

    def test_redaction_is_not_a_shape_match(self):
        """A redactor keyed to `session=` passes a test using a real-looking value and fails on
        whatever the next credential header is called. This asserts the literal is gone regardless
        of how it arrived, which is the property that survives contact with new headers."""
        self.run = self.build()
        self.run.command = lambda stage, cmd, target, deadline, output, cwd=None: (
            self.run.command_log.open("a").write(json.dumps(
                {"stage": stage, "command": [*cmd, f"-H", f"X-Api-Key: {SECRET}"]}) + "\n") or 0)
        self.run.run()
        self.assertEqual(self.leaks(SECRET), [],
                         f"a non-cookie secret shape reached an artifact: {self.leaks(SECRET)}")

    def test_the_credential_file_itself_is_not_copied_into_the_run(self):
        """The jar lives outside the run directory. A run directory that contains a live credential
        is a run directory that gets zipped, shared and uploaded to a triager."""
        self.run = self.build()
        self.run.run()
        copied = [str(p.relative_to(self.run.work)) for p in walk(self.run.work)
                  if p.name in ("cookies.txt", "cookies-b.txt")]
        self.assertEqual(copied, [], f"the credential file was copied into the run: {copied}")

    def test_every_artifact_is_walked(self):
        """Guards the guard: if walk() stopped finding files, the assertions above would pass
        without checking anything."""
        self.run = self.build()
        self.run.run()
        found = {str(p.relative_to(self.run.work)) for p in walk(self.run.work)}
        for expected in ("result.txt", "report.json", "run-state.json"):
            self.assertIn(expected, found, f"the walk did not reach {expected}")
        self.assertGreaterEqual(len(found), 8, f"the walk only reached {len(found)} files")


class TestResumeCommandRoundTrips(unittest.TestCase):
    """The resume line in report.json has to survive argparse, and has to carry the scope flags.

    A resume that drops --scope-exclude widens the target, dropping --profile changes the tool mix,
    and dropping --strict-scope removes the enforcement that was the point of the run. The operator
    pastes the line and the artifacts then describe a run that was never authorised.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(shutil.rmtree, "/dev/shm/autorecon-results", ignore_errors=True)

    def build(self, *extra):
        return Runner(apply_profile_defaults(parser().parse_args(
            ["127.0.0.1", "--output-dir", self.tmp, "--dry-run", *extra])))

    def round_trip(self, *extra):
        from autorecon_v8.core import STAGE_IDS, StageState
        run = self.build(*extra)
        run.command = lambda *a, **k: 0
        run.stages = {s: StageState(id=s, name=s, description="", dependencies=[]) for s in STAGE_IDS}
        run.generate_reports(0)
        line = json.loads((Path(run.work) / "report.json").read_text())["resume_command"]
        return line, line.split()

    def test_the_resume_line_parses(self):
        line, argv = self.round_trip("--rate-limit", "3.5")
        self.assertEqual(argv[0], "autorecon")
        self.assertIn("--resume", argv)
        self.assertIn("--rate-limit", argv)
        parser().parse_args(argv[1:])

    def test_scope_exclude_survives(self):
        line, argv = self.round_trip("--scope-exclude", "third-party.example.com")
        self.assertIn("third-party.example.com", line,
                      "the resume line drops --scope-exclude, which widens the target")
        args = parser().parse_args(argv[1:])
        self.assertIn("third-party.example.com", args.scope_exclude)

    def test_scope_include_survives(self):
        line, _ = self.round_trip("--scope-include", "only.example.com")
        self.assertIn("only.example.com", line)

    def test_strict_scope_survives(self):
        line, argv = self.round_trip("--strict-scope")
        self.assertIn("--strict-scope", line,
                      "the resume line drops --strict-scope, removing the enforcement")
        self.assertTrue(parser().parse_args(argv[1:]).strict_scope)

    def test_every_artifact_carries_the_same_resume_line(self):
        from autorecon_v8.core import STAGE_IDS, StageState
        run = self.build("--scope-exclude", "x.example.com")
        run.command = lambda *a, **k: 0
        run.stages = {s: StageState(id=s, name=s, description="", dependencies=[]) for s in STAGE_IDS}
        run.generate_reports(0)
        expected = json.loads((Path(run.work) / "report.json").read_text())["resume_command"]
        self.assertIn(expected, (Path(run.work) / "report.md").read_text())
        self.assertIn(expected, (Path(run.work) / "result.txt").read_text())

    def test_the_resume_line_never_carries_a_credential(self):
        jar = Path(self.tmp) / "c.txt"
        jar.write_text(f"Cookie: sessionid={SECRET}\n")
        line, _ = self.round_trip("--cookie-file", str(jar))
        self.assertNotIn(SECRET, line, "the resume line inlined a live session")
        self.assertIn(str(jar), line, "the credential is referenced by path instead")


class TestProgramHeaders(unittest.TestCase):
    """A program that asks for an identity header on unauthenticated requests.

    The HackerOne scope export for whatnot requires `X-HackerOne-Research: <username>` on requests
    that cannot carry a test account's alias. The header has to reach the wire, not just the args.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(shutil.rmtree, "/dev/shm/autorecon-results", ignore_errors=True)

    def build(self, *headers):
        return Runner(apply_profile_defaults(parser().parse_args(
            ["127.0.0.1", "--output-dir", self.tmp, "--dry-run", *headers])))

    def test_the_flag_is_repeatable(self):
        run = self.build("--header", "X-HackerOne-Research: omaraltamimi", "--header", "X-Other: 2")
        self.assertEqual(run.extra_headers,
                         {"X-HackerOne-Research": "omaraltamimi", "X-Other": "2"})

    def test_a_malformed_header_is_refused_rather_than_ignored(self):
        for bad in ("no-colon-here", ":empty-name", "  :v"):
            with self.assertRaises(ValueError, msg=f"{bad!r} was accepted"):
                self.build("--header", bad)

    def test_the_header_reaches_the_request(self):
        """Driven against a real listener, because the bug class is "it parsed but never went out"."""
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        seen = {}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.update({k: v for k, v in self.headers.items()})
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        port = server.server_address[1]

        run = self.build("--header", "X-HackerOne-Research: omaraltamimi")
        run._http_get(f"http://127.0.0.1:{port}/", __import__("time").monotonic() + 30)
        self.assertEqual(seen.get("X-HackerOne-Research"), "omaraltamimi",
                         "the identity header never reached the request")

    def test_a_value_containing_a_colon_is_kept_whole(self):
        run = self.build("--header", "X-Trace: a:b:c")
        self.assertEqual(run.extra_headers["X-Trace"], "a:b:c")


class TestProgramHeadersOnEveryRequestPath(unittest.TestCase):
    """The identity header has to go out on every path that touches the target, not just one.

    Three request sites exist: the page fetcher, the access-check prober, and the api-discovery
    probe. A header wired into only the first is a header that silently did not go out on the two
    requests an access-check candidate actually depends on.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(shutil.rmtree, "/dev/shm/autorecon-results", ignore_errors=True)
        self.seen = []

        class Handler(BaseHTTPRequestHandler):
            def _respond(self):
                self.server.seen.append(dict(self.headers.items()))
                body = b'{"openapi":"3.0.0"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = _respond

            def do_POST(self):
                self._respond()

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.seen = self.seen
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"

    def build(self, dry_run=True):
        # api_stage returns early under --dry-run without making a request, so the api-discovery
        # path has to run for real against the local listener to observe anything.
        argv = ["127.0.0.1", "--output-dir", self.tmp,
                "--header", "X-HackerOne-Research: omaraltamimi"]
        if dry_run:
            argv.append("--dry-run")
        run = Runner(apply_profile_defaults(parser().parse_args(argv)))
        run.seed = self.origin
        return run

    def deadline(self):
        import time
        return time.monotonic() + 30

    def test_the_page_fetcher_sends_it(self):
        self.build()._http_get(self.origin, self.deadline())
        self.assertEqual(self.seen[-1].get("X-HackerOne-Research"), "omaraltamimi")

    def test_the_access_check_prober_sends_it(self):
        run = self.build()
        run._probe(self.origin, {"Cookie": "sessionid=x"}, self.deadline())
        self.assertEqual(self.seen[-1].get("X-HackerOne-Research"), "omaraltamimi",
                         "the access-check prober dropped the identity header")

    def test_a_per_request_header_cannot_drop_the_identity_header(self):
        """Program headers are applied first, so a caller-supplied header cannot displace one."""
        run = self.build()
        run._probe(self.origin, {"X-HackerOne-Research": "someone-else"}, self.deadline())
        self.assertEqual(self.seen[-1].get("X-HackerOne-Research"), "omaraltamimi",
                         "a per-request header displaced the program's identity header")

    def test_the_api_discovery_probe_sends_it(self):
        run = self.build(dry_run=False)
        httpx = Path(run.raw) / "httpx" / "normalized.txt"
        httpx.parent.mkdir(parents=True, exist_ok=True)
        httpx.write_text(self.origin + "\n")
        st = StageState(id="api-discovery", name="api-discovery", description="", dependencies=[])
        run.stages = {"api-discovery": st}
        run.execute(st)
        self.assertTrue(self.seen, "api-discovery made no request, so nothing was checked")
        for headers in self.seen:
            self.assertEqual(headers.get("X-HackerOne-Research"), "omaraltamimi",
                             "an api-discovery request went out without the identity header")


if __name__ == "__main__":



    unittest.main(verbosity=2)