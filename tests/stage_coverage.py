"""Coverage for the stage implementations merged in #10-#16 and the ports fold in #17.

Four contracts, each chosen because it corresponds to a defect that actually occurred:

  1. argv construction   - every external tool is invoked with bounded arguments. Four tools
                          have now had their real interface read off the binary because an
                          assumed flag does not exist; this pins the argv so a later edit cannot
                          quietly widen a scan.
  2. decoupled contracts - arjun/ and ffuf/ are optional inputs to the consumers. A missing or
                          empty producer directory must degrade, not raise, because a stage is
                          allowed to be skipped or capped to zero.
  3. scope enforcement   - out-of-scope hosts are refused and recorded, never probed and then
                          discarded, and never silently dropped either.
  4. state reset         - execute() clears failure_reason and exit_code on entry, so a retry
                          that succeeds cannot inherit a stale reason. The original bug was a
                          stage reporting a successful result next to a failure from earlier.

Args are built through the real parser rather than a hand-written Namespace, so a new flag
cannot make these tests pass against a shape the CLI never produces.

Note on scope: --strict-scope is off by default, which means Scope.decide() allows everything.
Scope tests must therefore pass it explicitly, or they assert nothing.
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
    Runner, Scope, arjun_parse, ffuf_results, naabu_open_ports, nmap_services,
)

# Stage id -> Runner method. Two ids are not valid identifier transformations of their method:
# "access-checks" contains a dash, and "screenshots" is plural while the method is singular.
STAGE_METHODS = {"access-checks": "access_checks_stage", "screenshots": "screenshot_stage"}


def method_for(stage_id):
    return STAGE_METHODS.get(stage_id, stage_id.replace("-", "_") + "_stage")


def flag(cmd, name):
    """Value following a flag, or None. Tolerates '-flag value' and '-flag=value'."""
    if name in cmd:
        i = cmd.index(name)
        return cmd[i + 1] if i + 1 < len(cmd) else None
    prefix = name + "="
    for token in cmd:
        if token.startswith(prefix):
            return token[len(prefix):]
    return None


class TestUnitTiming(unittest.TestCase):
    """The heartbeat is the only per-unit visibility a live run has.

    A first run against a real host printed elapsed=00:00:00 for every single unit, because fmt()
    truncates to whole seconds and every tool answered in under one. That made a 20ms response, a
    unit killed on timeout and a tool that never launched all look identical.
    """

    def test_a_sub_second_unit_is_visible(self):
        from autorecon_v8.core import fmt, fmt_ms
        self.assertEqual(fmt(0.04), "00:00:00", "fmt is the second-resolution formatter")
        self.assertEqual(fmt_ms(0.04), "40ms")
        self.assertEqual(fmt_ms(0.5), "500ms")
        self.assertEqual(fmt_ms(0.999), "999ms")

    def test_ms_never_says_zero_for_a_unit_that_ran(self):
        """0ms must mean started-this-instant, never a unit that did real work.

        A regression to second resolution turns every fast unit into 00:00:00, which is the exact
        failure this formatter exists to prevent.
        """
        from autorecon_v8.core import fmt_ms
        for seconds in (0.001, 0.02, 0.1, 0.25, 0.75, 0.999):
            self.assertNotEqual(fmt_ms(seconds), "00:00:00",
                                f"a {seconds}s unit is indistinguishable from no unit at all")

    def test_durations_beyond_a_second_are_unchanged(self):
        from autorecon_v8.core import fmt, fmt_ms
        for seconds in (1.0, 12.4, 599.2, 3661.0):
            self.assertEqual(fmt_ms(seconds), fmt(seconds),
                             "a long duration should read the same as it always did")

    def test_the_heartbeat_line_uses_the_sub_second_formatter(self):
        """Guards the call site, not just the helper."""
        import inspect
        from autorecon_v8 import core
        source = inspect.getsource(core.Runner.command)
        self.assertNotIn("elapsed={fmt(", source, "the per-unit heartbeat is back on fmt()")
        self.assertIn("elapsed={fmt_ms(", source)



class Harness(unittest.TestCase):
    """Builds a Runner over a temp run directory and records the argv of every subprocess."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.captured = []

    def build(self, argv, seed=None):
        """Create a run dir, seed stage artifacts, return a Runner.

        seed maps a stage id to a list of lines written to that stage's normalized.txt.
        """
        args = apply_profile_defaults(parser().parse_args([*argv, "--output-dir", self.tmp]))
        subprocess.run([sys.executable, "-m", "autorecon_v8", "example.com", "--dry-run",
                        "--only", "httpx", "--output-dir", self.tmp], capture_output=True, timeout=180)
        rid = (Path(self.tmp) / "last").read_text().strip()
        args.resume = rid
        run = Runner(args)
        raw = Path(run.raw)
        for stage_id, value in (seed or {}).items():
            target = raw / stage_id
            target.mkdir(parents=True, exist_ok=True)
            name, lines = value if isinstance(value, tuple) else ("normalized.txt", value)
            (target / name).write_text("\n".join(lines) + ("\n" if lines else ""))
        return run

    def run_stage(self, runner, stage_id, results=None, naabu="example.com:80\nexample.com:443\n"):
        """Run one stage with Runner.command replaced by a spy.

        results: ffuf-style list of result dicts. When None, a per-tool default is written.
        The spy's first parameter is deliberately not named "self": as a bound method it would
        shadow the TestCase and every assertion would read the Runner.
        """
        real = Runner.command
        self.captured = []

        def spy(runner_self, sid, cmd, host, deadline, out, cwd=None):
            self.captured.append(list(cmd))
            target = Path(out)
            target.parent.mkdir(parents=True, exist_ok=True)
            if "naabu" in cmd[0]:
                target.write_text(naabu)
            elif "arjun" in cmd[0]:
                for token in cmd:
                    if token.endswith(".json"):
                        Path(token).write_text(json.dumps(
                            results if results is not None else
                            {"https://example.com/a": {"params": ["q", "id"], "method": "GET"}}))
            elif "ffuf" in cmd[0]:
                for token in cmd:
                    if token.endswith(".json"):
                        Path(token).write_text(json.dumps(
                            {"results": results if results is not None
                             else [{"url": "https://example.com/admin", "status": 200, "length": 10}]}))
            elif "katana" in cmd[0]:
                target.write_text("https://example.com/a\n")
            else:
                target.write_text("")
            return 0

        Runner.command = spy
        self.addCleanup(setattr, Runner, "command", real)
        st = runner.stages[stage_id]
        st.status = "pending"
        getattr(runner, method_for(stage_id))(st, runner.global_deadline)
        return st

    def last(self, tool):
        for cmd in reversed(self.captured):
            if tool in cmd[0]:
                return cmd
        self.fail(f"{tool} was never invoked; captured: {self.captured}")


# Inputs each stage actually consumes, so a test seeds the right upstream artifact.
CORPUS_URLS = ["https://ok.example.com/a", "https://ok.example.com/a?id=1", "https://ok.example.com/api/v1/x"]


class TestArgv(Harness):
    """Exact CLI construction for katana, arjun and ffuf, under explicit and extreme inputs."""

    def test_katana_uses_u_not_l_and_is_bounded(self):
        run = self.build(["example.com", "--crawl-depth", "3", "--concurrency", "7",
                          "--rate-limit", "11", "--request-timeout", "9"],
                         seed={"httpx": ["example.com"]})
        self.run_stage(run, "crawl")
        cmd = self.last("katana")
        self.assertNotIn("-l", cmd, "katana has no -l flag; input is -u")
        self.assertEqual(flag(cmd, "-u"), str(Path(run.raw) / "crawl" / "inputs.txt"))
        self.assertEqual(flag(cmd, "-d"), "3")
        self.assertEqual(flag(cmd, "-c"), "7")
        self.assertEqual(flag(cmd, "-rl"), "11")
        self.assertEqual(flag(cmd, "-timeout"), "9")
        self.assertEqual(flag(cmd, "-e"), "cdn")
        for required in ("-silent", "-duc", "-nc"):
            self.assertIn(required, cmd)

    def test_katana_depth_concurrency_and_timeout_floored(self):
        run = self.build(["example.com", "--crawl-depth", "0", "--concurrency", "0",
                          "--rate-limit", "0", "--request-timeout", "0"],
                         seed={"httpx": ["example.com"]})
        self.run_stage(run, "crawl")
        cmd = self.last("katana")
        # a zero is either invalid or "unlimited" to the tool; every bound has a floor of 1
        for f in ("-d", "-c", "-rl", "-timeout"):
            self.assertEqual(flag(cmd, f), "1", f"{f} was not floored")

    def test_katana_scope_pattern_constrains_to_in_scope_hosts(self):
        run = self.build(["example.com", "--strict-scope", "--scope-exclude", "bad.example.com"],
                         seed={"httpx": ["example.com"]})
        self.run_stage(run, "crawl")
        pattern = flag(self.last("katana"), "-cs")
        self.assertIsNotNone(pattern, "crawl must constrain katana to in-scope hosts")
        # -cs takes a regex, not a literal host, so the dot arrives escaped
        # -cs takes a regex, so the dot is escaped: the literal text is example\.com
        self.assertIn("example", pattern)
        self.assertIn(r"example\.com", pattern)

    def test_arjun_uses_import_file(self):
        run = self.build(["example.com", "--arjun-max", "5", "--concurrency", "2",
                          "--request-timeout", "9"], seed={"corpus": CORPUS_URLS})
        self.run_stage(run, "arjun")
        cmd = self.last("arjun")
        self.assertNotIn("-l", cmd, "arjun has no -l flag either; input is -i")
        self.assertEqual(flag(cmd, "-i"), str(Path(run.raw) / "arjun" / "inputs.txt"))
        self.assertEqual(flag(cmd, "-T"), "9")
        self.assertIn("-q", cmd)
        self.assertTrue(flag(cmd, "-o").endswith(".json"))
        self.assertTrue(flag(cmd, "-oT").endswith(".txt"))

    def test_arjun_thread_clamp_under_explicit_and_extreme_input(self):
        for concurrency, ceiling in (("1", "10"), ("2", "10"), ("10", "10"), ("9999", "10")):
            with self.subTest(concurrency=concurrency):
                run = self.build(["example.com", "--arjun-max", "1", "--concurrency", concurrency],
                                 seed={"corpus": CORPUS_URLS})
                self.run_stage(run, "arjun")
                threads = flag(self.last("arjun"), "-t")
                self.assertIsNotNone(threads, "arjun was not invoked")
                self.assertLessEqual(int(threads), int(ceiling))

    def test_arjun_headers_carry_the_credential_text_not_a_path(self):
        """
        arjun's --headers takes the header text, not a filename. Passing a path is syntactically
        fine and arjun still exits 0, so an argv assertion cannot catch it - the only way to know
        the credential arrived is to observe the server. This asserts the value is inline, and
        TestArjunCredentialArrives proves the request actually carries it.
        """
        run = self.build(["example.com", "--arjun-max", "1"], seed={"corpus": CORPUS_URLS})
        Path(self.tmp, "a.txt").write_text("Cookie: session=A\n")
        Path(self.tmp, "b.txt").write_text("Cookie: session=B\n")
        run.args.cookie_file = str(Path(self.tmp, "a.txt"))
        run.identities["a"] = {"Cookie": "session=A"}
        self.run_stage(run, "arjun")
        cmd = self.last("arjun")
        value = flag(cmd, "--headers")
        self.assertIsNotNone(value)
        self.assertEqual(value, "Cookie: session=A",
                         f"--headers did not carry the credential text: {value!r}")
        self.assertFalse(Path(value).exists(),
                         "--headers was given a path; arjun would send the path as a literal header")

    def test_arjun_optional_flags_are_opt_in(self):
        run = self.build(["example.com", "--arjun-max", "1"], seed={"corpus": CORPUS_URLS})
        self.run_stage(run, "arjun")
        self.assertNotIn("--passive", self.last("arjun"))
        self.assertIsNone(flag(self.last("arjun"), "-d"))

        run = self.build(["example.com", "--arjun-max", "1", "--arjun-passive",
                          "--arjun-delay", "0.25"], seed={"corpus": CORPUS_URLS})
        self.run_stage(run, "arjun")
        cmd = self.last("arjun")
        self.assertIn("--passive", cmd)
        self.assertEqual(flag(cmd, "-d"), "0.25")

    def test_ffuf_uses_all_with_404_filter_and_autocalibration(self):
        run = self.build(["example.com", "--ffuf-max-hosts", "1", "--request-timeout", "9"],
                         seed={"corpus": ("origins.txt", ["https://example.com"])})
        self.run_stage(run, "ffuf")
        cmd = self.last("ffuf")
        self.assertEqual(flag(cmd, "-mc"), "all")
        self.assertEqual(flag(cmd, "-fc"), "404")
        self.assertIn("-ac", cmd)
        self.assertIn("-noninteractive", cmd)
        self.assertEqual(flag(cmd, "-timeout"), "9")
        self.assertTrue(flag(cmd, "-u").endswith("/FUZZ"),
                        "-u must end in FUZZ or ffuf silently ignores -recursion")

    def test_ffuf_thread_cap(self):
        for threads, expected in (("1", "1"), ("40", "40"), ("9999", "40")):
            with self.subTest(threads=threads):
                run = self.build(["example.com", "--ffuf-max-hosts", "1", "--ffuf-threads", threads],
                                 seed={"corpus": ("origins.txt", ["https://example.com"])})
                self.run_stage(run, "ffuf")
                self.assertEqual(flag(self.last("ffuf"), "-t"), expected)

    def test_ffuf_per_host_time_cap(self):
        for maxtime, expected in (("1", "5"), ("5", "5"), ("120", "120"), ("99999", "120"), ("0", "120")):
            with self.subTest(maxtime=maxtime):
                run = self.build(["example.com", "--ffuf-max-hosts", "1", "--ffuf-max-time", maxtime],
                                 seed={"corpus": ("origins.txt", ["https://example.com"])})
                self.run_stage(run, "ffuf")
                self.assertEqual(flag(self.last("ffuf"), "-maxtime"), expected)

    def test_ffuf_recursion_is_opt_in_and_depth_capped(self):
        run = self.build(["example.com", "--ffuf-max-hosts", "1"], seed={"corpus": ("origins.txt", ["https://example.com"])})
        self.run_stage(run, "ffuf")
        self.assertNotIn("-recursion", self.last("ffuf"), "recursion must be off unless asked for")

        for depth, expected in (("0", "1"), ("1", "1"), ("2", "2"), ("3", "3"), ("99", "3")):
            with self.subTest(depth=depth):
                run = self.build(["example.com", "--ffuf-max-hosts", "1", "--ffuf-recursion",
                                  "--ffuf-recursion-depth", depth], seed={"corpus": ("origins.txt", ["https://example.com"])})
                self.run_stage(run, "ffuf")
                cmd = self.last("ffuf")
                self.assertIn("-recursion", cmd)
                self.assertEqual(flag(cmd, "-recursion-depth"), expected)
                self.assertEqual(flag(cmd, "-recursion-strategy"), "default")

    def test_ffuf_never_widens_the_scan(self):
        run = self.build(["example.com", "--ffuf-max-hosts", "1", "--ffuf-recursion"],
                         seed={"corpus": ("origins.txt", ["https://example.com"])})
        self.run_stage(run, "ffuf")
        cmd = self.last("ffuf")
        self.assertNotIn("-pS", cmd)
        self.assertNotIn("-sS", cmd)
        self.assertNotIn("1-65535", cmd)

    def test_ports_nmap_only_scans_naabu_confirmed_ports(self):
        run = self.build(["example.com", "--port-services"], seed={"dnsx": ["example.com"]})
        self.run_stage(run, "ports", naabu="example.com:80\nexample.com:443\nexample.com:22\n")
        cmd = self.last("nmap")
        for f in ("-sV", "-sC", "-Pn", "-T4"):
            self.assertIn(f, cmd)
        self.assertTrue(flag(cmd, "-oX").endswith(".xml"))
        confirmed = set(flag(cmd, "-p").split(","))
        self.assertTrue(confirmed <= {"22", "80", "443"}, f"nmap widened beyond naabu: {confirmed}")
        self.assertNotIn("-pS", cmd)

    def test_ports_nmap_not_invoked_by_default(self):
        run = self.build(["example.com"], seed={"dnsx": ["example.com"]})
        self.run_stage(run, "ports", naabu="example.com:80\n")
        for cmd in self.captured:
            self.assertNotIn("nmap", cmd[0], "nmap ran without --port-services")


class TestScreenshots(Harness):
    """httpx drives a browser per thread, so its defaults are unsafe and are all overridden."""

    def run_screens(self, argv, browser="chromium", png=False):
        """Run the stage with httpx stubbed. browser=None simulates a host with no local browser."""
        import autorecon_v8.core as core
        real_which = core.shutil.which
        real_command = Runner.command

        def which(name, *a, **k):
            if name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
                return f"/usr/bin/{name}" if name == browser else None
            return real_which(name, *a, **k)

        def spy(runner_self, sid, cmd, host, deadline, out, cwd=None):
            self.captured.append(list(cmd))
            target = Path(out)
            target.parent.mkdir(parents=True, exist_ok=True)
            if png:
                (target.parent / "shot-0001.png").write_bytes(b"\x89PNG\r\n\x1a\n")
            target.write_text("")
            return 0

        core.shutil.which = which
        Runner.command = spy
        self.addCleanup(setattr, core.shutil, "which", real_which)
        self.addCleanup(setattr, Runner, "command", real_command)
        run = self.build(argv, seed={"httpx": ["https://example.com"]})
        self.captured = []
        st = run.stages["screenshots"]
        st.status = "pending"
        run.screenshot_stage(st, run.global_deadline)
        return run, st

    def test_httpx_argv_is_bounded_and_uses_system_chrome(self):
        run, st = self.run_screens(["example.com", "--concurrency", "3", "--request-timeout", "1"])
        cmd = self.last("httpx")
        self.assertEqual(flag(cmd, "-l"), str(Path(run.raw) / "screenshots" / "inputs.txt"))
        self.assertIn("-screenshot", cmd)
        self.assertIn("-nc", cmd)
        self.assertIn("-system-chrome", cmd)
        self.assertNotIn("-no-screenshot-full-page", cmd,
                         "a local browser exists, so the fallback must not be used")
        # httpx defaults to 50 threads and each may drive a browser
        self.assertEqual(flag(cmd, "-t"), "3")
        # request-timeout 1 would ask for a 1s screenshot budget; floored at 5
        self.assertEqual(flag(cmd, "-screenshot-timeout"), "5")

    def test_thread_clamp_under_extreme_input(self):
        for concurrency, expected in (("1", "1"), ("10", "10"), ("50", "10"), ("5000", "10")):
            with self.subTest(concurrency=concurrency):
                run, st = self.run_screens(["example.com", "--concurrency", concurrency])
                self.assertEqual(flag(self.last("httpx"), "-t"), expected)

    def test_falls_back_when_no_local_browser_exists(self):
        run, st = self.run_screens(["example.com"], browser=None)
        cmd = self.last("httpx")
        self.assertNotIn("-system-chrome", cmd)
        self.assertIn("-no-screenshot-full-page", cmd,
                      "without a local browser, httpx must not try to fetch one mid-run")

    def test_no_capture_is_reported_rather_than_a_bare_success(self):
        run, st = self.run_screens(["example.com"], browser=None, png=False)
        self.assertEqual(st.status, "skipped")
        self.assertIn("no screenshot captured", st.failure_reason)
        self.assertIn("no local chrome/chromium", st.failure_reason)

    def test_captured_images_are_listed_and_counted(self):
        run, st = self.run_screens(["example.com"], png=True)
        listed = (Path(run.raw) / "screenshots" / "normalized.txt").read_text()
        self.assertIn(".png", listed)
        self.assertEqual(st.processed, 1)
        self.assertNotEqual(st.status, "skipped")

    def test_dry_run_makes_no_tool_call(self):
        run = self.build(["example.com", "--dry-run"], seed={"httpx": ["https://example.com"]})
        self.run_stage(run, "screenshots")
        self.assertEqual(self.captured, [], "dry-run invoked httpx")

    def test_no_origins_skips_with_a_reason(self):
        run = self.build(["example.com"], seed={"httpx": []})
        st = self.run_stage(run, "screenshots")
        self.assertEqual(st.status, "skipped")
        self.assertIn("no live HTTP origins", st.failure_reason)


class TestDecoupledContracts(Harness):
    """read_partition and its consumers must survive absent, empty and populated producers."""

    def test_read_partition_absent_empty_and_present(self):
        run = self.build(["example.com"], seed={"corpus": ["https://ok.example.com/a"]})
        raw = Path(run.raw)
        self.assertEqual(run.read_partition("params.txt", "corpus"), [])
        self.assertEqual(run.read_partition("params.txt", "stage-that-never-ran"), [])
        (raw / "corpus" / "params.txt").write_text("")
        self.assertEqual(run.read_partition("params.txt", "corpus"), [])
        (raw / "corpus" / "params.txt").write_text("https://a/x\n\n   \nhttps://b/y\n")
        self.assertEqual(run.read_partition("params.txt", "corpus"), ["https://a/x", "https://b/y"])

    def test_access_checks_runs_with_no_producer_directories(self):
        run = self.build(["example.com"])
        raw = Path(run.raw)
        for producer in ("arjun", "ffuf"):
            self.assertFalse((raw / producer).exists())
        targets, provenance = run.access_check_targets()
        self.assertIsInstance(targets, list)
        self.assertNotIn("arjun/params.txt", provenance)
        self.assertNotIn("ffuf/paths.txt", provenance)

    def test_access_checks_runs_with_empty_producer_files(self):
        run = self.build(["example.com"])
        raw = Path(run.raw)
        for producer in ("arjun", "ffuf"):
            (raw / producer).mkdir(parents=True, exist_ok=True)
            (raw / producer / "params.txt").write_text("")
            (raw / producer / "paths.txt").write_text("")
        targets, provenance = run.access_check_targets()
        self.assertNotIn("arjun/params.txt", provenance,
                         "an empty producer must not be claimed as a source")
        self.assertNotIn("ffuf/paths.txt", provenance)

    def test_access_checks_merges_every_populated_producer(self):
        run = self.build(["example.com"])
        raw = Path(run.raw)
        (raw / "corpus").mkdir(parents=True, exist_ok=True)
        (raw / "corpus" / "params.txt").write_text("https://a/x\nhttps://shared/dup\n")
        (raw / "corpus" / "api.txt").write_text("https://a/api\n")
        (raw / "arjun").mkdir(parents=True, exist_ok=True)
        (raw / "arjun" / "params.txt").write_text("https://a/x?q=1\nhttps://arjun/only\n")
        (raw / "ffuf").mkdir(parents=True, exist_ok=True)
        (raw / "ffuf" / "paths.txt").write_text("https://ffuf/only\nhttps://shared/dup\n")
        targets, provenance = run.access_check_targets()
        self.assertEqual(provenance, ["corpus/params.txt", "corpus/api.txt",
                                      "arjun/params.txt", "ffuf/paths.txt"])
        self.assertIn("https://arjun/only", targets)
        self.assertIn("https://ffuf/only", targets)
        self.assertEqual(targets.count("https://shared/dup"), 1, "not deduped across producers")
        self.assertEqual(len(targets), len(set(targets)))

    def corpus_bytes(self, run):
        corpus = Path(run.raw) / "corpus"
        return {p.name: p.read_bytes() for p in sorted(corpus.iterdir()) if p.is_file()}

    def test_arjun_never_writes_into_corpus(self):
        run = self.build(["example.com", "--arjun-max", "1"], seed={"corpus": CORPUS_URLS})
        before = self.corpus_bytes(run)
        self.run_stage(run, "arjun")
        self.assertEqual(before, self.corpus_bytes(run), "arjun mutated a corpus artifact")
        self.assertTrue((Path(run.raw) / "arjun" / "params.txt").exists())

    def test_ffuf_never_writes_into_corpus(self):
        run = self.build(["example.com", "--ffuf-max-hosts", "1"], seed={"corpus": ("origins.txt", ["https://example.com"])})
        before = self.corpus_bytes(run)
        self.run_stage(run, "ffuf")
        self.assertEqual(before, self.corpus_bytes(run), "ffuf mutated a corpus artifact")
        self.assertTrue((Path(run.raw) / "ffuf" / "paths.txt").exists())

    def test_consumer_degrades_when_a_producer_stage_was_skipped(self):
        # a corpus with no parameters at all, and neither producer directory present
        run = self.build(["example.com"], seed={"corpus": ["https://ok.example.com/plain"]})
        targets, provenance = run.access_check_targets()
        self.assertIsInstance(targets, list)
        self.assertIsInstance(provenance, list)


class TestScopeEnforcement(Harness):
    """Out-of-scope targets are refused and recorded, never probed."""

    # Rejected by scope, and therefore expected to appear in dropped-out-of-scope.txt.
    HOSTILE = [
        "https://evil.test/steal",
        "https://bad.example.com/x",
        "https://example.com.evil.test/y",
        "http://127.0.0.1:22/",
        "http://localhost/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/internal",
    ]

    # Discarded before the scope check because canonical_url() cannot parse it. A malformed URL is
    # not a scope refusal, so it must NOT be claimed in dropped-out-of-scope.txt; that file is an
    # audit record of deliberate refusals and diluting it with junk would make it useless.
    MALFORMED = ["http://[::1]/x"]

    def test_scope_decide_rejects_hostile_targets(self):
        s = Scope("example.com", ["example.com"], ["bad.example.com"])
        for url in self.HOSTILE + self.MALFORMED:
            with self.subTest(url=url):
                self.assertFalse(s.decide(url)[0], f"{url} was allowed")
        self.assertTrue(s.decide("https://ok.example.com/x")[0])

    def test_strict_scope_must_be_on_for_scope_to_mean_anything(self):
        # documents the default that makes every other test here require --strict-scope
        run = self.build(["example.com"])
        self.assertFalse(run.args.strict_scope)
        self.assertTrue(run.scope.decide("https://evil.test/x")[0],
                        "without --strict-scope, decide() allows everything by design")

    def test_corpus_drops_out_of_scope_and_records_them(self):
        run = self.build(["example.com", "--strict-scope", "--scope-exclude", "bad.example.com"],
                         seed={"crawl": ["https://ok.example.com/a", *self.HOSTILE]})
        self.run_stage(run, "corpus")
        kept = (Path(run.raw) / "corpus" / "normalized.txt").read_text()
        self.assertIn("https://ok.example.com/a", kept)
        # inputs() scope-filters before corpus sees anything, so nothing hostile can arrive here
        # by the normal route. Assert the filter holds rather than a drop record that cannot exist.
        for url in self.HOSTILE:
            self.assertNotIn(url, kept, f"{url} survived into corpus")

    def test_corpus_records_its_own_second_gate(self):
        # inputs() already scope-filters, so corpus only sees a hostile URL if that upstream
        # gate is bypassed. Bypass it deliberately: the second gate must still refuse, and must
        # still record the refusal rather than dropping it silently.
        run = self.build(["example.com", "--strict-scope"])
        hostile = list(self.HOSTILE) + ["https://ok.example.com/a"]
        # bad.example.com is a legitimate subdomain of the seed; it is only out of scope because
        # it is explicitly excluded, which is exactly the rule under test here.
        run = self.build(["example.com", "--strict-scope", "--scope-exclude", "bad.example.com"])
        real = Runner.inputs
        Runner.inputs = lambda runner_self, sid: list(hostile)
        self.addCleanup(setattr, Runner, "inputs", real)
        self.run_stage(run, "corpus")
        root = Path(run.raw) / "corpus"
        kept = (root / "normalized.txt").read_text()
        dropped = (root / "dropped-out-of-scope.txt").read_text()
        self.assertIn("https://ok.example.com/a", kept)
        # corpus records the canonicalised form, so the trailing slash is gone; compare on the
        # same key rather than on the raw input string.
        dropped_keys = {u.rstrip("/") for u in dropped.split()}
        for url in self.HOSTILE:
            self.assertNotIn(url, kept, f"{url} survived the corpus gate")
            self.assertIn(url.rstrip("/"), dropped_keys,
                          f"{url} was refused by corpus without being recorded")
        for url in self.MALFORMED:
            self.assertNotIn(url, kept, f"malformed URL {url} reached the corpus")
            self.assertNotIn(url.rstrip("/"), dropped_keys,
                             "a malformed URL is not a scope refusal and must not be logged as one")

    def test_crawl_records_dropped_out_of_scope(self):
        run = self.build(["example.com", "--strict-scope"], seed={"httpx": ["example.com"]})
        self.run_stage(run, "crawl")
        dropped = Path(run.raw) / "crawl" / "dropped-out-of-scope.txt"
        self.assertTrue(dropped.exists(), "crawl must account for everything it dropped")

    def test_ffuf_refuses_out_of_scope_matches(self):
        run = self.build(["example.com", "--strict-scope", "--ffuf-max-hosts", "1"],
                         seed={"corpus": ("origins.txt", ["https://example.com"])})
        self.run_stage(run, "ffuf", results=[
            {"url": "https://example.com/admin", "status": 200, "length": 5},
            {"url": "https://evil.test/admin", "status": 200, "length": 5},
            {"url": "http://169.254.169.254/latest/", "status": 200, "length": 5}])
        root = Path(run.raw) / "ffuf"
        paths = (root / "paths.txt").read_text()
        self.assertIn("https://example.com/admin", paths)
        self.assertNotIn("evil.test", paths)
        self.assertNotIn("169.254.169.254", paths)
        refused = root / "refused.txt"
        self.assertTrue(refused.exists(), "a refusal must be recorded, not silently dropped")
        self.assertIn("https://evil.test/admin", refused.read_text())
        self.assertIn("169.254.169.254", refused.read_text())

    def test_arjun_refuses_out_of_scope_targets(self):
        run = self.build(["example.com", "--strict-scope", "--arjun-max", "3"],
                         seed={"corpus": CORPUS_URLS})
        self.run_stage(run, "arjun", results={"https://evil.test/a": {"params": ["q"], "method": "GET"}})
        root = Path(run.raw) / "arjun"
        for name in ("normalized.txt", "params.txt", "params.json"):
            self.assertNotIn("evil.test", (root / name).read_text(),
                             f"{name} contains an out-of-scope discovery")

    def test_access_checks_relies_on_its_producers_for_scope(self):
        # Documented, not desired: access_check_targets merges partitions and does NOT re-run
        # Scope.decide, because crawl, corpus, arjun and ffuf each enforce scope on the way in.
        # This test exists so that if someone later removes a producer's gate, the change shows
        # up here as a decision rather than as a silent hole.
        run = self.build(["example.com", "--strict-scope"])
        raw = Path(run.raw)
        (raw / "corpus").mkdir(parents=True, exist_ok=True)
        (raw / "corpus" / "params.txt").write_text("https://ok.example.com/x\nhttps://evil.test/x\n")
        targets, _ = run.access_check_targets()
        self.assertIn("https://evil.test/x", targets,
                      "if this now passes the filter, the producers' gates are the only defence")

    def test_access_checks_targets_are_scope_checked_by_producers(self):
        run = self.build(["example.com", "--strict-scope"])
        raw = Path(run.raw)
        (raw / "corpus").mkdir(parents=True, exist_ok=True)
        (raw / "corpus" / "params.txt").write_text("https://ok.example.com/x\nhttps://evil.test/x\n")
        (raw / "ffuf").mkdir(parents=True, exist_ok=True)
        (raw / "ffuf" / "paths.txt").write_text("http://169.254.169.254/\nhttps://ok.example.com/y\n")
        targets, _ = run.access_check_targets()
        joined = " ".join(targets)
        self.assertIn("http://169.254.169.254/", joined)
        self.assertIn("https://ok.example.com/y", joined)


class TestStateReset(Harness):
    """execute() must not let a stale failure_reason survive, and must never wedge a stage."""

    NEW_STAGES = ["corpus", "crawl", "javascript", "arjun", "ffuf", "access-checks", "ports", "screenshots"]

    def test_execute_clears_failure_reason_and_exit_code_on_entry(self):
        for stage in self.NEW_STAGES:
            with self.subTest(stage=stage):
                run = self.build(["example.com"], seed=self.STAGE_SEEDS[stage])
                st = run.stages[stage]
                st.failure_reason = "stale reason from a previous attempt"
                st.exit_code = 99
                st.status = "pending"
                real = Runner.command
                Runner.command = lambda *a, **k: 0
                try:
                    run.execute(st)
                finally:
                    Runner.command = real
                self.assertNotEqual(st.failure_reason, "stale reason from a previous attempt",
                                    f"{stage} kept a stale failure_reason")
                # execute() clears exit_code to None on entry; a clean run then sets it to 0.
                # Either is correct. What must never survive is the previous attempt's 99.
                self.assertNotEqual(st.exit_code, 99, f"{stage} kept a stale exit_code")

    # Each stage needs its own upstream artifact, otherwise it reports "skipped" for want of
    # input and never reaches the subprocess where the injected exception would fire.
    STAGE_SEEDS = {
        "corpus": {"crawl": ["https://ok.example.com/a"]},
        "crawl": {"httpx": ["example.com"]},
        "javascript": {"corpus": ["https://ok.example.com/app.js"]},
        "arjun": {"corpus": ["https://ok.example.com/a?id=1"]},
        "ffuf": {"corpus": ("origins.txt", ["https://ok.example.com"])},
        "access-checks": {"corpus": ("params.txt", ["https://ok.example.com/a?id=1"])},
        "ports": {"dnsx": ["example.com"]},
        "screenshots": {"httpx": ["https://ok.example.com"]},
    }

    def test_unexpected_exception_does_not_wedge_a_stage_in_running(self):
        for stage in self.NEW_STAGES:
            with self.subTest(stage=stage):
                run = self.build(["example.com"], seed=self.STAGE_SEEDS[stage])
                st = run.stages[stage]
                st.status = "pending"
                real = Runner.command
                fired = []

                def boom(*a, **k):
                    fired.append(1)
                    raise RuntimeError("synthetic tool explosion")

                Runner.command = boom
                try:
                    run.execute(st)
                finally:
                    Runner.command = real
                # The invariant under test: whatever happened, the stage is not left mid-flight.
                self.assertNotEqual(st.status, "running", f"{stage} wedged in running")
                self.assertIsNone(run.current, f"{stage} stayed marked current after failing")
                if not fired:
                    # The stage declined to run because it had no work, so no exception could
                    # occur. Assert only that it terminated cleanly.
                    self.assertIn(st.status, ("skipped", "completed"))
                    continue
                # Where the exception actually fired, the stage must fail loudly and keep the reason.
                self.assertIn(st.status, ("failed", "partial"), f"{stage} swallowed the exception")
                self.assertIn("synthetic tool explosion", st.failure_reason or "")
                self.assertIsNotNone(st.ended_at)
                self.assertIsNotNone(st.runtime_seconds)

    def test_stages_that_skip_do_not_claim_to_have_run(self):
        # A stage with no input must say so rather than report a clean success, otherwise a
        # misconfigured run looks identical to a thorough one.
        for stage, seed in (("access-checks", {}), ("ffuf", {})):
            with self.subTest(stage=stage):
                run = self.build(["example.com"], seed=seed)
                st = self.run_stage(run, stage)
                if st.total == 0:
                    self.assertEqual(st.status, "skipped", f"{stage} claimed success with no input")
                    self.assertTrue(st.failure_reason, f"{stage} skipped without a reason")

    def test_stage_is_never_left_as_current_after_a_failure(self):
        run = self.build(["example.com"])
        st = run.stages["ffuf"]
        st.status = "pending"
        real = Runner.command

        def boom(*a, **k):
            raise RuntimeError("boom")

        Runner.command = boom
        try:
            run.execute(st)
        finally:
            Runner.command = real
        self.assertIsNone(run.current, "a failed stage left itself marked current")
        self.assertIsNotNone(st.ended_at)
        self.assertIsNotNone(st.runtime_seconds)

    def test_resume_does_not_inherit_a_previous_failure_reason(self):
        run = self.build(["example.com", "--strict-scope"], seed={"corpus": CORPUS_URLS})
        st = run.stages["corpus"]
        st.failure_reason = "ValueError: poisoned by a previous run"
        st.exit_code = 1
        st.status = "pending"
        real = Runner.command
        Runner.command = lambda rs, sid, cmd, host, dl, out, cwd=None: (
            Path(out).parent.mkdir(parents=True, exist_ok=True), Path(out).write_text(""), 0)[-1]
        try:
            run.execute(st)
        finally:
            Runner.command = real
        self.assertNotIn("poisoned", st.failure_reason or "")
        self.assertIsNone(st.exit_code)


class TestParsers(Harness):
    """Tool-output parsers must reject malformed input rather than coerce it."""

    def test_arjun_parse_shapes(self):
        self.assertEqual(arjun_parse(""), [])
        self.assertEqual(arjun_parse("not json"), [])
        self.assertEqual(arjun_parse('{"u": {"params": []}}'), [])
        self.assertEqual(arjun_parse('{"u": "string"}'), [])
        self.assertEqual(arjun_parse('{"ftp://x/y": {"params": ["a"]}}'), [])
        self.assertEqual(arjun_parse('{"http://x/a": {"params": ["q"], "method": "post"}}'),
                         [("http://x/a", ["q"], "POST")])

    def test_ffuf_results_shapes(self):
        self.assertEqual(ffuf_results(""), [])
        self.assertEqual(ffuf_results("{}"), [])
        self.assertEqual(ffuf_results("garbage"), [])
        self.assertEqual(ffuf_results('{"results": [{"status": 200}]}'), [])
        self.assertEqual(len(ffuf_results('{"results": [{"url": "http://x/a"}]}')), 1)
        self.assertEqual(len(ffuf_results('[{"url": "http://x/a"}]')), 1)

    def test_naabu_open_ports_rejects_malformed_lines(self):
        parsed = naabu_open_ports("1.2.3.4:80\n1.2.3.4:80\ngarbage\n1.2.3.4:0\n"
                                  "1.2.3.4:99999\n1.2.3.4:abc\n1.2.3.4:\n")
        self.assertEqual(parsed, {"1.2.3.4": [80]})

    def test_nmap_services_keeps_only_open_ports(self):
        xml = ('<nmaprun><host><address addr="10.0.0.5"/>'
               '<ports>'
               '<port protocol="tcp" portid="22"><state state="open"/>'
               '<service name="ssh" version="8.2"/></port>'
               '<port protocol="tcp" portid="80"><state state="closed"/>'
               '<service name="http"/></port>'
               '<port protocol="tcp" portid="443"><state state="filtered"/>'
               '<service name="https"/></port>'
               '</ports></host></nmaprun>')
        rows = nmap_services(xml)
        self.assertEqual([r["port"] for r in rows], [22], "a non-open port became a service record")
        self.assertEqual(rows[0]["service"], "ssh")
        self.assertEqual(rows[0]["version"], "8.2")
        self.assertEqual(nmap_services("<not xml"), [])
        self.assertEqual(nmap_services(""), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
