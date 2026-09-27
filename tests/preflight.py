"""A preflight that says what is missing before the run starts.

Every stage that shells out degrades to a skip with a reason when its tool is absent, which is honest
and is not the problem. The problem is when it happens at hour three, after the DNS work that did work
has already been spent, and the operator only learns it by reading run-state.json afterwards. A missing
tool is knowable before the first stage runs.

So this is a preflight, not a gate. It reports, it never blocks, and a missing tool is not a reason to
refuse to start - passive discovery with no naabu is still worth running.

The check that matters most is resolve_tool rather than shutil.which: the Debian `httpx` package is an
entirely unrelated program that answers to the same name, so a naive which() says the tool is present
and the stage then fails in a way that looks like a target problem.
"""
import shutil
import unittest
from pathlib import Path

import autorecon_v8.core as core
from autorecon_v8.cli import apply_profile_defaults, parser
from autorecon_v8.core import ACTIVE, PROFILES, Runner, STAGE_IDS, resolve_tool

# The tool each stage needs, taken from core rather than restated: a second hand-written copy of
# this map is exactly the thing that goes stale and makes a preflight lie. Covered and asserted below.
STAGE_TOOLS = core.STAGE_TOOLS


class TestPreflight(unittest.TestCase):
    def test_the_table_covers_every_stage(self):
        self.assertEqual(sorted(STAGE_TOOLS), sorted(STAGE_IDS),
                         "STAGE_TOOLS has drifted from STAGE_IDS")

    def test_the_table_agrees_with_the_code(self):
        """generic_stage resolves its tool out of this table, so the two cannot drift."""
        import inspect
        source = inspect.getsource(core.Runner.generic_stage)
        self.assertIn("STAGE_TOOLS.get(st.id)", source,
                      "generic_stage stopped reading the shared table and has its own copy again")
        for stage, tool in core.STAGE_TOOLS.items():
            if not tool:
                continue
            self.assertEqual(STAGE_TOOLS[stage], tool,
                             f"the test copy disagrees with core for {stage}")

    def test_present_tools_are_reported_present(self):
        """The positive case matters as much as the negative one: a preflight that always says
        'missing' is noise and gets ignored."""
        tmp = Path("/usr/bin")
        found = [t for t in set(STAGE_TOOLS.values()) if t and shutil.which(t)]
        if not found:
            self.skipTest("no external tools installed on this host")
        for tool in found:
            self.assertTrue(core.resolve_tool(tool) is not None,
                            f"{tool} is on PATH but resolve_tool did not return it")


class TestResolveToolRefusesImpostors(unittest.TestCase):
    def test_the_debian_httpx_is_not_the_httpx_we_want(self):
        """A same-named unrelated binary is the failure mode resolve_tool exists for."""
        real = core.resolve_tool("httpx")
        if real is None:
            self.skipTest("no httpx on this host")
        self.assertNotIn("/usr/bin/httpx", str(real),
                         "resolve_tool accepted the unrelated Debian httpx")
        self.assertNotIn("/usr/local/bin/httpx", str(real),
                         "resolve_tool accepted /usr/local/bin/httpx")

    def test_a_tool_that_is_not_installed_returns_none(self):
        self.assertIsNone(core.resolve_tool("definitely-not-a-real-tool-xyz"),
                          "resolve_tool invented a path for a tool that does not exist")


class TestPreflightNeverBlocks(unittest.TestCase):
    def test_a_missing_tool_does_not_stop_the_run(self):
        """No naabu, no nmap: the run still has to start and still has to finish."""
        import tempfile
        tmp = tempfile.mkdtemp()
        try:
            args = apply_profile_defaults(parser().parse_args(
                ["127.0.0.1", "--output-dir", tmp, "--dry-run", "--profile", "passive"]))
            run = Runner(args)
            self.assertGreater(len(run.preflight()), 0, "preflight returned nothing to report")
            self.assertTrue(all(isinstance(row, tuple) for row in run.preflight()),
                            "preflight rows are not uniformly shaped")
        finally:
            import shutil as s
            s.rmtree(tmp, ignore_errors=True)

    def test_preflight_rows_name_a_stage_and_a_verdict(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        try:
            args = apply_profile_defaults(parser().parse_args(
                ["127.0.0.1", "--output-dir", tmp, "--dry-run", "--profile", "passive"]))
            rows = Runner(args).preflight()
            for row in rows:
                self.assertEqual(len(row), 3, f"unexpected preflight row shape: {row!r}")
                stage, tool, ok = row
                self.assertIn(stage, STAGE_IDS, f"preflight named unknown stage {stage!r}")
                self.assertIsInstance(ok, bool)
                if ok:
                    self.assertTrue(tool, f"{stage} reported present with no tool named")
        finally:
            import shutil as s
            s.rmtree(tmp, ignore_errors=True)

    def test_the_run_prints_the_preflight_before_the_first_stage(self):
        """The point of a preflight is that it is said early, on stderr, without blocking."""
        import tempfile
        import io
        import contextlib
        from autorecon_v8.core import Runner
        tmp = tempfile.mkdtemp()
        try:
            args = apply_profile_defaults(parser().parse_args(
                ["127.0.0.1", "--output-dir", tmp, "--dry-run", "--profile", "passive"]))
            run = Runner(args)
            real = core.resolve_tool
            core.resolve_tool = lambda name: None          # every tool missing
            try:
                err = io.StringIO()
                out = io.StringIO()
                with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
                    run.run()
            finally:
                core.resolve_tool = real
            self.assertIn("preflight", err.getvalue(),
                          "a run with every tool missing did not report a preflight")
            self.assertIn("not found", err.getvalue())
            self.assertIn("continues", err.getvalue(),
                          "the preflight does not say the run goes on")
        finally:
            import shutil as s
            s.rmtree(tmp, ignore_errors=True)

    def test_a_clean_preflight_says_nothing(self):
        """A preflight that always prints is noise, and noise is what gets ignored."""
        import tempfile
        import io
        import contextlib
        from autorecon_v8.core import Runner
        tmp = tempfile.mkdtemp()
        try:
            args = apply_profile_defaults(parser().parse_args(
                ["127.0.0.1", "--output-dir", tmp, "--dry-run", "--profile", "passive"]))
            run = Runner(args)
            if any(not ok for _, _, ok in run.preflight()):
                self.skipTest("this host is missing tools, so a clean preflight cannot be shown")
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                run.run()
            self.assertNotIn("preflight", err.getvalue())
        finally:
            import shutil as s
            s.rmtree(tmp, ignore_errors=True)

    def test_a_skipped_stage_never_asks_for_a_tool_it_will_not_use(self):
        """If the profile skips a stage, its tool is not part of this run's preflight."""
        import tempfile
        tmp = tempfile.mkdtemp()
        try:
            args = apply_profile_defaults(parser().parse_args(
                ["127.0.0.1", "--output-dir", tmp, "--dry-run", "--profile", "passive"]))
            run = Runner(args)
            checked = [row[0] for row in run.preflight()]
            for stage in PROFILES["passive"]["skip"]:
                self.assertNotIn(stage, checked,
                                 f"passive skips {stage} but preflight still requires its tool")
        finally:
            import shutil as s
            s.rmtree(tmp, ignore_errors=True)


class TestResumeRefusesToInventARun(unittest.TestCase):
    """A mistyped --resume used to create the run directory and carry on.

    It produced a clean result.txt for a run that never happened, wearing the id of a run the
    operator believed they were continuing. The id is the one thing tying a report to its evidence,
    so an unverified id must not be accepted silently.
    """

    def test_an_unknown_run_id_is_refused_and_creates_nothing(self):
        import tempfile
        import shutil
        from autorecon_v8.core import Runner
        from autorecon_v8.cli import apply_profile_defaults, parser
        tmp = tempfile.mkdtemp()
        try:
            args = apply_profile_defaults(parser().parse_args(
                ["127.0.0.1", "--output-dir", tmp, "--dry-run", "--resume", "nosuchrun"]))
            with self.assertRaises(ValueError) as caught:
                Runner(args)
            self.assertIn("nosuchrun", str(caught.exception))
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), [],
                             "a refused --resume left a directory behind")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_the_refusal_names_the_runs_that_do_exist(self):
        import tempfile
        import shutil
        from autorecon_v8.core import Runner
        from autorecon_v8.cli import apply_profile_defaults, parser
        tmp = tempfile.mkdtemp()
        try:
            args = apply_profile_defaults(parser().parse_args(
                ["127.0.0.1", "--output-dir", tmp, "--dry-run"]))
            Runner(args).run()
            args = apply_profile_defaults(parser().parse_args(
                ["127.0.0.1", "--output-dir", tmp, "--dry-run", "--resume", "typo"]))
            with self.assertRaises(ValueError) as caught:
                Runner(args)
            self.assertIn("known runs", str(caught.exception),
                          "the refusal does not tell the operator what they could have typed")
            self.assertIn(Path(tmp, "last").read_text().strip(), str(caught.exception))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_a_real_run_id_is_still_accepted(self):
        import tempfile
        import shutil
        from autorecon_v8.core import Runner
        from autorecon_v8.cli import apply_profile_defaults, parser
        tmp = tempfile.mkdtemp()
        try:
            args = apply_profile_defaults(parser().parse_args(
                ["127.0.0.1", "--output-dir", tmp, "--dry-run"]))
            first = Runner(args)
            first.run()
            rid = first.run_id
            args = apply_profile_defaults(parser().parse_args(
                ["127.0.0.1", "--output-dir", tmp, "--dry-run", "--resume", rid]))
            self.assertEqual(Runner(args).run_id, rid, "a genuine run id was refused")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_last_on_an_empty_output_dir_says_so(self):
        """--resume last with nothing to resume is an error, and it is a loud one.

        It already was, and stays that way: inventing a run is exactly what this change is about.
        """
        import tempfile
        import shutil
        from autorecon_v8.core import Runner
        from autorecon_v8.cli import apply_profile_defaults, parser
        tmp = tempfile.mkdtemp()
        try:
            args = apply_profile_defaults(parser().parse_args(
                ["127.0.0.1", "--output-dir", tmp, "--dry-run", "--resume", "last"]))
            with self.assertRaises(ValueError) as caught:
                Runner(args)
            self.assertIn("resumable", str(caught.exception))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


    def test_a_bare_directory_is_not_a_run(self):
        """Existing is not the same as being a run.

        A directory with the right name but no run-state.json is not something to continue: there is
        no state to reuse and no evidence behind it. Accepting it would produce a result.txt for a run
        that has no record of having done anything.
        """
        import tempfile
        import shutil
        from autorecon_v8.core import Runner
        from autorecon_v8.cli import apply_profile_defaults, parser
        tmp = tempfile.mkdtemp()
        try:
            Path(tmp, "20200101T000000Z-deadbeef").mkdir()
            args = apply_profile_defaults(parser().parse_args(
                ["127.0.0.1", "--output-dir", tmp, "--dry-run",
                 "--resume", "20200101T000000Z-deadbeef"]))
            with self.assertRaises(ValueError) as caught:
                Runner(args)
            self.assertIn("run-state.json", str(caught.exception))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)