"""DAG honesty: the dependency graph and the artifact-level data flow must not disagree.

Two defects are pinned here. The metadata understated the graph - access-checks read four producers
while claiming one - so reports and --list-stages misrepresented the pipeline. And a consumer that
ran without its inputs reported a clean "0 candidates", which is the worst shape a false negative
can take: it looks like a result rather than an absence of one.
"""

import contextlib
import io
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

from autorecon_v8.cli import apply_profile_defaults, parser
from autorecon_v8.core import DEPS, STAGE_IDS, STAGE_INPUTS, Runner, missing_inputs


class GraphConsistency(unittest.TestCase):
    """DEPS must be derivable from STAGE_INPUTS, or the two will drift again."""

    def test_every_declared_producer_is_a_real_stage(self):
        for stage, inputs in STAGE_INPUTS.items():
            for producer, _ in inputs:
                self.assertIn(producer, STAGE_IDS,
                              f"{stage} declares input from unknown stage {producer}")
                self.assertNotEqual(producer, stage, f"{stage} declares itself as its own input")

    def test_deps_include_every_declared_producer(self):
        for stage, inputs in STAGE_INPUTS.items():
            for producer, _ in inputs:
                self.assertIn(producer, DEPS[stage],
                              f"DEPS[{stage}] omits producer {producer}; the graph understates it")

    def test_access_checks_declares_all_five_of_its_inputs(self):
        self.assertEqual(
            {stage for stage, _ in STAGE_INPUTS["access-checks"]},
            {"corpus", "arjun", "ffuf", "web-intelligence"},
        )
        self.assertIn("arjun", DEPS["access-checks"])
        self.assertIn("ffuf", DEPS["access-checks"])
        self.assertIn("web-intelligence", DEPS["access-checks"])

    def test_consumer_is_derived_from_the_table_not_restated(self):
        self.assertEqual(Runner.ACCESS_CHECK_INPUTS, STAGE_INPUTS["access-checks"])

    def test_deps_reference_only_real_stages(self):
        for stage, deps in DEPS.items():
            for dep in deps:
                self.assertIn(dep, STAGE_IDS, f"DEPS[{stage}] names unknown stage {dep}")


class MissingInputDetection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.raw = pathlib.Path(self.tmp) / "raw"
        self.raw.mkdir(parents=True, exist_ok=True)

    def test_absent_directory_counts_as_missing(self):
        self.assertEqual(
            sorted(missing_inputs(self.raw, "access-checks")),
            ["arjun/params.txt", "corpus/api.txt", "corpus/params.txt",
             "ffuf/paths.txt", "web-intelligence/endpoints.txt"],
        )

    def test_present_but_empty_file_counts_as_missing(self):
        """An input file that exists but is empty is not an input: a stage that reads it learns nothing."""
        for stage, name in (("corpus", "params.txt"), ("corpus", "api.txt"),
                            ("arjun", "params.txt"), ("ffuf", "paths.txt"),
                            ("web-intelligence", "endpoints.txt")):
            (self.raw / stage).mkdir(parents=True, exist_ok=True)
            (self.raw / stage / name).write_text("")
        self.assertEqual(
            sorted(missing_inputs(self.raw, "access-checks")),
            ["arjun/params.txt", "corpus/api.txt", "corpus/params.txt",
             "ffuf/paths.txt", "web-intelligence/endpoints.txt"],
        )

    def test_whitespace_only_file_counts_as_missing(self):
        (self.raw / "corpus").mkdir(parents=True, exist_ok=True)
        (self.raw / "corpus" / "params.txt").write_text("\n   \n\n")
        self.assertIn("corpus/params.txt", missing_inputs(self.raw, "access-checks"))

    def test_populated_file_is_not_missing(self):
        (self.raw / "corpus").mkdir(parents=True, exist_ok=True)
        (self.raw / "corpus" / "params.txt").write_text("https://example.com/a\n")
        self.assertNotIn("corpus/params.txt", missing_inputs(self.raw, "access-checks"))

    def test_undeclared_stage_reports_nothing(self):
        self.assertEqual(missing_inputs(self.raw, "dns"), [])


class AbsentInputIsReported(unittest.TestCase):
    """A zero-candidate result must say whether its inputs existed."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cookie = pathlib.Path(self.tmp) / "a.txt"
        self.cookie.write_text("Cookie: session=A\n")

    def run_stage(self, seed_params):
        args = apply_profile_defaults(parser().parse_args([
            "127.0.0.1", "--strict-scope", "--scope-include", "127.0.0.1",
            "--output-dir", self.tmp, "--cookie-file", str(self.cookie)]))
        subprocess.run([sys.executable, "-m", "autorecon_v8", "127.0.0.1", "--dry-run",
                        "--only", "httpx", "--output-dir", self.tmp], capture_output=True, timeout=180)
        args.resume = (pathlib.Path(self.tmp) / "last").read_text().strip()
        run = Runner(args)
        raw = pathlib.Path(run.raw)
        (raw / "corpus").mkdir(parents=True, exist_ok=True)
        (raw / "corpus" / "params.txt").write_text(seed_params)
        st = run.stages["access-checks"]
        st.status = "pending"
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            run.access_checks_stage(st, run.global_deadline)
        return st, json.loads((raw / "access-checks" / "findings.json").read_text()), buf.getvalue()

    def test_absent_inputs_are_named_in_the_warning(self):
        st, findings, logged = self.run_stage("")
        self.assertIn("declared input(s) absent or empty", logged)
        for absent in ("arjun/params.txt", "ffuf/paths.txt", "web-intelligence/endpoints.txt"):
            self.assertIn(absent, logged)

    def test_findings_record_completeness(self):
        st, findings, _ = self.run_stage("")
        self.assertFalse(findings["inputs_complete"])
        self.assertIn("corpus/api.txt", findings["declared_inputs_missing"])

    def test_main_path_warns_when_candidates_exist_but_producers_are_missing(self):
        """
        The more important shape: there IS something to probe, so the stage runs, and a reader
        would reasonably take an empty candidate list as a real result. The three discovery
        producers are absent, which is exactly what --only, --from or a skipped stage produces.
        """
        st, findings, logged = self.run_stage("http://127.0.0.1:1/api/v1/x\n")
        # The stage probes and then completes with no real candidates, which is precisely the
        # shape a reader would mistake for a clean result.
        self.assertNotEqual(st.status, "skipped", "expected the stage to actually probe")
        self.assertGreater(st.processed, 0)
        self.assertEqual(st.status, "completed")
        for absent in ("arjun/params.txt", "ffuf/paths.txt", "web-intelligence/endpoints.txt"):
            self.assertIn(absent, logged, f"the main path did not name {absent}")
            self.assertIn(absent, findings["declared_inputs_missing"])
        self.assertFalse(findings["inputs_complete"])
        self.assertIn("not evidence of safety", logged)
        self.assertIn("not evidence of safety", st.failure_reason or "")

    def test_main_path_absent_inputs_survive_alongside_a_real_candidate(self):
        """A refusal note and an input gap must both survive; neither may overwrite the other."""
        st, findings, logged = self.run_stage("http://127.0.0.1:1/api/v1/x\n")
        reason = st.failure_reason or ""
        self.assertIn("declared input(s) absent or empty", reason)
        self.assertIn("not evidence of safety", reason)

    def test_skip_path_declares_the_findings_it_wrote(self):
        """An artifact that exists but is not in st.outputs is invisible to anything reading the report."""
        st, findings, _ = self.run_stage("")
        target = pathlib.Path(self.tmp) / st.id if False else None
        self.assertTrue(findings["skipped"])
        self.assertTrue(findings["inputs_complete"] is False)
        self.assertEqual(st.status, "skipped")
        self.assertTrue(any(p.endswith("findings.json") for p in st.outputs),
                        f"findings.json was written but not declared: {st.outputs}")
        self.assertTrue(any(p.endswith("normalized.txt") for p in st.outputs))

    def test_skipped_stage_still_records_its_disclaimer(self):
        st, findings, _ = self.run_stage("")
        self.assertIn("not evidence", findings["disclaimer"])
        self.assertIn("no verdict was formed", findings["disclaimer"])

    def test_stage_reason_says_a_zero_result_is_not_safety(self):
        st, _, _ = self.run_stage("")
        self.assertIn("not evidence of safety", st.failure_reason or "")

    def test_complete_inputs_report_complete(self):
        st, findings, logged = self.run_stage("https://example.com/a\n")
        # the other three producers are still absent in this fixture, so completeness must be false
        self.assertFalse(findings["inputs_complete"])

    def test_fully_seeded_run_reports_complete_and_no_warning(self):
        args = apply_profile_defaults(parser().parse_args([
            "127.0.0.1", "--strict-scope", "--scope-include", "127.0.0.1",
            "--output-dir", self.tmp, "--cookie-file", str(self.cookie)]))
        subprocess.run([sys.executable, "-m", "autorecon_v8", "127.0.0.1", "--dry-run",
                        "--only", "httpx", "--output-dir", self.tmp], capture_output=True, timeout=180)
        args.resume = (pathlib.Path(self.tmp) / "last").read_text().strip()
        run = Runner(args)
        raw = pathlib.Path(run.raw)
        for stage, name, body in (("corpus", "params.txt", "https://example.com/a\n"),
                                  ("corpus", "api.txt", "https://example.com/api\n"),
                                  ("arjun", "params.txt", "https://example.com/a?q=1\n"),
                                  ("ffuf", "paths.txt", "https://example.com/admin\n"),
                                  ("web-intelligence", "endpoints.txt", "https://example.com/x\n")):
            (raw / stage).mkdir(parents=True, exist_ok=True)
            (raw / stage / name).write_text(body)
        st = run.stages["access-checks"]
        st.status = "pending"
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            run.access_checks_stage(st, run.global_deadline)
        findings = json.loads((raw / "access-checks" / "findings.json").read_text())
        self.assertTrue(findings["inputs_complete"])
        self.assertEqual(findings["declared_inputs_missing"], [])
        self.assertNotIn("declared input(s) absent", buf.getvalue())
        self.assertNotIn("not evidence of safety", st.failure_reason or "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
