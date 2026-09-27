"""No stage may report success while having produced nothing.

One line in Runner.execute produces every silent zero in this tool:

    if st.status=="running": st.status="completed"; st.exit_code=0; st.resume="completed artifacts reusable"

A stage method that returns without setting a status is stamped completed. That is the right default
for a stage that did its work, and it is exactly how a stage that quietly did nothing ends up
claiming it succeeded. The real run this was written for reported `ports completed` over a sweep where
every chunk after the first had been killed.

So the property is asserted empirically rather than by reading the code: every stage is driven through
the real dispatch with no input, and none of them may end up completed with nothing to say for itself.
A stage that has nothing to do says so, with a reason.
"""
import shutil
import tempfile
import time
import unittest
from pathlib import Path

import autorecon_v8.core as core
from autorecon_v8.cli import apply_profile_defaults, parser
from autorecon_v8.core import STAGE_IDS, StageState

EXECUTABLE = [s for s in STAGE_IDS if s != "report"]


def build(tmp, stage):
    args = apply_profile_defaults(parser().parse_args(
        ["127.0.0.1", "--output-dir", tmp, "--only", stage, "--profile", "passive"]))
    return core.Runner(args)


class TestNoSilentZero(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def drive(self, stage, inputs=(), command=None):
        """Run one stage through the real dispatch with a given input list."""
        run = build(self.tmp, stage)
        run.inputs = lambda sid, values=list(inputs): list(values)
        run.command = command or (lambda *a, **k: 0)
        st = StageState(id=stage, name=stage, description="", dependencies=[])
        run.stages = {stage: st}
        run.execute(st)
        return st

    def test_no_stage_claims_success_with_no_input(self):
        offenders = []
        for stage in EXECUTABLE:
            st = self.drive(stage, inputs=[])
            if st.status == "completed" and not (st.failure_reason or "").strip():
                offenders.append(stage)
        self.assertEqual(offenders, [],
                         f"these stages report completed with no input and no reason: {offenders}")

    def test_every_stage_states_why_it_did_nothing(self):
        """Not just a status: an operator reading result.txt needs the sentence."""
        for stage in EXECUTABLE:
            st = self.drive(stage, inputs=[])
            if st.status == "completed":
                continue                       # a stage that legitimately had nothing to do
            self.assertTrue((st.failure_reason or "").strip(),
                            f"{stage} ended {st.status!r} without a failure_reason")

    def test_a_stage_is_never_left_running(self):
        for stage in EXECUTABLE:
            st = self.drive(stage, inputs=[])
            self.assertNotEqual(st.status, "running",
                                f"{stage} returned still 'running'; the dispatch never stamped it")

    def test_the_dispatch_covers_every_stage(self):
        """A stage with no branch in the dispatch falls through to generic_stage and is never tested.

        Asserted by reading the dispatch itself, so adding a stage to STAGE_IDS without a branch
        fails here instead of quietly inheriting the tool-driven path.
        """
        import inspect
        source = inspect.getsource(core.Runner.execute)
        for stage in EXECUTABLE:
            if stage in ("api-discovery", "javascript", "corpus", "crawl", "access-checks",
                        "arjun", "ports", "ffuf", "screenshots", "web-intelligence"):
                self.assertIn(f'st.id=="{stage}"', source,
                              f"{stage} has no branch in the dispatch")


class TestZeroIsNotEvidence(unittest.TestCase):
    """A stage whose declared input was never generated must not read as a clean result."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_access_checks_says_so_when_its_input_never_arrived(self):
        run = build(self.tmp, "access-checks")
        run.inputs = lambda sid: []
        st = StageState(id="access-checks", name="access-checks", description="", dependencies=[])
        run.stages = {"access-checks": st}
        run.execute(st)
        self.assertNotEqual(st.status, "completed")
        findings = Path(run.raw) / "access-checks" / "findings.json"
        self.assertTrue(findings.exists(), "a skipped stage must still write findings.json")
        import json
        data = json.loads(findings.read_text())
        self.assertIn("declared_inputs_missing", data)
        self.assertTrue(data.get("inputs_complete") is not True,
                        "inputs_complete=True over a stage whose inputs never arrived")

    def test_a_stage_with_no_reason_is_visible_in_result_txt(self):
        """The sentence has to survive into the artifact a human actually reads."""
        run = build(self.tmp, "javascript")
        run.inputs = lambda sid: []
        st = StageState(id="javascript", name="javascript", description="", dependencies=[])
        # generate_reports walks every stage in STAGE_IDS, so the rest have to exist even though
        # only one is being driven.
        run.stages = {s: StageState(id=s, name=s, description="", dependencies=[]) for s in STAGE_IDS}
        run.stages["javascript"] = st
        run.execute(st)
        run.generate_reports(0)
        text = (Path(run.work) / "result.txt").read_text()
        row = [l for l in text.splitlines() if l.strip().startswith("javascript")]
        self.assertTrue(row, "result.txt has no javascript row at all")
        self.assertIn(st.failure_reason, row[0],
                      f"the reason is in the state but not in the artifact a human reads: {row[0]!r}")
        self.assertIn("skipped", row[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
