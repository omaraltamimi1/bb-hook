"""A resume with different credentials must not reuse the previous run's authenticated results.

Resume invalidated by stage and by --restart-stage, but not by credential state. A resume with a
different cookie jar reused api-discovery wholesale, so a report could mix the previous run's
authenticated probes with the new run's anonymous ones - and nothing in any artifact recorded that a
mix had happened. An access-check candidate derived from that mixture is not evidence of anything.

The credential is identified by a hash of the headers it implies, never by its value, so a state file
can be compared across runs without holding a secret.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from autorecon_v8.cli import apply_profile_defaults, parser
from autorecon_v8.core import AUTH_DEPENDENT_STAGES, Runner, STAGE_IDS, StageState

FIRST = "Cookie: sessionid=jar-one-value\n"
SECOND = "Cookie: sessionid=jar-two-value\n"


def jar(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text(body)
    path.chmod(0o600)
    return path


class TestResumeAcrossCredentials(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(shutil.rmtree, "/dev/shm/autorecon-results", ignore_errors=True)
        self.jars = Path(self.tmp) / "jars"
        self.jars.mkdir()
        self.out = Path(self.tmp) / "runs"
        self.a = jar(self.jars, "a.txt", FIRST)
        self.b = jar(self.jars, "b.txt", SECOND)

    def build(self, credential, resume=None):
        argv = ["127.0.0.1", "--output-dir", str(self.out), "--dry-run",
                "--cookie-file", str(credential)]
        if resume:
            argv += ["--resume", resume]
        run = Runner(apply_profile_defaults(parser().parse_args(argv)))
        run.command = lambda *a, **k: 0
        return run

    def first_run(self):
        run = self.build(self.a)
        # api-discovery only completes when it has an origin to probe, so httpx output is seeded.
        # Without it every authenticated stage skips and there is nothing to invalidate, which would
        # make the invalidation untestable rather than unproven.
        httpx = Path(run.raw) / "httpx" / "normalized.txt"
        httpx.parent.mkdir(parents=True, exist_ok=True)
        httpx.write_text("https://example.com\n")
        run.run()
        self.assertEqual(run.stages["api-discovery"].status, "completed",
                         "the fixture did not complete an authenticated stage")
        return run.run_id

    def test_a_credential_change_invalidates_the_authenticated_stages(self):
        rid = self.first_run()
        run = self.build(self.b, resume=rid)
        run._load()
        self.assertTrue(run.credentials_changed,
                        "a different cookie jar was not detected as a credential change")
        # Only stages that actually produced artifacts have something to invalidate. A stage that
        # never ran has no authenticated result to discard.
        self.assertIn("api-discovery", run.credentials_invalidated,
                      "the fixture did not invalidate an authenticated stage that had completed")
        for sid in run.credentials_invalidated:
            self.assertIn("credentials changed", (run.stages[sid].resume or ""),
                          f"{sid} was invalidated without recording why")
        for sid in AUTH_DEPENDENT_STAGES:
            if sid in run.stages and run.stages[sid].status == "completed":
                self.fail(f"{sid} sent credentials under the old jar and is still marked completed")

    def test_the_same_jar_still_reuses(self):
        """Otherwise every resume re-runs the expensive half of the tool for nothing."""
        rid = self.first_run()
        run = self.build(self.a, resume=rid)
        run._load()
        self.assertFalse(run.credentials_changed, "an unchanged jar was treated as a change")
        self.assertNotIn("credentials changed",
                         (run.stages["api-discovery"].resume or ""),
                         "an unchanged credential invalidated api-discovery anyway")

    def test_credential_change_is_visible_in_run_state(self):
        rid = self.first_run()
        self.build(self.b, resume=rid).run()
        state = json.loads((self.out / rid / "run-state.json").read_text())
        self.assertIn("auth_state", state,
                      "a resume has nothing to compare against without a persisted auth_state")
        for sid in self.build(self.a, resume=rid).credentials_invalidated or ["api-discovery"]:
            if sid in state["stages"]:
                self.assertIn("credentials changed", state["stages"][sid]["resume"],
                              f"{sid} was re-run without recording why, so the re-run is unexplained")

    def test_a_state_file_without_auth_state_does_not_crash_a_resume(self):
        """Runs recorded before auth_state existed are still resumable."""
        rid = self.first_run()
        path = self.out / rid / "run-state.json"
        state = json.loads(path.read_text())
        del state["auth_state"]
        path.write_text(json.dumps(state))
        run = self.build(self.b, resume=rid)
        run._load()
        self.assertFalse(run.credentials_changed,
                         "with no recorded auth_state there is nothing to compare, so nothing is lost")

    def test_target_independent_stages_are_not_invalidated(self):
        """dns and tls never sent a cookie. Re-running them costs time and gains nothing."""
        rid = self.first_run()
        run = self.build(self.b, resume=rid)
        run._load()
        for sid in ("dns", "tls", "dnsx"):
            if sid in run.stages:
                self.assertNotIn("credentials changed", (run.stages[sid].resume or ""),
                                 f"{sid} is target-independent and was invalidated anyway")

    def test_the_auth_state_never_holds_a_credential_value(self):
        rid = self.first_run()
        state = json.loads((self.out / rid / "run-state.json").read_text())
        blob = json.dumps(state)
        self.assertNotIn("jar-one-value", blob, "run-state.json holds a live cookie value")
        self.assertNotIn("jar-two-value", blob, "run-state.json holds a live cookie value")

    def test_anonymous_runs_are_unaffected(self):
        """A run with no credentials has no credential to change."""
        run = Runner(apply_profile_defaults(parser().parse_args(
            ["127.0.0.1", "--output-dir", str(self.out), "--dry-run"])))
        run.command = lambda *a, **k: 0
        rid = run.run_id
        run.run()
        again = self.build(self.a, resume=rid)
        again._load()
        self.assertFalse(again.credentials_changed,
                         "gaining credentials on a resume was treated as a credential change")


if __name__ == "__main__":
    unittest.main(verbosity=2)
