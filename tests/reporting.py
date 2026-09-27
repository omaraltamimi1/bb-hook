"""result.txt: the file a human reads to decide what to chase.

Asserted on content, because the failure modes here are editorial rather than functional. A
result.txt that lists every URL is the same as one that lists none, and one that presents a
candidate as a confirmed vulnerability is worse than no file at all.
"""

import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

from autorecon_v8.cli import apply_profile_defaults, parser
from autorecon_v8.core import Runner, atomic_text


def build(tmp, extra=()):
    args = apply_profile_defaults(parser().parse_args(
        ["127.0.0.1", "--output-dir", tmp, "--no-kali-share", *extra]))
    subprocess.run([sys.executable, "-m", "autorecon_v8", "127.0.0.1", "--dry-run",
                    "--only", "httpx", "--output-dir", tmp], capture_output=True, timeout=180)
    args.resume = (pathlib.Path(tmp) / "last").read_text().strip()
    return Runner(args)


def seed(run, stages):
    raw = pathlib.Path(run.raw)
    for stage, body in stages.items():
        (raw / stage).mkdir(parents=True, exist_ok=True)
        (raw / stage / "normalized.txt").write_text("\n".join(body) + "\n")
    return raw


class AtomicText(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_writes_and_replaces(self):
        target = pathlib.Path(self.tmp) / "r.txt"
        atomic_text(target, "first")
        self.assertEqual(target.read_text(), "first")
        atomic_text(target, "second")
        self.assertEqual(target.read_text(), "second")

    def test_leaves_no_temp_files_behind(self):
        target = pathlib.Path(self.tmp) / "r.txt"
        atomic_text(target, "x")
        self.assertEqual([p.name for p in pathlib.Path(self.tmp).iterdir()], ["r.txt"])

    def test_creates_missing_parents(self):
        target = pathlib.Path(self.tmp) / "deep" / "nested" / "r.txt"
        atomic_text(target, "x")
        self.assertTrue(target.exists())


class ResultTxt(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.run = build(self.tmp)
        self.raw = seed(self.run, {
            "dns": ["example.com 3600 IN A 1.2.3.4"],
            "subdomains": ["api.example.com"],
            "dnsx": ["example.com"],
            "httpx": ["https://example.com"],
            "ports": ["example.com:443"],
            "crawl": ["https://example.com/app"],
            "ffuf": ["https://example.com/admin"],
            "web-intelligence": ["https://example.com/api/v1/internal/accounts"],
        })
        (self.raw / "corpus").mkdir(parents=True, exist_ok=True)
        (self.raw / "corpus" / "normalized.txt").write_text(
            "https://example.com/.env\nhttps://example.com/about\n")

    def result(self):
        self.run.generate_reports(0)
        return (self.run.work / "result.txt").read_text()

    def test_is_written_on_report_generation(self):
        # The seeding run already executes the report stage, so this asserts the file is
        # regenerated and stays current rather than that it appears from nothing.
        self.result()
        target = self.run.work / "result.txt"
        self.assertTrue(target.exists())
        before = target.stat().st_mtime_ns
        target.write_text("stale")
        self.result()
        self.assertNotEqual(target.read_text(), "stale", "report generation did not rewrite result.txt")
        self.assertGreaterEqual(target.stat().st_mtime_ns, before)

    def test_header_identifies_target_run_and_status(self):
        text = self.result()
        self.assertIn("example.com", text)
        self.assertIn(self.run.run_id, text)
        self.assertIn("Status", text)

    def test_only_non_empty_sections_appear(self):
        """Zero-noise rule: a section with nothing in it is omitted, not shown empty."""
        text = self.result()
        for present in ("DNS RECORDS", "SUBDOMAINS", "LIVE HOSTS", "OPEN PORTS",
                        "DISCOVERED PATHS", "DISCOVERED ENDPOINTS", "STAGE SUMMARY"):
            self.assertIn(present, text, f"{present} missing despite having content")
        # javascript and arjun produced nothing, so their sections must not appear
        self.assertNotIn("[JAVASCRIPT", text)
        self.assertNotIn("[ARJUN", text)

    def test_high_value_urls_included_and_ordinary_ones_excluded(self):
        text = self.result()
        self.assertIn("/.env", text)
        self.assertNotIn("/about", text, "an ordinary page crowded the interesting-URL section")

    def test_candidate_sections_are_labelled_as_candidates(self):
        text = self.result()
        # The access-check section is absent here because no candidates were seeded, which is the
        # zero-noise rule working. Its populated form is asserted separately.
        self.assertNotIn("ACCESS-CHECK CANDIDATES", text)
        self.assertIn("DISCOVERED PATHS (ffuf candidates)", text)
        self.assertIn("DISCOVERED ENDPOINTS (web-intelligence candidates)", text)
        self.assertIn("Every item above is a candidate", text)

    def test_resume_command_is_included(self):
        self.assertIn("--resume", self.result())

    def test_never_run_stages_are_omitted_but_skipped_ones_are_not(self):
        """
        A stage that never executed is omitted; a stage that ran and decided to skip is kept,
        because "skipped, and here is why" is information an operator needs.
        """
        self.run.stages["corpus"].status = "completed"
        self.run.stages["corpus"].processed = 2
        self.run.stages["corpus"].runtime_seconds = 1.0
        self.run.stages["javascript"].status = "pending"
        self.run.stages["javascript"].failure_reason = None
        text = self.result()
        self.assertIn("corpus", text)
        self.assertNotIn("javascript", text, "a never-run stage appeared in the summary table")
        self.assertIn("screenshots", text, "a skipped stage was wrongly hidden from the summary")

    def test_a_failure_reason_is_shown_next_to_its_stage(self):
        st = self.run.stages["ffuf"]
        st.status = "partial"
        st.failure_reason = "1 of 2 origins exceeded maxtime"
        st.runtime_seconds = 120.0
        self.assertIn("1 of 2 origins exceeded maxtime", self.result())

    def test_access_check_candidates_are_surfaced_with_severity(self):
        ac = self.raw / "access-checks"
        ac.mkdir(parents=True, exist_ok=True)
        ac.joinpath("anomalies.tsv").write_text(
            "url\tsignal\tseverity\tconfidence\tfalse_positive_risk\tdetail\tverify\n"
            "https://example.com/api/v1/tenants/A/records/101\tidentical_across_identities"
            "\thigh\tmedium\ttwo identities may be the same account"
            "\tidentity-a and identity-b both returned 200 with an identical 290-byte body\t"
            "confirm a and b are distinct\n")
        ac.joinpath("suppressed.tsv").write_text(
            "url\tsignal\treason\nhttps://example.com/private/dashboard\tauth_required\tnone\n")
        text = self.result()
        self.assertIn("identical_across_identities", text)
        self.assertIn("[high/medium]", text)
        self.assertIn("SUPPRESSED AS CORRECT BEHAVIOUR", text)
        self.assertIn("1 route(s)", text)

    def test_no_share_flag_suppresses_the_mirror(self):
        self.result()
        self.assertTrue((self.run.work / "result.txt").exists())

    def test_share_mirror_failure_does_not_lose_the_result(self, ):
        """A missing mount must never fail a run that already has its result on disk."""
        import autorecon_v8.core as core
        real = core.KALI_SHARE_RESULTS
        core.KALI_SHARE_RESULTS = "/proc/definitely-not-writable/share"
        self.addCleanup(setattr, core, "KALI_SHARE_RESULTS", real)
        args = apply_profile_defaults(parser().parse_args(["127.0.0.1", "--output-dir", self.tmp]))
        subprocess.run([sys.executable, "-m", "autorecon_v8", "127.0.0.1", "--dry-run",
                        "--only", "httpx", "--output-dir", self.tmp], capture_output=True, timeout=180)
        args.resume = (pathlib.Path(self.tmp) / "last").read_text().strip()
        run = Runner(args)
        run.generate_reports(0)
        self.assertTrue((run.work / "result.txt").exists(),
                        "an unwritable share mount cost the run its result")


if __name__ == "__main__":
    unittest.main(verbosity=2)
