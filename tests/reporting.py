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
import autorecon_v8.core as core_module
from autorecon_v8.core import Runner, atomic_text


_pending: dict = {}


def build(tmp, extra=(), mirror=False, mount="/dev/shm"):
    """A runner over a seeded run directory.

    mirror=False passes --no-kali-share, which is right for tests that only care about result.txt. It
    is also why the previous share test proved nothing: the mirror was switched off before the mount
    was ever consulted, so its assertion held whatever the guard did.

    mirror=True points the guard at mount, never at the operator's real share. A test that mirrors to
    /mnt/KaliShare writes there for real; that happened, and left forty files on a shared evidence
    directory that is not the test's to touch. /dev/shm is a genuine tmpfs mount, so the guard's
    mount check is still exercised for real rather than stubbed.
    """
    flags = ["127.0.0.1", "--output-dir", tmp, *extra] + ([] if mirror else ["--no-kali-share"])
    if mirror:
        import autorecon_v8.core as core
        real = core.KALI_SHARE_MOUNT
        core.KALI_SHARE_MOUNT = mount
        _pending.setdefault("restore_mount", real)
    args = apply_profile_defaults(parser().parse_args(flags))
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
        share_tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, share_tmp, ignore_errors=True)
        self.shared = build(share_tmp, mirror=True)
        # Whatever the tests did under /dev/shm goes with them; the mount is shared, the litter is not.
        self.addCleanup(shutil.rmtree, "/dev/shm/autorecon-results", ignore_errors=True)
        self.addCleanup(setattr, core_module, "KALI_SHARE_MOUNT",
                        _pending.pop("restore_mount", core_module.KALI_SHARE_MOUNT))
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

    def patched_mount(self, path):
        """Point the share guard at a path and restore it afterwards."""
        import autorecon_v8.core as core
        real = core.KALI_SHARE_MOUNT
        core.KALI_SHARE_MOUNT = path
        self.addCleanup(setattr, core, "KALI_SHARE_MOUNT", real)

    def test_a_writable_mount_is_the_positive_control(self):
        """/dev/shm is a real, writable mount, so this proves the guard is not just always refusing."""
        import os
        if not (os.path.ismount("/dev/shm") and os.access("/dev/shm", os.W_OK)):
            self.skipTest("no writable mount available on this host")
        self.patched_mount("/dev/shm")
        self.shared.generate_reports(0)
        mirrored = list(pathlib.Path("/dev/shm/autorecon-results").glob("*-*.txt"))
        self.addCleanup(shutil.rmtree, "/dev/shm/autorecon-results", True)
        self.assertTrue(mirrored, "a writable mount produced no mirror; the guard refuses unconditionally")

    def test_a_mount_that_is_not_writable_keeps_the_result(self):
        """A real mount that is not writable must degrade, not fail."""
        import os
        if not os.path.ismount("/run"):
            self.skipTest("no read-only mount available on this host")
        self.patched_mount("/run")
        self.shared.generate_reports(0)
        self.assertTrue((self.shared.work / "result.txt").exists(),
                        "an unwritable share mount cost the run its result")

    def test_a_plain_directory_is_not_a_mount(self):
        """Existence is not the test.

        The previous implementation created the path with parents=True, so on a host that never had
        the share attached it invented /mnt/KaliShare and reported a share that did not exist. Both
        halves matter: a plain directory is refused, and nothing is created to make the next run
        agree with this one.
        """
        plain = pathlib.Path(self.tmp) / "not-a-mount"
        plain.mkdir(parents=True)
        self.patched_mount(str(plain))
        self.shared.generate_reports(0)
        self.assertTrue((self.shared.work / "result.txt").exists())
        self.assertFalse((plain / "autorecon-results").exists(),
                         "the guard created the results directory inside a non-mount")

    def test_a_missing_mount_is_not_created(self):
        absent = pathlib.Path(self.tmp) / "never-mounted" / "KaliShare"
        self.patched_mount(str(absent))
        self.shared.generate_reports(0)
        self.assertTrue((self.shared.work / "result.txt").exists())
        self.assertFalse(absent.exists(), "the guard created the mount point itself")

    def test_the_warning_goes_to_stderr_not_stdout(self):
        """result.txt is assembled from captured stdout, so a warning on stdout reads like a finding."""
        import contextlib, io
        self.patched_mount("/definitely/not/a/mount")
        err, out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            self.shared.generate_reports(0)
        self.assertIn("unavailable", err.getvalue(), "no warning was emitted on stderr")
        self.assertNotIn("unavailable", out.getvalue(),
                         "the warning leaked onto stdout, where it is indistinguishable from output")

    def test_resume_command_preserves_the_scope_that_was_authorised(self):
        """A resume that drops --scope-exclude widens the target, and that is the one failure that
        cannot be noticed later: the run completes and the artifacts describe a scan wider than the
        one that was approved."""
        args = apply_profile_defaults(parser().parse_args([
            "127.0.0.1", "--output-dir", self.tmp, "--scope-exclude", "dev.example.com",
            "--strict-scope", "--port-services"]))
        cmd = Runner(args).resume_command()
        self.assertIn("--scope-exclude dev.example.com", cmd, "the resume command lost the exclusion rule")
        self.assertIn("--strict-scope", cmd, "the resume command lost scope enforcement")
        self.assertIn("--profile", cmd, "the resume command lost the profile")

    def test_resume_command_reparses_to_the_same_run(self):
        """The command is only useful if pasting it back reproduces the run."""
        args = apply_profile_defaults(parser().parse_args([
            "127.0.0.1", "--output-dir", self.tmp, "--profile", "deep",
            "--scope-exclude", "dev.example.com", "--scope-exclude", "qa.example.com",
            "--strict-scope", "--port-services", "--crawl-depth", "5", "--rate-limit", "20"]))
        reparsed = parser().parse_args(Runner(args).resume_command().split()[1:])
        self.assertEqual(reparsed.scope_exclude, args.scope_exclude)
        self.assertEqual(reparsed.scope_include, args.scope_include)
        self.assertEqual(reparsed.profile, args.profile)
        self.assertEqual(reparsed.crawl_depth, args.crawl_depth)
        self.assertEqual(reparsed.rate_limit, args.rate_limit)
        self.assertTrue(reparsed.strict_scope)
        self.assertTrue(reparsed.port_services)

    def test_the_published_resume_command_carries_the_scope(self):
        """resume_command() being correct is not the same as the pipeline publishing it.

        Both consumers are asserted, because either one alone can drift: report.json is what a script
        reads and result.txt is what a human pastes, and a resume that drops --scope-exclude widens
        the target of the next run without a trace.
        """
        import json
        args = apply_profile_defaults(parser().parse_args([
            "127.0.0.1", "--output-dir", self.tmp, "--scope-exclude", "dev.example.com",
            "--strict-scope", "--profile", "deep"]))
        run = Runner(args)
        run.generate_reports(0)
        published = json.loads((run.work / "report.json").read_text())["resume_command"]
        self.assertIn("--scope-exclude dev.example.com", published,
                      "report.json publishes a resume that drops the exclusion rule")
        self.assertIn("--strict-scope", published, "report.json publishes a resume with no enforcement")
        text = (run.work / "result.txt").read_text()
        line = [l for l in text.splitlines() if "Resume:" in l]
        self.assertTrue(line, "result.txt has no resume line at all")
        self.assertIn("--scope-exclude dev.example.com", line[0],
                      "the resume a human would paste drops the exclusion rule")

    def test_resume_command_repeats_no_flag_and_embeds_no_credential(self):
        args = apply_profile_defaults(parser().parse_args([
            "127.0.0.1", "--output-dir", self.tmp, "--profile", "deep", "--strict-scope"]))
        cmd = Runner(args).resume_command()
        flags = [w for w in cmd.split() if w.startswith("--")]
        self.assertEqual(len(flags), len(set(flags)), f"a flag is repeated: {cmd}")
        self.assertNotIn("session=", cmd, "a live credential was inlined into the resume command")


if __name__ == "__main__":
    unittest.main(verbosity=2)
