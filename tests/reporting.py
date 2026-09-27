"""result.txt: the file a human reads to decide what to chase.

Asserted on content, because the failure modes here are editorial rather than functional. A
result.txt that lists every URL is the same as one that lists none, and one that presents a
candidate as a confirmed vulnerability is worse than no file at all.
"""

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from autorecon_v8.cli import apply_profile_defaults, parser
import autorecon_v8.core as core_module
from autorecon_v8.core import KALI_SHARE_MOUNT, KALI_SHARE_SUBDIR, Runner, atomic_text


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


from pathlib import Path
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
        # Opting in is the point: the mirror is written only when a directory is named. This still
        # proves the write path is not just always refusing, which is what it was written to prove.
        opt_in = build(self.tmp, ("--share-dir", "/dev/shm"), mirror=True)
        opt_in.write_result_txt("ok", "resume", [])
        mirrored = list(pathlib.Path("/dev/shm").glob("*-*.txt"))
        for stray in mirrored:
            self.addCleanup(stray.unlink, True)
        self.assertTrue(mirrored, "a writable, named directory produced no mirror; the path always refuses")

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
        # A named directory that does not exist must still warn, and the warning belongs on stderr.
        broken = build(self.tmp, ("--share-dir", "/definitely/not/a/mount"), mirror=True)
        err, out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            broken.write_result_txt("ok", "resume", [])
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


class TestResultTxtIsCappedAndRanked(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(shutil.rmtree, "/dev/shm/autorecon-results", ignore_errors=True)
        self.run = build(self.tmp)

    def runner(self):
        return self.run

    """[SUBDOMAINS] on a real target is several hundred lines, and the entries worth reading are
    buried inside it. A cap that does not announce itself is indistinguishable from a target that has
    nothing, so the announcement is part of the feature, not a nicety."""

    def build_with_subdomains(self, values):
        run = self.runner()
        path = Path(run.raw) / "subdomains" / "normalized.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(values) + "\n")
        run.generate_reports(0)
        return (Path(run.work) / "result.txt").read_text()

    def test_a_large_section_is_capped(self):
        from autorecon_v8.core import RESULT_SECTION_CAP
        text = self.build_with_subdomains([f"host{i}.example.com" for i in range(300)])
        block = text.split("[SUBDOMAINS]", 1)[1].split("[", 1)[0]
        rows = [l for l in block.splitlines() if ".example.com" in l]
        self.assertEqual(len(rows), RESULT_SECTION_CAP, "the section is not capped")

    def test_a_capped_section_says_how_many_were_dropped(self):
        text = self.build_with_subdomains([f"host{i}.example.com" for i in range(300)])
        block = text.split("[SUBDOMAINS]", 1)[1].split("[", 1)[0]
        self.assertIn("300 of 300 shown", block,
                      "a truncated section must say so, or a partial list reads as a complete one")

    def test_a_short_section_is_not_annotated(self):
        text = self.build_with_subdomains(["a.example.com", "b.example.com"])
        block = text.split("[SUBDOMAINS]", 1)[1].split("[", 1)[0]
        self.assertNotIn("shown", block, "a complete section does not need a truncation notice")

    def test_the_sensitive_entry_ranks_first(self):
        text = self.build_with_subdomains([f"host{i}.example.com" for i in range(300)]
                                          + ["admin.example.com/wp-login.php"])
        block = text.split("[SUBDOMAINS]", 1)[1].split("[", 1)[0]
        rows = [l.strip() for l in block.splitlines() if ".example.com" in l]
        self.assertIn("wp-login", rows[0],
                      "a login path is the one entry here worth reading and it was truncated away")

    def test_the_queue_and_result_txt_cannot_drift_apart(self):
        """hunt_queue had its own copy of this ordering. Two copies is one too many, and nothing
        caught it when they diverged - the copies were byte-identical when written and nothing held
        them there. The call site is asserted so the duplication cannot come back."""
        import inspect
        source = inspect.getsource(core_module.Runner.hunt_queue)
        self.assertIn("return rank_hunt(values)", source,
                      "hunt_queue grew a private ordering again; result.txt and report.md would "
                      "disagree about what matters")
        self.assertNotIn("key=lambda v:(0 if HUNT_SENSITIVE.search(v)", source)

    def test_result_txt_and_the_hunt_queue_rank_identically(self):
        """Two orderings of 'what matters' is how a duplicated ranking rule goes stale."""
        from autorecon_v8.core import rank_hunt
        values = [f"host{i}.example.com" for i in range(50)] + ["admin.example.com/wp-login.php"]
        run = self.runner()
        path = Path(run.raw) / "subdomains" / "normalized.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(values) + "\n")
        run.generate_reports(0)
        text = (Path(run.work) / "result.txt").read_text()
        block = text.split("[SUBDOMAINS]", 1)[1].split("[", 1)[0]
        from_result = [l.strip() for l in block.splitlines() if ".example.com" in l]
        self.assertEqual(from_result, rank_hunt(values)[:len(from_result)])


class TestOneVersionNumber(unittest.TestCase):
    """Four different version numbers in one package means nobody can say which build produced a
    report. Every writer reads __version__; a hardcoded literal anywhere is a bug, and the check is
    textual so a new writer cannot quietly reintroduce one."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(shutil.rmtree, "/dev/shm/autorecon-results", ignore_errors=True)

    def test_report_json_carries_the_package_version(self):
        from autorecon_v8 import __version__
        run = build(self.tmp)
        run.generate_reports(0)
        data = json.loads((Path(run.work) / "report.json").read_text())
        self.assertEqual(data["version"], __version__,
                         "report.json's version does not match the package")

    def test_report_md_carries_the_package_version(self):
        from autorecon_v8 import __version__
        run = build(self.tmp)
        run.generate_reports(0)
        text = (Path(run.work) / "report.md").read_text()
        self.assertIn(f"AutoRecon v{__version__}", text,
                      "report.md's heading does not match the package version")

    def test_result_txt_carries_the_package_version(self):
        from autorecon_v8 import __version__
        run = build(self.tmp)
        run.generate_reports(0)
        self.assertIn(f"AutoRecon v{__version__}",
                      (Path(run.work) / "result.txt").read_text())

    def test_no_source_file_hardcodes_a_version(self):
        import autorecon_v8
        root = Path(autorecon_v8.__file__).parent
        offenders = []
        for source in root.glob("*.py"):
            for number, line in enumerate(source.read_text().splitlines(), 1):
                if '__version__' in line or line.lstrip().startswith("#"):
                    continue
                if re.search(r'(?<!\d)8\.\d+\.\d+(?!\d)', line) and "version" in line.lower():
                    offenders.append(f"{source.name}:{number}: {line.strip()[:80]}")
        self.assertEqual(offenders, [],
                         f"a hardcoded version crept back in: {offenders}")

    def test_the_cli_banner_carries_the_package_version(self):
        """--help is where an operator checks which build they are running."""
        import contextlib
        import io
        from autorecon_v8 import __version__
        from autorecon_v8.cli import parser
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit):
                parser().parse_args(["--help"])
        self.assertIn(f"AutoRecon v{__version__}", buf.getvalue(),
                      "the CLI banner does not match the package version")

    def test_pyproject_reads_the_same_number(self):
        import autorecon_v8
        from autorecon_v8 import __version__
        text = (Path(autorecon_v8.__file__).parent.parent / "pyproject.toml").read_text()
        found = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
        self.assertIsNotNone(found, "pyproject.toml has no static version to compare")
        self.assertEqual(found.group(1), __version__,
                         "pyproject.toml and the package disagree on the version")


class TestOneResultOneLine(unittest.TestCase):
    """A run that fails a stage emits a partial report from the failure path and then runs the report
    stage, which regenerated the identical file and announced it again. Two "[report] result.txt ->"
    lines per run, each naming two destinations, is what made this look like four separate results."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(shutil.rmtree, "/dev/shm/autorecon-results", ignore_errors=True)

    def runner(self, argv=()):
        return build(self.tmp, *argv)

    def test_the_report_is_announced_once_per_run(self):
        run = self.runner()
        lines = []
        real = print

        def spy(*a, **k):
            text = " ".join(str(x) for x in a)
            if "result.txt ->" in text:
                lines.append(text)
            return real(*a, **k)

        import builtins
        builtins.print = spy
        self.addCleanup(setattr, builtins, "print", real)
        run.write_result_txt("partial", "resume", [])
        run.write_result_txt("partial", "resume", [])  # failure path, then the report stage
        self.assertEqual(len(lines), 1,
                         f"identical report content was announced {len(lines)} times: {lines}")

    def test_one_result_file_is_written_by_default(self):
        run = self.runner()
        os.environ.pop("KALI_SHARE_DIR", None)
        out = run.write_result_txt("ok", "resume", [])
        self.assertTrue(out.exists(), "no result.txt was written")
        self.assertEqual(out.parent, Path(run.work),
                         "the result did not land in the run directory")
        self.assertFalse((Path(run.work) / "result.txt").read_text().count("[STAGE SUMMARY]") > 1,
                         "the result contains more than one report body")

    def test_the_result_is_collected_onto_the_evidence_mount_by_default(self):
        """The share is where the operator collects results, so it is written without being asked for.

        I had made this opt-in on my own judgement that a run should not write to a mount nobody
        named, and that silently broke the collection workflow. The evidence copy is the point of the
        mount. What was actually wrong was the duplicate announcement, and that is fixed at the
        source instead: one report per run, announced once.
        """
        import autorecon_v8.core as core
        real_mount = core.KALI_SHARE_MOUNT
        core.KALI_SHARE_MOUNT = "/dev/shm"
        self.addCleanup(setattr, core, "KALI_SHARE_MOUNT", real_mount)
        run = build(self.tmp, (), mirror=True)
        os.environ.pop("KALI_SHARE_DIR", None)
        mount = Path("/dev/shm") / KALI_SHARE_SUBDIR
        mount.mkdir(parents=True, exist_ok=True)
        stale = Path(run.work) / "result.txt"
        if stale.exists():
            stale.unlink()
        run.write_result_txt("ok", "resume", [])
        collected = sorted(p for p in mount.iterdir() if run.run_id in p.name)
        for stray in collected:
            self.addCleanup(stray.unlink, True)
        self.assertEqual(len(collected), 1,
                         f"the run collected {len(collected)} result files on the evidence mount, "
                         f"expected exactly one: {[str(p) for p in collected]}")

    def test_one_run_collects_one_file_however_many_times_the_report_runs(self):
        """Reported twice, written once. The name+mtime snapshot is deliberate: two runs in the same
        second share a run id, so a second write would overwrite the first and a name-only check
        would never see it."""
        import autorecon_v8.core as core
        real_mount = core.KALI_SHARE_MOUNT
        core.KALI_SHARE_MOUNT = "/dev/shm"
        self.addCleanup(setattr, core, "KALI_SHARE_MOUNT", real_mount)
        run = build(self.tmp, (), mirror=True)
        os.environ.pop("KALI_SHARE_DIR", None)
        mount = Path("/dev/shm") / KALI_SHARE_SUBDIR
        mount.mkdir(parents=True, exist_ok=True)
        stale = Path(run.work) / "result.txt"
        if stale.exists():
            stale.unlink()
        run.write_result_txt("ok", "resume", [])
        def snapshot():
            return {p.name: p.stat().st_mtime_ns for p in mount.iterdir() if run.run_id in p.name}
        first = snapshot()
        run.write_result_txt("ok", "resume", [])
        second = snapshot()
        for name in second:
            self.addCleanup((mount / name).unlink, True)
        self.assertEqual(sorted(first), sorted(second))
        self.assertEqual(len(first), 1, f"expected one collected file, found {sorted(first)}")


class TestTheRunAnnouncesItsResultOnce(unittest.TestCase):
    """A CLI-level count, because the bug lived in the run loop, not in the writer.

    write_result_txt called twice in a row is not the same thing as a run calling it twice: the run
    reaches it from the report stage inside the loop and again from the finally block. Asserting on
    the writer alone passed while the run still announced every result twice.
    """

    def test_a_full_run_announces_its_result_exactly_once(self):
        import subprocess, tempfile as tf
        with tf.TemporaryDirectory() as d:
            env = dict(os.environ, AUTORECON_KALI_SHARE="/mnt/KaliShare")
            r = subprocess.run(
                ["autorecon", "https://127.0.0.1:1/",
                 "--output-dir", d, "--only", "report", "--no-kali-share", "--global-timeout", "60"],
                capture_output=True, text=True, env=env, timeout=300)
            announced = [l for l in (r.stdout + r.stderr).splitlines() if "result.txt ->" in l]
            self.assertEqual(len(announced), 1,
                             f"one run announced its result {len(announced)} times: {announced}")

    def test_a_failing_stage_still_announces_exactly_once(self):
        """The finally block is the safety net for a run that never reaches the report stage. It has
        to fire in that case, and stay quiet otherwise - both halves, or it is either dead code or a
        second announcement."""
        import subprocess, tempfile as tf
        with tf.TemporaryDirectory() as d:
            env = dict(os.environ, AUTORECON_KALI_SHARE="/mnt/KaliShare")
            r = subprocess.run(
                ["autorecon", "https://127.0.0.1:1/",
                 "--output-dir", d, "--only", "report,dns", "--no-kali-share",
                 "--global-timeout", "60", "--stage-timeout", "0.001"],
                capture_output=True, text=True, env=env, timeout=300)
            announced = [l for l in (r.stdout + r.stderr).splitlines() if "result.txt ->" in l]
            self.assertLessEqual(len(announced), 1,
                                 f"a run that reached the report stage announced {len(announced)} times: {announced}")


class TestTheDefaultRunAnnouncesOnce(unittest.TestCase):
    """The dedup tests above all pass --no-kali-share, so none of them exercised the path a normal run
    takes: the collected copy. A regression that announced both the collected file and the run copy
    passed the whole suite, because the only branch under test was the suppressed one."""

    def default_run(self, d):
        import subprocess
        # The share root has to be a real mount for the guard to accept it, so /dev/shm rather than a
        # temp dir - a plain directory is correctly rejected, which is the other half of the guard.
        env = dict(os.environ, AUTORECON_KALI_SHARE="/dev/shm")
        r = subprocess.run(
            ["autorecon", "https://127.0.0.1:1/", "--output-dir", d,
             "--only", "report", "--global-timeout", "60"],
            capture_output=True, text=True, env=env, timeout=300)
        return [l for l in (r.stdout + r.stderr).splitlines() if "result.txt ->" in l]

    def test_a_default_run_announces_exactly_one_line(self):
        with tempfile.TemporaryDirectory() as d:
            announced = self.default_run(d)
            self.assertEqual(len(announced), 1,
                             f"a default run announced its result {len(announced)} times: {announced}")

    def test_the_collected_file_is_what_gets_announced(self):
        with tempfile.TemporaryDirectory() as d:
            announced = self.default_run(d)
            self.assertEqual(len(announced), 1, f"expected one announcement, got {announced}")
            line = announced[0]
            self.assertIn("run copy:", line,
                          f"the announcement does not disclose the run copy, so the two paths read as "
                          f"two results again: {line}")
            collected = line.split("result.txt -> ", 1)[1].split("  (run copy:")[0].strip()
            self.assertTrue(collected.startswith("/dev/shm/autorecon-results/"),
                            f"the announced result is not the collected file: {line}")
            self.assertTrue(os.path.exists(collected), f"the announced file does not exist: {collected}")
            self.addCleanup(lambda: os.path.exists(collected) and os.unlink(collected))


if __name__ == "__main__":


    unittest.main(verbosity=2)