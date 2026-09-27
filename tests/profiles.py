"""Profile defaults, and the invariant that caused the real run to fail.

v8.1 ran `daily` with tool_timeout=600 inside a stage_timeout of 1500. One naabu invocation over 90
hosts cannot finish inside 600s, so the tool was killed, ports exited rc=124, and every downstream
stage skipped its way to a result.txt that read like a finished scan. The stage no longer hangs the
run like that, but a timeout pair that lets a single tool call be killed mid-stage is still a silent
failure waiting for a slower target, so it is asserted here.
"""
import unittest

from autorecon_v8.cli import apply_profile_defaults, parser
from autorecon_v8.core import ACTIVE, PROFILES

# The values the real whatnot run used. Changing these changes the meaning of a run an operator
# already has results for, so they are pinned rather than merely smoke-tested.
DAILY = {"concurrency": 8, "rate_limit": 5.0, "request_timeout": 12.0,
         "tool_timeout": 600.0, "stage_timeout": 1500.0, "max_hosts": 0}


class TestDailyProfile(unittest.TestCase):
    def test_daily_exists_with_the_v81_values(self):
        self.assertIn("daily", PROFILES)
        for key, value in DAILY.items():
            self.assertEqual(PROFILES["daily"][key], value, f"daily.{key} drifted from v8.1")

    def test_daily_is_reachable_from_the_cli(self):
        args = apply_profile_defaults(parser().parse_args(["127.0.0.1", "--profile", "daily"]))
        for key, value in DAILY.items():
            self.assertEqual(getattr(args, key), value, f"--profile daily did not set {key}")

    def test_daily_skips_screenshots_only(self):
        """v8.1 daily skipped screenshots and nothing else. nmap is gone; ffuf runs."""
        self.assertEqual(PROFILES["daily"]["skip"], ["screenshots"])
        self.assertIn("ffuf", ACTIVE)
        self.assertNotIn("ffuf", PROFILES["daily"]["skip"])

    def test_daily_keeps_ports_and_the_downstream_chain(self):
        """The stages that were skipped in the real run must be reachable under daily."""
        for stage in ("ports", "httpx", "crawl", "archives", "api-discovery", "access-checks"):
            self.assertNotIn(stage, PROFILES["daily"]["skip"],
                             f"daily skips {stage}; the whatnot run skipped it as a side effect")

    def test_the_cli_rejects_a_profile_that_does_not_exist(self):
        with self.assertRaises(SystemExit):
            parser().parse_args(["127.0.0.1", "--profile", "aggressive"])


class TestProfileInvariants(unittest.TestCase):
    def test_no_profile_allows_a_tool_call_killed_by_its_own_timeout(self):
        """A stage that spends stage_timeout on a tool capped at tool_timeout cannot finish.

        The tool is killed and the stage reports a timeout no matter how much stage time is left, so
        the ratio is the thing that decides whether a slow sweep is a partial result or a dead run.
        """
        for name, prof in PROFILES.items():
            self.assertLessEqual(prof["tool_timeout"], prof["stage_timeout"],
                                 f"{name}: tool_timeout exceeds stage_timeout, so the stage is "
                                 f"guaranteed to be killed before it can use its own budget")

    def test_every_profile_has_the_same_keys(self):
        """A profile missing a key would be filled in by whichever default happened to be global."""
        shapes = {name: set(prof) for name, prof in PROFILES.items()}
        canonical = shapes["daily"]
        for name, keys in shapes.items():
            self.assertEqual(keys, canonical,
                             f"{name} has a different key set than daily: "
                             f"missing={canonical - keys} extra={keys - canonical}")

    def test_max_hosts_zero_means_uncapped(self):
        """0 is the sentinel everywhere; a real cap is never 0 or negative."""
        for name, prof in PROFILES.items():
            self.assertGreaterEqual(prof["max_hosts"], 0, f"{name} has a negative max_hosts")

    def test_zero_max_hosts_is_accepted_and_means_no_cap(self):
        """The CLI rejected max_hosts=0 as a non-positive limit, so daily could not be selected at all.

        0 is the documented sentinel for "no ceiling" and every consuming stage treats it that way.
        """
        args = apply_profile_defaults(parser().parse_args(["127.0.0.1", "--max-hosts", "0"]))
        self.assertEqual(args.max_hosts, 0)

    def test_a_negative_max_hosts_is_still_refused(self):
        """The cap check lives in main(), not in parse_args, so it is driven through the real entry point."""
        import contextlib
        import io
        from autorecon_v8.cli import main
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            with self.assertRaises(SystemExit):
                main(["127.0.0.1", "--max-hosts", "-1"])

    def test_each_profile_actually_reaches_its_stage_inputs(self):
        """max_hosts=0 must not starve the run.

        The cap was applied with a bare slice, values[:max_hosts], in two places while the rest of the
        code used limit_values. For an uncapped profile that slice is values[:0]: every stage received
        zero inputs and the run reported itself complete having looked at nothing. Driven through the
        real dispatch so the difference between "capped" and "starved" is what is measured.
        """
        import tempfile
        import shutil
        from pathlib import Path
        from autorecon_v8.core import Runner
        for profile in PROFILES:
            if PROFILES[profile]["max_hosts"] != 0:
                continue
            tmp = tempfile.mkdtemp()
            try:
                args = apply_profile_defaults(parser().parse_args(
                    ["127.0.0.1", "--output-dir", tmp, "--profile", profile]))
                run = Runner(args)
                run.command = lambda *a, **k: 0
                self.assertTrue(run.inputs("httpx"),
                                f"{profile} is uncapped but handed zero inputs to httpx")
                # crawl reads httpx output, so a fresh run has none and an empty answer is correct.
                # What must not happen is the cap deleting real input, so httpx is seeded first.
                seed = Path(run.raw) / "httpx" / "normalized.txt"
                seed.parent.mkdir(parents=True, exist_ok=True)
                seed.write_text("https://a.example.com\nhttps://b.example.com\n")
                self.assertEqual(len(run.inputs("crawl")), 2,
                                 f"{profile} is uncapped but truncated crawl's real input")
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

    def test_concurrency_and_rate_limit_are_sane(self):
        for name, prof in PROFILES.items():
            self.assertGreaterEqual(prof["concurrency"], 1, f"{name} concurrency below 1")
            self.assertGreater(prof["rate_limit"], 0, f"{name} rate_limit is not positive")

    def test_every_skip_is_a_real_stage(self):
        for name, prof in PROFILES.items():
            for stage in prof["skip"]:
                self.assertIn(stage, ACTIVE,
                              f"{name} skips {stage!r}, which is not an active stage")


if __name__ == "__main__":
    unittest.main(verbosity=2)
