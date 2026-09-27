"""hunt_queue: the ranked worklist an operator reads to decide what to chase.

The queue is where every stage's output becomes a decision. Two properties matter most and are
pinned hardest: an authorization candidate outranks infrastructure noise, and nothing out of scope
reaches the list no matter which stage produced it.
"""

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

from autorecon_v8.cli import apply_profile_defaults, parser
from autorecon_v8.core import HUNT_LIMIT, HUNT_RANK, HUNT_SENSITIVE, Runner, UNUSUAL_PORTS


def build(tmp, includes=("127.0.0.1",)):
    args = apply_profile_defaults(parser().parse_args([
        "127.0.0.1", "--strict-scope", "--output-dir", tmp, "--no-kali-share",
        *sum((["--scope-include", i] for i in includes), [])]))
    subprocess.run([sys.executable, "-m", "autorecon_v8", "127.0.0.1", "--dry-run",
                    "--only", "httpx", "--output-dir", tmp], capture_output=True, timeout=180)
    args.resume = (pathlib.Path(tmp) / "last").read_text().strip()
    return Runner(args)


def seed(run, stages, anomalies=None):
    raw = pathlib.Path(run.raw)
    for stage, body in stages.items():
        (raw / stage).mkdir(parents=True, exist_ok=True)
        (raw / stage / "normalized.txt").write_text("\n".join(body) + "\n")
    if anomalies is not None:
        ac = raw / "access-checks"
        ac.mkdir(parents=True, exist_ok=True)
        ac.joinpath("anomalies.tsv").write_text(
            "url\tsignal\tseverity\tconfidence\trisk\tdetail\tverify\n"
            + "".join(f"{u}\tidentical_across_identities\thigh\tmedium\trisk\tdetail\tverify\n"
                      for u in anomalies))
    return raw


class Ranking(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_access_candidate_ranks_first(self):
        run = build(self.tmp, ("127.0.0.1", "example.com"))
        seed(run, {"ports": ["example.com:22", "example.com:80"],
                   "httpx": ["http://127.0.0.1:9/"],
                   "javascript": ["http://127.0.0.1:9/app.js"]},
             anomalies=["http://127.0.0.1:9/api/v1/tenants/A/records/101"])
        queue = run.hunt_queue()
        self.assertEqual(queue[0]["why"], "access-candidate",
                         f"an authorization candidate did not lead: {[i['why'] for i in queue]}")
        self.assertEqual(queue[0]["rank"], "0")

    def test_rank_order_is_monotonic(self):
        run = build(self.tmp, ("127.0.0.1", "example.com"))
        seed(run, {"ports": ["example.com:22", "example.com:80"],
                   "httpx": ["http://127.0.0.1:9/"],
                   "ffuf": ["http://127.0.0.1:9/admin"],
                   "web-intelligence": ["http://127.0.0.1:9/api/v1/x"]},
             anomalies=["http://127.0.0.1:9/api/v1/tenants/A/records/101"])
        ranks = [int(i["rank"]) for i in run.hunt_queue()]
        self.assertEqual(ranks, sorted(ranks), f"queue is not in rank order: {ranks}")

    def test_infrastructure_never_outranks_an_access_candidate(self):
        self.assertLess(HUNT_RANK["access-candidate"], HUNT_RANK["unusual-port"])
        self.assertLess(HUNT_RANK["access-candidate"], HUNT_RANK["open-port"])
        self.assertLess(HUNT_RANK["access-candidate"], HUNT_RANK["live-host"])

    def test_unusual_port_is_labelled_and_ranks_above_an_ordinary_one(self):
        run = build(self.tmp, ("127.0.0.1", "example.com"))
        seed(run, {"ports": ["example.com:22", "example.com:443"]})
        by_value = {i["value"]: i for i in run.hunt_queue()}
        self.assertEqual(by_value["example.com:22"]["why"], "unusual-port")
        self.assertEqual(by_value["example.com:443"]["why"], "open-port")
        self.assertLess(int(by_value["example.com:22"]["rank"]),
                        int(by_value["example.com:443"]["rank"]))

    def test_sensitive_paths_lead_within_their_rank(self):
        run = build(self.tmp, ("127.0.0.1",))
        seed(run, {"corpus": ["http://127.0.0.1:9/about",
                              "http://127.0.0.1:9/.env",
                              "http://127.0.0.1:9/admin"]})
        queue = [i["value"] for i in run.hunt_queue()]
        self.assertEqual(queue[0], "http://127.0.0.1:9/.env",
                         f"sensitive path did not lead: {queue}")

    def test_every_discovery_stage_is_a_source(self):
        run = build(self.tmp, ("127.0.0.1",))
        seed(run, {"httpx": ["http://127.0.0.1:9/host"],
                   "ffuf": ["http://127.0.0.1:9/admin"],
                   "web-intelligence": ["http://127.0.0.1:9/api/v1/x"],
                   "arjun": ["http://127.0.0.1:9/a?q=1"],
                   "javascript": ["http://127.0.0.1:9/app.js"]},
             anomalies=["http://127.0.0.1:9/api/v1/tenants/A/records/101"])
        stages = {i["stage"] for i in run.hunt_queue()}
        for expected in ("access-checks", "ffuf", "web-intelligence", "arjun",
                         "javascript", "httpx"):
            self.assertIn(expected, stages, f"{expected} contributes nothing to the queue")

    def test_active_flag_reflects_the_producing_stage(self):
        run = build(self.tmp, ("127.0.0.1", "example.com"))
        seed(run, {"httpx": ["http://127.0.0.1:9/"],
                   "ffuf": ["http://127.0.0.1:9/admin"]})
        by_stage = {i["stage"]: i["active"] for i in run.hunt_queue()}
        self.assertEqual(by_stage["ffuf"], "True", "ffuf is an active stage")
        self.assertEqual(by_stage["httpx"], "False", "httpx is not an active stage")


class ScopeAndBounds(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_out_of_scope_values_are_excluded_from_every_source(self):
        run = build(self.tmp, ("127.0.0.1",))
        hostile = ["https://evil.test/x", "http://169.254.169.254/", "http://127.0.0.1:22/evil"]
        seed(run, {"httpx": ["http://127.0.0.1:9/ok", *hostile],
                   "ffuf": ["http://127.0.0.1:9/admin", *hostile],
                   "web-intelligence": ["http://127.0.0.1:9/x", *hostile],
                   "arjun": ["http://127.0.0.1:9/a", *hostile],
                   "javascript": ["http://127.0.0.1:9/app.js", *hostile]},
             anomalies=["http://127.0.0.1:9/api/v1/tenants/A/records/101", *hostile])
        joined = " ".join(i["value"] for i in run.hunt_queue())
        for bad in ("evil.test", "169.254.169.254"):
            self.assertNotIn(bad, joined, f"{bad} reached the queue")

    def test_queue_is_deduplicated(self):
        run = build(self.tmp, ("127.0.0.1",))
        seed(run, {"httpx": ["http://127.0.0.1:9/dup", "http://127.0.0.1:9/dup"],
                   "ffuf": ["http://127.0.0.1:9/dup"]})
        values = [i["value"] for i in run.hunt_queue()]
        self.assertEqual(len(values), len(set(values)))

    def test_queue_is_bounded(self):
        run = build(self.tmp, ("127.0.0.1",))
        seed(run, {"httpx": [f"http://127.0.0.1:9/host{i}" for i in range(300)]})
        # the seed run leaves the target itself in httpx output, so that is part of the count
        self.assertLessEqual(len(run.hunt_queue()), HUNT_LIMIT)
        self.assertEqual(len(run.hunt_queue(limit=5)), 5)

    def test_empty_run_yields_an_empty_queue_not_an_error(self):
        run = build(self.tmp, ("127.0.0.1",))
        # The seed run leaves the target in httpx output; clear it so "empty" really is empty.
        seed(run, {"httpx": []})
        self.assertEqual(run.hunt_queue(), [])


class ReportIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_queue_lands_in_report_json_and_markdown(self):
        run = build(self.tmp, ("127.0.0.1",))
        seed(run, {"ffuf": ["http://127.0.0.1:9/admin"]},
             anomalies=["http://127.0.0.1:9/api/v1/tenants/A/records/101"])
        run.generate_reports(0)
        report = json.loads((run.work / "report.json").read_text())
        self.assertIn("hunt_queue", report)
        self.assertTrue(report["hunt_queue"], "report.json carries an empty queue")
        self.assertEqual(report["hunt_queue"][0]["why"], "access-candidate")
        markdown = (run.work / "report.md").read_text()
        self.assertIn("## Hunt queue", markdown)
        self.assertIn("access-candidate", markdown)
        self.assertIn("/api/v1/tenants/A/records/101", markdown)

    def test_empty_queue_is_stated_rather_than_omitted(self):
        run = build(self.tmp, ("127.0.0.1",))
        seed(run, {"httpx": []})
        run.generate_reports(0)
        self.assertIn("No ranked candidates.", (run.work / "report.md").read_text())


class PatternSanity(unittest.TestCase):
    def test_sensitive_pattern_fires_on_the_obvious_and_not_on_ordinary_paths(self):
        for hit in ("/.env", "/.git/config", "/wp-config.php", "/admin", "/phpmyadmin",
                    "/actuator/env", "/backup", "/.aws/credentials", "/cgi-bin/test"):
            self.assertTrue(HUNT_SENSITIVE.search(hit), f"{hit} should be treated as sensitive")
        for miss in ("/about", "/pricing", "/api/v1/users", "/blog/post-1", "/assets/app.css"):
            self.assertFalse(HUNT_SENSITIVE.search(miss), f"{miss} should not be treated as sensitive")

    def test_unusual_port_set_is_not_empty_and_excludes_https(self):
        self.assertIn(22, UNUSUAL_PORTS)
        self.assertIn(3306, UNUSUAL_PORTS)
        self.assertNotIn(443, UNUSUAL_PORTS, "443 is the ordinary case, not unusual")
        self.assertNotIn(80, UNUSUAL_PORTS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
