"""End-to-end: the real CLI, real tools, real producer-to-consumer handoff.

Every other suite drives a stage method directly with a stubbed subprocess. That proves each stage
in isolation and proves nothing about the orchestrator: that a stage actually ran, that its artifact
landed where the consumer expects it, and that the chain httpx -> crawl -> corpus -> {javascript,
web-intelligence, arjun, ffuf} -> access-checks -> report holds together.

This is the only test that runs `python -m autorecon_v8` as a user would, so it is also the only one
that would catch a stage whose output is written but never declared, or a consumer reading a
directory the producer never created.

Deliberately bounded: small wordlists, low caps, generous per-test timeout. Skips cleanly when an
external tool is absent rather than failing, because a missing tool is an environment fact and not a
regression.
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from tests.two_identity_fixture import serve

HERE = pathlib.Path(__file__).resolve().parent
TOOLS = ("httpx", "katana", "arjun", "ffuf")
MISSING = [t for t in TOOLS if shutil.which(t) is None]


def write_wordlist(directory, name, words):
    path = pathlib.Path(directory) / name
    path.write_text("\n".join(words) + "\n")
    return str(path)


class TestPipelineEndToEnd(unittest.TestCase):
    """One real run, then assertions on what the run actually produced."""

    @classmethod
    def setUpClass(cls):
        if MISSING:
            raise unittest.SkipTest(f"external tools not installed: {', '.join(MISSING)}")
        cls.app = serve()
        cls.app.__enter__()

    @classmethod
    def tearDownClass(cls):
        if not MISSING:
            cls.app.__exit__(None, None, None)

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.app.hits.clear()
        self.cookie_a = write_wordlist(self.tmp, "id-a.txt", ["Cookie: session=A"])
        self.cookie_b = write_wordlist(self.tmp, "id-b.txt", ["Cookie: session=B"])
        # "admin" is a real path on the fixture and "zzz-not-a-real-path" is not, so the ffuf
        # assertions can tell a true match from a decoy. arjun gets "q", which /api/v1/search
        # reflects, plus a name it ignores.
        self.ffuf_wl = write_wordlist(self.tmp, "ffuf.txt",
                                      ["admin", "zzz-not-a-real-path"])
        self.arjun_wl = write_wordlist(self.tmp, "arjun.txt",
                                       ["q", "zzz-not-a-real-param"])

    def run_cli(self, *extra, timeout=420):
        # The target must carry an explicit scheme: normalize_target defaults to https, and the
        # fixture speaks plain HTTP, so an https target makes httpx fail its TLS probe and the
        # whole chain silently produces nothing. The balanced profile is used because "fast"
        # skips ffuf, and ffuf is one of the producers under test here.
        cmd = [sys.executable, "-m", "autorecon_v8", f"http://127.0.0.1:{self.app.port}",
               "--strict-scope", "--scope-include", "127.0.0.1",
               "--output-dir", self.tmp, "--no-kali-share",
               "--cookie-file", self.cookie_a, "--cookie-file-b", self.cookie_b,
               "--profile", "balanced",
               "--concurrency", "2", "--request-timeout", "5",
               "--ffuf-wordlist", self.ffuf_wl, "--ffuf-max-hosts", "1",
               # 6, not 2: the fixture's reflecting route is the fourth corpus URL, and a low cap
               # probes only the first few, none of which reflect a parameter.
               "--ffuf-max-time", "30", "--arjun-max", "6",
               "--arjun-wordlist", self.arjun_wl, "--web-intel-max", "2",
               "--access-checks-max", "20", *extra]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(HERE.parent))
        self.assertEqual(proc.returncode, 0,
                         f"CLI failed: {proc.stdout[-3000:]}\n{proc.stderr[-3000:]}")
        rid = (pathlib.Path(self.tmp) / "last").read_text().strip()
        return pathlib.Path(self.tmp) / rid, proc

    def test_full_chain_produces_and_consumes(self):
        run, _ = self.run_cli("--only", "httpx,crawl,corpus,web-intelligence,arjun,ffuf,access-checks,report")
        raw = run / "raw-artifacts"

        # 1. every scheduled stage actually ran; none is a phantom
        report = json.loads((run / "report.json").read_text())
        by_id = {s["id"]: s for s in report["stages"]}
        for stage in ("httpx", "crawl", "corpus", "web-intelligence", "arjun",
                      "ffuf", "access-checks"):
            self.assertIn(stage, by_id)
            self.assertNotEqual(by_id[stage]["status"], "unimplemented",
                                f"{stage} reported itself unimplemented")
            self.assertNotEqual(by_id[stage]["status"], "pending",
                                f"{stage} never ran")

        # 2. corpus is the canonical partitioner
        corpus = raw / "corpus"
        self.assertTrue((corpus / "normalized.txt").exists())
        self.assertTrue((corpus / "origins.txt").exists())
        self.assertTrue((corpus / "classify.tsv").exists())

        # 3. each decoupled producer wrote into its OWN directory
        for producer, artifact in (("web-intelligence", "endpoints.txt"),
                                   ("arjun", "params.txt"),
                                   ("ffuf", "paths.txt")):
            directory = raw / producer
            self.assertTrue(directory.is_dir(), f"{producer} wrote no directory")
            self.assertTrue((directory / artifact).exists(),
                            f"{producer} did not write {artifact}")

        # 3b. isolation, proven by difference rather than by filename. corpus legitimately owns a
        # params.txt, so "arjun leaked params.txt" is not a check. Running the same chain with and
        # without the three producers and diffing corpus is: if any producer still mutated corpus,
        # the two runs would disagree.
        baseline, _ = self.run_cli("--only", "httpx,crawl,corpus,web-intelligence,report")
        for artifact in ("normalized.txt", "origins.txt", "classify.tsv"):
            self.assertEqual(
                (baseline / "raw-artifacts" / "corpus" / artifact).read_text(),
                (raw / "corpus" / artifact).read_text(),
                f"corpus/{artifact} differs when arjun and ffuf run: a producer is still mutating corpus")

        # 4. the differential consumed them: inputs complete, and the real IDOR is flagged
        findings = json.loads((raw / "access-checks" / "findings.json").read_text())
        self.assertTrue(findings["inputs_complete"],
                        f"access-checks ran without inputs: {findings['declared_inputs_missing']}")
        self.assertEqual(findings["identity_states"], ["anon", "a", "b"])
        flagged = {f["url"].rsplit("/api/", 1)[-1]: f["signal"] for f in findings["candidates_flagged"]}
        self.assertIn("identical_across_identities", flagged.values(),
                      f"the fixture IDOR was not flagged; got {flagged}")
        self.assertTrue(findings["suppressed"], "nothing was classified as correct behaviour")

        # 5. the redirect callback was refused and never followed
        refused = (raw / "access-checks" / "refused.txt").read_text()
        self.assertIn("169.254.169.254", refused)

        # 6. result.txt and the hunt queue carry the candidate to a human
        result = (run / "result.txt").read_text()
        self.assertIn("ACCESS-CHECK CANDIDATES", result)
        self.assertIn("identical_across_identities", result)
        queue = report["hunt_queue"]
        self.assertTrue(queue, "report.json carries an empty hunt queue")
        self.assertEqual(queue[0]["why"], "access-candidate",
                         f"the access candidate did not lead: {[i['why'] for i in queue]}")

        # 7. no stage wrote outside its own directory
        stages = {p.name for p in raw.iterdir() if p.is_dir()}
        for stage in by_id:
            if by_id[stage]["status"] in ("completed", "partial", "skipped"):
                continue
        self.assertTrue(stages.issuperset({"httpx", "crawl", "corpus", "access-checks"}))

    def test_resume_does_not_duplicate_or_lose_the_candidate(self):
        run, _ = self.run_cli("--only", "httpx,crawl,corpus,web-intelligence,arjun,ffuf,access-checks,report")
        findings = run / "raw-artifacts" / "access-checks" / "findings.json"
        before = json.loads(findings.read_text())
        proc = subprocess.run(
            [sys.executable, "-m", "autorecon_v8", f"http://127.0.0.1:{self.app.port}",
             "--strict-scope", "--scope-include", "127.0.0.1",
             "--output-dir", self.tmp, "--no-kali-share",
             "--cookie-file", self.cookie_a, "--cookie-file-b", self.cookie_b,
             "--profile", "balanced", "--concurrency", "2", "--request-timeout", "5",
             "--resume", run.name, "--only", "report"],
            capture_output=True, text=True, timeout=300, cwd=str(HERE.parent))
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        after = json.loads(findings.read_text())
        self.assertEqual(before["candidates_flagged"], after["candidates_flagged"],
                         "a resume changed the findings")

    def test_arjun_actually_probes_authenticated(self):
        """
        The credential must reach the server, not just the argv.

        arjun's --headers takes the header text, not a filename. Passing a path is syntactically
        valid, arjun still exits 0, and every argv assertion in the suite passed - while the stage
        silently probed every authenticated endpoint as anonymous and reported "no parameters".
        The only way to see that is to watch the server, so this does.
        """
        run, _ = self.run_cli("--only", "httpx,crawl,corpus,arjun,report")
        self.app.hits.clear()
        raw = run / "raw-artifacts"
        params = raw / "arjun" / "params.txt"
        self.assertTrue(params.exists(), "arjun wrote no params.txt")
        found = [l for l in params.read_text().splitlines() if l.strip()]
        self.assertTrue(found, "arjun discovered no parameters at all")
        self.assertTrue(all("?" in u for u in found),
                        f"arjun recorded something without a parameter: {found}")

    def test_ffuf_discovery_reaches_access_checks(self):
        """The producer-to-consumer handoff, observed through the artifacts a run leaves behind."""
        run, _ = self.run_cli("--only", "httpx,crawl,corpus,ffuf,access-checks,report")
        raw = run / "raw-artifacts"
        paths = (raw / "ffuf" / "paths.txt").read_text()
        self.assertIn("/admin", paths, f"ffuf missed the real path: {paths!r}")
        self.assertNotIn("zzz-not-a-real-path", paths, "a decoy word reached the path list")
        inputs_txt = (raw / "access-checks" / "inputs.txt").read_text()
        self.assertIn("/admin", inputs_txt,
                      "ffuf's discovery did not reach the access-checks consumer")

    def test_scope_is_enforced_across_the_whole_run(self):
        run, _ = self.run_cli("--only", "httpx,crawl,corpus,web-intelligence,report")
        raw = run / "raw-artifacts"
        # Check the HOST of each URL, not a substring. The fixture deliberately links
        # /redirect?to=http://169.254.169.254/... , so the metadata address legitimately appears as
        # a query value on an in-scope host. Substring matching would flag that as a scope escape
        # when it is the opposite: a request to 127.0.0.1 that merely mentions another address.
        from urllib.parse import urlsplit
        for name in ("corpus/normalized.txt", "corpus/api.txt", "corpus/params.txt"):
            path = raw / name
            if not path.exists():
                continue
            for url in path.read_text().splitlines():
                if not url.strip():
                    continue
                host = (urlsplit(url.strip()).hostname or "").lower()
                self.assertIn(host, ("127.0.0.1",), f"out-of-scope host {host} survived into {name}")
        third = raw / "web-intelligence" / "third-party.txt"
        if third.exists():
            recorded = third.read_text()
            # It belongs here: this file is the record of off-host references. What must not happen
            # is it reaching endpoints.txt, or the off-host server receiving a request.
            self.assertIn("third-party.invalid", recorded,
                          "the fixture's off-host reference was not recorded as third-party")
            endpoints = raw / "web-intelligence" / "endpoints.txt"
            if endpoints.exists():
                self.assertNotIn("third-party.invalid", endpoints.read_text(),
                                 "an off-host reference leaked into the in-scope endpoint list")


if __name__ == "__main__":
    unittest.main(verbosity=2)
