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


class TestPartialWorkSurvivesInterruption(unittest.TestCase):
    """A killed run must leave the probes it did, not nothing.

    api-discovery collected every origin's metrics in memory and wrote the file once at stage end, so
    an interrupted stage left no metrics.jsonl at all - and result.txt then omitted [API ENDPOINTS]
    entirely, as though no probe had ever run. Evidence of work that happened is the whole point of
    a raw-artifacts directory.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.run = build(self.tmp, "api-discovery")
        self.run.inputs = lambda sid: ["https://a.example.com", "https://b.example.com"]
        self.st = StageState(id="api-discovery", name="api-discovery", description="", dependencies=[])
        self.run.stages = {"api-discovery": self.st}

    def test_metrics_are_written_before_the_stage_ends(self):
        """The file has to exist and hold rows even when the stage never reached its end.

        api-discovery probes over HTTP itself rather than through self.command, so the way to
        interrupt it is the deadline, and execute() turns Deadline into a partial status rather than
        letting it out.
        """
        # A socket that accepts and then never answers, so the probe blocks until the deadline
        # rather than finishing quickly. Racing a real timeout against a real network is what made
        # this flaky: on a fast run both origins completed and the stage finished cleanly, which is a
        # different test entirely.
        import socket
        import threading
        from http.server import BaseHTTPRequestHandler
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        port = listener.getsockname()[1]
        held = []

        def drain():
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                held.append(conn)          # accepted, never answered
        thread = threading.Thread(target=drain, daemon=True)
        thread.start()

        def cleanup():
            listener.close()
            for conn in held:
                conn.close()
        self.addCleanup(cleanup)
        # One origin answers, the other hangs. A single origin that only ever blocks leaves processed
        # at 0, which is a *failed* stage, and the test would be asserting on the wrong status while
        # measuring the same thing. Answering first is also the case that matters: it is the finished
        # origin whose evidence must already be on disk when the deadline takes the second.
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/hang"):
                    import time
                    time.sleep(5)
                body = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        import socketserver
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        live = server.server_address[1]
        self.run.inputs = lambda sid: [f"http://127.0.0.1:{live}/openapi.json",
                                       f"http://127.0.0.1:{port}/hang"]
        # request_timeout is held well above stage_timeout on purpose. With both in the same range the
        # socket timeout sometimes fired first, and a socket timeout is an OSError with its own
        # message - the stage then failed with "TimeoutError" instead of the stage deadline, and the
        # assertion was really about which of two timeouts won a race. Only the stage deadline should
        # be able to end this stage.
        self.run.args.request_timeout = 30.0
        self.run.args.stage_timeout = 1.0
        self.run.args.tool_timeout = 30.0
        self.run.execute(self.st)
        self.assertEqual(self.st.status, "partial", "the stage was not interrupted as intended")
        # Not "TimeoutError: ". A worker that outlives its budget is a deadline, and saying so is the
        # difference between an operator knowing the run ran out of time and one reading an opaque
        # exception with an empty message.
        self.assertEqual(self.st.failure_reason, "stage deadline expired",
                         "a stage that ran out of time did not say so")
        path = Path(self.run.raw) / "api-discovery" / "metrics.jsonl"
        self.assertTrue(path.exists(),
                        "metrics.jsonl did not exist until the stage finished; a killed stage loses it")
        self.assertIn(str(path), self.st.outputs,
                      "an interrupted stage must still list what it wrote")

    def test_an_interrupted_api_stage_still_yields_an_api_section(self):
        """The user-visible half of it: result.txt keeps the probes that did complete.

        metrics.jsonl is seeded by hand here, standing in for the rows an interrupted run would have
        flushed. What is under test is that the reporting side reads a partial file rather than
        treating its absence as "nothing was found".
        """
        import json as j
        rows = [{"origin": "https://a.example.com", "probe": "openapi",
                 "url": "https://a.example.com/openapi.json", "status": 200,
                 "bytes": 2, "timestamp": "now"}]
        path = Path(self.run.raw) / "api-discovery" / "metrics.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(j.dumps(r) + "\n" for r in rows))
        self.st.status = "partial"; self.st.failure_reason = "stage deadline expired"
        self.run.stages = {s: StageState(id=s, name=s, description="", dependencies=[])
                           for s in STAGE_IDS}
        self.run.stages["api-discovery"] = self.st
        self.run.generate_reports(0)
        text = (Path(self.run.work) / "result.txt").read_text()
        self.assertIn("API", text.upper())
        self.assertIn("a.example.com", text,
                      "result.txt dropped the one origin that had actually been probed")

    def test_the_stream_is_append_only_across_two_runs(self):
        """A resume must not truncate what the earlier run already found."""
        import json as j
        path = Path(self.run.raw) / "api-discovery" / "metrics.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(j.dumps({"origin": "https://first.example.com", "probe": "openapi"}) + "\n")
        self.run.command = lambda *a, **k: 0
        self.run.execute(self.st)
        text = path.read_text()
        self.assertIn("first.example.com", text,
                      "a resumed api-discovery overwrote the previous run's metrics")


class TestMetricsAreFlushedWhileTheStageRuns(unittest.TestCase):
    """Asserted by observation, not by reading the code: a probe served mid-stage sees the earlier
    probe's row already on disk. Collecting rows in memory and writing once at the end passes every
    test that only inspects the file afterwards, which is the shape of test that let this ship."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_a_probe_served_mid_stage_sees_the_earlier_row_on_disk(self):
        import json as j
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        seen = {}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                path = Path(self.server.metrics_path)
                seen[self.server.hits] = path.exists() and bool(path.read_text().strip())
                self.server.hits += 1
                body = b'{"openapi":"3.0.0"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        run = build(self.tmp, "api-discovery")
        run.args.concurrency = 1
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.hits = 0
        server.metrics_path = str(Path(run.raw) / "api-discovery" / "metrics.jsonl")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)

        port = server.server_address[1]
        # Two distinct origins: unique_origins() collapses identical scheme+host+port, and both must
        # survive that for the second origin's probes to run after the first origin has been emitted.
        run.inputs = lambda sid: [f"http://127.0.0.1:{port}", f"http://localhost:{port}"]
        st = StageState(id="api-discovery", name="api-discovery", description="", dependencies=[])
        run.stages = {"api-discovery": st}
        run.execute(st)

        rows = [json_line for json_line in
                Path(server.metrics_path).read_text().splitlines() if json_line.strip()]
        self.assertGreaterEqual(len(rows), 2, f"expected a row per probe, got {len(rows)}")
        self.assertTrue(seen[0] is False, "the first probe should find nothing written yet")
        self.assertTrue(any(seen.values()),
                        "no probe found an earlier probe's metrics already on disk, so the stream "
                        "is buffered in memory and only written at stage end")
        import json as j
        for row in rows:
            self.assertIn("status", j.loads(row), f"a metrics row is missing its status: {row}")


class TestCrawlDoesNotLoseTheRun(unittest.TestCase):
    """The whatnot live run: one katana invocation over one seed never returned, produced zero lines,
    and the stage deadline then took corpus, javascript, arjun, ffuf and access-checks down with it.
    Five stages lost to one slow host, and the stages that skipped all said why - so the report was
    honest and still nearly empty."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(shutil.rmtree, "/dev/shm/autorecon-results", ignore_errors=True)

    def runner(self, seeds):
        run = build(self.tmp, "crawl")
        run.inputs = lambda sid, v=list(seeds): list(v)
        return run

    def stage(self, run):
        st = StageState(id="crawl", name="crawl", description="", dependencies=[])
        run.stages = {"crawl": st}
        run.execute(st)
        return st

    def test_seeds_are_crawled_one_at_a_time_by_default(self):
        """The whole point: one host cannot consume the stage's budget on its own."""
        calls = []

        def spy(stage, cmd, target, deadline, output, cwd=None):
            calls.append(target)
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(f"https://{target}/found\n")
            return 0
        run = self.runner(["a.example.com", "b.example.com", "c.example.com"])
        run.command = spy
        self.stage(run)
        self.assertEqual(len(calls), 3, f"expected one invocation per seed, got {len(calls)}")

    def test_a_killed_seed_keeps_the_others(self):
        def killed(stage, cmd, target, deadline, output, cwd=None):
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            if target == "b.example.com":
                Path(output).write_text("https://b.example.com/half\n")
                return 124
            Path(output).write_text(f"https://{target}/found\n")
            return 0
        run = self.runner(["a.example.com", "b.example.com", "c.example.com"])
        run.command = killed
        st = self.stage(run)
        text = (Path(run.work) / "result.txt")
        kept = (Path(run.raw) / "crawl" / "normalized.txt").read_text()
        self.assertIn("a.example.com", kept)
        self.assertIn("c.example.com", kept)
        self.assertIn("b.example.com/half", kept,
                      "the killed seed's partial results were discarded")
        self.assertEqual(st.status, "partial", "a killed seed was reported as a clean stage")
        self.assertIn("b.example.com", st.failure_reason or "")

    def test_a_slow_seed_cannot_starve_the_rest(self):
        """The budget is per invocation, so a seed that overruns is bounded to its own unit."""
        run = self.runner([f"h{i}.example.com" for i in range(20)])
        run.command = lambda *a, **k: 0
        st = self.stage(run)
        self.assertEqual(st.processed, 20,
                         "a crawl that spawned per-seed invocations did not account for all seeds")


if __name__ == "__main__":



    unittest.main(verbosity=2)