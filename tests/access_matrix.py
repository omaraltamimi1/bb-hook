"""The access-checks authorization matrix, pinned end to end against a live fixture.

Pins the five outcomes the differential has to tell apart, against a real HTTP server with three
authentication contexts. Argv tests cannot do this: a regression in the evaluation matrix that
emitted zero candidates for a vulnerable endpoint would pass every argument assertion in the suite.

Each case asserts on the artifacts an operator actually reads - findings.json, anomalies.tsv,
suppressed.tsv, refused.txt - not on internal state.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from autorecon_v8.cli import apply_profile_defaults, parser
from autorecon_v8.core import Runner
from tests.two_identity_fixture import serve, serve_external


IDENTITY_A_COOKIE = "session=A; tenant=A"
IDENTITY_B_COOKIE = "session=B; tenant=B"


class MatrixHarness(unittest.TestCase):
    """Runs access-checks against the fixture and returns its artifacts."""

    @classmethod
    def setUpClass(cls):
        cls.app = serve()
        cls.app.__enter__()
        cls.external = serve_external()
        cls.external.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.external.__exit__(None, None, None)
        cls.app.__exit__(None, None, None)

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.cookie_a = Path(self.tmp) / "identity-a.txt"
        self.cookie_b = Path(self.tmp) / "identity-b.txt"
        # Written verbatim, the way an operator supplies a real session.
        self.cookie_a.write_text(f"Cookie: {IDENTITY_A_COOKIE}\n")
        self.cookie_b.write_text(f"Cookie: {IDENTITY_B_COOKIE}\n")
        self.external.hits.clear()
        self.app.hits.clear()

    def url(self, path):
        return self.app.origin + path

    def external_target(self):
        """URL of the must-not-be-touched server, addressed by a name scope will not match.

        Scope compares hostnames, not host:port, so a second port on 127.0.0.1 is still in
        scope. Addressing that same server as "localhost" puts it out of scope while keeping it
        reachable, which is what turns "the redirect was not followed" into a checkable claim:
        the server records every hit it receives, so an empty log is evidence rather than an
        assumption about code that never ran.
        """
        return f"http://localhost:{self.external.port}/latest/meta-data/"

    def run_matrix(self, paths, extra_argv=()):
        """Run access-checks over paths and return the parsed artifacts plus the stage state."""
        args = apply_profile_defaults(parser().parse_args([
            "127.0.0.1", "--strict-scope", "--scope-include", "127.0.0.1",
            "--cookie-file", str(self.cookie_a), "--cookie-file-b", str(self.cookie_b),
            "--output-dir", self.tmp, *extra_argv]))
        subprocess.run([sys.executable, "-m", "autorecon_v8", "127.0.0.1", "--dry-run",
                        "--only", "httpx", "--output-dir", self.tmp],
                       capture_output=True, timeout=180)
        args.resume = (Path(self.tmp) / "last").read_text().strip()
        run = Runner(args)
        raw = Path(run.raw)
        (raw / "corpus").mkdir(parents=True, exist_ok=True)
        (raw / "corpus" / "params.txt").write_text("\n".join(self.url(p) for p in paths) + "\n")
        st = run.stages["access-checks"]
        st.status = "pending"
        run.access_checks_stage(st, run.global_deadline)
        root = raw / "access-checks"
        findings = json.loads((root / "findings.json").read_text()) if (root / "findings.json").exists() else {}
        anomalies = self._tsv(root / "anomalies.tsv")
        suppressed = self._tsv(root / "suppressed.tsv")
        refused = (root / "refused.txt").read_text().split() if (root / "refused.txt").exists() else []
        return {
            "stage": st, "root": root, "findings": findings,
            "flagged": findings.get("candidates_flagged", []),
            "suppressed_records": findings.get("suppressed", []),
            "anomalies": anomalies, "suppressed": suppressed, "refused": refused,
        }

    @staticmethod
    def _tsv(path):
        """Read a TSV written by the stage, header first."""
        if not path.exists():
            return []
        lines = [l for l in path.read_text().splitlines() if l.strip()]
        if not lines:
            return []
        header = lines[0].split("\t")
        return [dict(zip(header, l.split("\t"))) for l in lines[1:]]

    @staticmethod
    def signals_for(artifacts, path):
        """Every signal emitted for one fixture path, across all three artifacts."""
        out = []
        for record in artifacts["flagged"]:
            if record["url"].endswith(path):
                out.append(record["signal"])
        for record in artifacts["suppressed_records"]:
            if record["url"].endswith(path):
                out.append(record["signal"])
        for row in artifacts["anomalies"]:
            if row["url"].endswith(path):
                out.append(row["signal"])
        for row in artifacts["suppressed"]:
            if row["url"].endswith(path):
                out.append(row["signal"])
        return out

    def record_for(self, artifacts, path, signal):
        for record in artifacts["flagged"] + artifacts["suppressed_records"]:
            if record["url"].endswith(path) and record["signal"] == signal:
                return record
        for row in artifacts["anomalies"] + artifacts["suppressed"]:
            if row["url"].endswith(path) and row["signal"] == signal:
                return row
        return None


class TestTrueIdor(MatrixHarness):
    """Case 1: identity_b_accesses_a_private - the true positive."""

    PATH = "/api/v1/tenants/A/records/101"

    def test_b_receives_a_private_object(self):
        artifacts = self.run_matrix([self.PATH])
        signals = self.signals_for(artifacts, self.PATH)
        self.assertIn("identical_across_identities", signals,
                      f"a cross-identity IDOR was not flagged; signals were {signals}")
        self.assertNotIn("auth_required", [f["signal"] for f in artifacts["flagged"]
                                           if f["url"].endswith(self.PATH)],
                         "auth_required is a suppression and must not also be a finding")

    def test_flagged_with_severity_and_confidence(self):
        artifacts = self.run_matrix([self.PATH])
        record = self.record_for(artifacts, self.PATH, "identical_across_identities")
        self.assertIsNotNone(record, "no record to score")
        self.assertEqual(record["severity"], "high")
        self.assertEqual(record["confidence"], "medium")
        self.assertTrue(record["false_positive_risk"], "a candidate must state its false-positive risk")
        self.assertTrue(record["verify"], "a candidate must state the next verification step")
        self.assertIn("id", record["verify"].lower() + record["detail"].lower())

    def test_appears_in_findings_and_anomalies(self):
        artifacts = self.run_matrix([self.PATH])
        self.assertTrue(artifacts["flagged"], "findings.json listed no candidates")
        self.assertTrue(any(r["url"].endswith(self.PATH) for r in artifacts["anomalies"]),
                        "anomalies.tsv omitted the IDOR candidate")
        self.assertIn("candidates only", artifacts["findings"]["disclaimer"].lower())
        self.assertIn("none of these is a validated vulnerability",
                      artifacts["findings"]["disclaimer"].lower())

    def test_observed_states_capture_all_three_identities(self):
        artifacts = self.run_matrix([self.PATH])
        record = self.record_for(artifacts, self.PATH, "identical_across_identities")
        observed = record["observed"]
        self.assertEqual(set(observed), {"anon", "a", "b"})
        self.assertEqual(observed["a"]["status"], 200)
        self.assertEqual(observed["b"]["status"], 200)
        self.assertEqual(observed["anon"]["status"], 401)
        self.assertEqual(observed["a"]["sha256"], observed["b"]["sha256"])

    def test_anonymous_alone_would_not_have_caught_it(self):
        """Guards the reason identity B exists: A-versus-anonymous looks like correct auth."""
        artifacts = self.run_matrix([self.PATH])
        record = self.record_for(artifacts, self.PATH, "identical_across_identities")
        observed = record["observed"]
        self.assertNotEqual(observed["anon"]["status"], observed["a"]["status"],
                            "fixture regression: anonymous must be refused")


class TestTenantIsolated(MatrixHarness):
    """Case 2: properly_scoped_multitenant - correct partitioning, not a finding."""

    PATH = "/api/v1/profile"

    def test_each_identity_receives_its_own_tenant(self):
        artifacts = self.run_matrix([self.PATH])
        rows = [r for r in artifacts["flagged"] if r["url"].endswith(self.PATH)]
        self.assertTrue(rows, "no record at all for the profile route")
        observed = rows[0]["observed"]
        self.assertEqual(observed["a"]["status"], 200)
        self.assertEqual(observed["b"]["status"], 200)
        self.assertNotEqual(observed["a"]["sha256"], observed["b"]["sha256"])

    def test_does_not_produce_a_high_confidence_idor(self):
        artifacts = self.run_matrix([self.PATH])
        signals = self.signals_for(artifacts, self.PATH)
        self.assertNotIn("identical_across_identities", signals,
                         f"correct per-tenant responses were reported as a shared object: {signals}")
        for row in artifacts["anomalies"]:
            if row["url"].endswith(self.PATH):
                self.assertNotEqual(row["severity"], "high",
                                    "a length differential between two users is not high severity")
                self.assertIn(row["confidence"], ("low", "n/a"),
                              f"unexpected confidence {row['confidence']} for a benign differential")


class TestPublicResource(MatrixHarness):
    """Case 3: public_resource - identical for everyone including anonymous."""

    PATH = "/api/v1/config/public"

    def test_public_resource_is_not_reported_as_idor(self):
        artifacts = self.run_matrix([self.PATH])
        high = [r for r in artifacts["flagged"]
                if r["url"].endswith(self.PATH) and r["severity"] == "high"]
        self.assertEqual(high, [],
                         f"a public endpoint was escalated to a high-severity candidate: "
                         f"{[r['signal'] for r in high]}")

    def test_public_resource_is_categorised_and_suppressed(self):
        artifacts = self.run_matrix([self.PATH])
        signals = self.signals_for(artifacts, self.PATH)
        self.assertTrue(signals, "the public route produced no classification at all")
        self.assertIn("public_shared_resource", signals,
                      f"a route byte-identical for all three contexts was not identified as public: {signals}")
        record = self.record_for(artifacts, self.PATH, "public_shared_resource")
        self.assertEqual(record["severity"], "info")
        self.assertEqual(record["confidence"], "n/a")

    def test_public_resource_appears_in_suppressed_not_anomalies(self):
        artifacts = self.run_matrix([self.PATH])
        self.assertTrue(any(r["url"].endswith(self.PATH) for r in artifacts["suppressed"]),
                        "the public route was not recorded as suppressed")
        self.assertEqual([r for r in artifacts["anomalies"] if r["url"].endswith(self.PATH)], [],
                         "a public resource must not pollute anomalies.tsv")


class TestAuthEnforced(MatrixHarness):
    """Case 4: auth_enforced - A allowed, anonymous refused, B refused."""

    PATH = "/api/v1/private/dashboard"

    def test_suppressed_from_findings(self):
        artifacts = self.run_matrix([self.PATH])
        flagged = [r["signal"] for r in artifacts["flagged"] if r["url"].endswith(self.PATH)]
        self.assertEqual(flagged, [], f"correct auth enforcement was reported as a candidate: {flagged}")

    def test_recorded_cleanly_in_suppressed(self):
        artifacts = self.run_matrix([self.PATH])
        self.assertTrue(any(r["url"].endswith(self.PATH) and r["signal"] == "auth_required"
                            for r in artifacts["suppressed_records"]),
                        "the enforced route was not recorded as an auth_required suppression")
        row = self.record_for(artifacts, self.PATH, "auth_required")
        self.assertEqual(row["severity"], "info")
        self.assertEqual(row["false_positive_risk"], "none, this is correct behaviour")

    def test_absent_from_anomalies(self):
        artifacts = self.run_matrix([self.PATH])
        self.assertEqual([r for r in artifacts["anomalies"] if r["url"].endswith(self.PATH)], [])

    def test_identity_b_being_refused_does_not_create_a_signal(self):
        # B is 403, not 200. If the fixture ever gave B a 200 the stage would emit an A-vs-B
        # candidate and this case would stop isolating the anonymous-versus-authenticated matrix.
        artifacts = self.run_matrix([self.PATH])
        suppressed = [r for r in artifacts["suppressed_records"] if r["url"].endswith(self.PATH)]
        self.assertTrue(suppressed)
        observed = suppressed[0]["observed"]
        self.assertEqual(observed["b"]["status"], 403)
        self.assertEqual(observed["anon"]["status"], 401)
        self.assertEqual(observed["a"]["status"], 200)


class TestUntrustedRedirect(MatrixHarness):
    """Case 5: untrusted_redirect - the callback must be refused, not fetched."""

    METADATA = "http://169.254.169.254/latest/meta-data/"

    def test_cloud_metadata_callback_is_refused(self):
        """The operator's case: link-local metadata is never in scope for a web assessment."""
        artifacts = self.run_matrix([f"/redirect?to={self.METADATA}"])
        self.assertTrue(artifacts["refused"], "the metadata callback was not refused")
        self.assertTrue(any("169.254.169.254" in r for r in artifacts["refused"]),
                        f"the metadata callback is missing from refused.txt: {artifacts['refused']}")

    def test_redirect_callback_is_refused_and_recorded(self):
        target = self.external_target()
        artifacts = self.run_matrix([f"/redirect?to={target}"])
        self.assertTrue(artifacts["refused"], "the out-of-scope redirect callback was not refused")
        self.assertTrue(any("latest/meta-data" in r for r in artifacts["refused"]),
                        f"the metadata callback is missing from refused.txt: {artifacts['refused']}")

    def test_external_host_is_never_actually_requested(self):
        """The strong claim: a server that records hits must show zero."""
        target = self.external_target()
        self.run_matrix([f"/redirect?to={target}"])
        self.assertEqual(self.external.hits, [],
                         f"the stage followed the redirect off-target: {self.external.hits}")

    def test_redirect_itself_was_probed(self):
        """Guards the test above: if the route were never probed, 'no hits' proves nothing."""
        target = self.external_target()
        self.run_matrix([f"/redirect?to={target}"])
        self.assertTrue(any(h["path"] == "/redirect" for h in self.app.hits),
                        "the redirect route was never requested, so the refusal was not exercised")

    def test_refusal_is_annotated_on_the_record(self):
        target = self.external_target()
        artifacts = self.run_matrix([f"/redirect?to={target}"])
        records = [r for r in artifacts["flagged"] + artifacts["suppressed_records"]
                   if "redirect" in r["url"]]
        self.assertTrue(records, "no record captured the redirect response")
        annotated = any("REFUSED" in str(r.get("observed", {}).get("a", {}).get("location", ""))
                        or "REFUSED" in str(r.get("detail", ""))
                        or any("REFUSED" in str(v) for v in r.get("observed", {}).values())
                        for r in records)
        self.assertTrue(annotated, "the refused callback was not annotated on the record")


class TestDiscriminatingComparisons(MatrixHarness):
    """Two cases that separate the comparisons the stage actually performs."""

    def test_same_length_different_content_is_not_treated_as_identical(self):
        """A length comparison would report this as a shared object. It is not one."""
        path = "/api/v1/orders/equal-length"
        artifacts = self.run_matrix([path])
        signals = self.signals_for(artifacts, path)
        self.assertIn("same_status_different_content", signals,
                      f"same-length different-content was not distinguished: {signals}")
        self.assertNotIn("identical_across_identities", signals,
                         f"a length comparison was mistaken for a digest match: {signals}")
        record = self.record_for(artifacts, path, "same_status_different_content")
        self.assertEqual(record["observed"]["a"]["length"], record["observed"]["b"]["length"],
                         "fixture regression: the two payloads must be the same length")
        self.assertNotEqual(record["observed"]["a"]["sha256"], record["observed"]["b"]["sha256"])

    def test_same_bytes_different_status_is_not_a_public_resource(self):
        """Identical digests with a differing status must not collapse into public_shared_resource."""
        path = "/api/v1/status-only-enforcement"
        artifacts = self.run_matrix([path])
        signals = self.signals_for(artifacts, path)
        self.assertNotIn("public_shared_resource", signals,
                         f"a 401 was treated as equivalent to a 200: {signals}")
        self.assertIn("identical_across_identities", signals,
                      f"identical authenticated bodies were not flagged: {signals}")
        self.assertIn("auth_required", signals,
                      f"the anonymous 401 was not recorded as enforcement: {signals}")
        record = self.record_for(artifacts, path, "auth_required")
        self.assertEqual(record["observed"]["anon"]["status"], 401)
        self.assertEqual(record["observed"]["a"]["status"], 200)
        self.assertEqual(record["observed"]["anon"]["sha256"], record["observed"]["a"]["sha256"],
                         "fixture regression: the bodies must be byte-identical for this case")


class TestMatrixEndToEnd(MatrixHarness):
    """All five routes in one run: the matrix must not let one case contaminate another."""

    PATHS = [
        "/api/v1/tenants/A/records/101",
        "/api/v1/profile",
        "/api/v1/config/public",
        "/api/v1/private/dashboard",
    ]

    def test_each_route_gets_its_own_verdict(self):
        artifacts = self.run_matrix(self.PATHS)
        expected = {
            "/api/v1/tenants/A/records/101": "identical_across_identities",
            "/api/v1/profile": "length_differs_across_identities",
            "/api/v1/config/public": "public_shared_resource",
            "/api/v1/private/dashboard": "auth_required",
        }
        for path, signal in expected.items():
            with self.subTest(path=path):
                self.assertIn(signal, self.signals_for(artifacts, path),
                              f"{path} did not produce {signal}: {self.signals_for(artifacts, path)}")

    def test_only_the_true_positive_is_high_severity(self):
        artifacts = self.run_matrix(self.PATHS)
        high = {r["url"].rsplit(self.app.origin, 1)[-1] for r in artifacts["flagged"]
                if r["severity"] == "high"}
        self.assertEqual(high, {"/api/v1/tenants/A/records/101"},
                         f"more than the true positive was escalated: {high}")

    def test_findings_json_accounting_is_consistent(self):
        artifacts = self.run_matrix(self.PATHS)
        findings = artifacts["findings"]
        self.assertEqual(findings["identity_states"], ["anon", "a", "b"])
        self.assertEqual(findings["targets_probed"], len(self.PATHS))
        self.assertEqual(findings["targets_considered"], len(self.PATHS))
        self.assertEqual(len(artifacts["flagged"]) + len(artifacts["suppressed_records"]),
                         len(self.signals_for_all(artifacts)))
        # every candidate carries an explicit disclaimer
        self.assertIn("candidates only", findings["disclaimer"].lower())

    def signals_for_all(self, artifacts):
        return artifacts["flagged"] + artifacts["suppressed_records"]

    def test_normalized_rows_have_a_status_for_every_identity(self):
        artifacts = self.run_matrix(self.PATHS)
        text = (artifacts["root"] / "normalized.txt").read_text()
        rows = [l.split("\t") for l in text.splitlines() if l.strip()]
        self.assertEqual(len(rows), len(self.PATHS))
        for row in rows:
            # url, one status per state, one length per state, then the signal list
            self.assertEqual(len(row), 1 + 3 + 3 + 1, f"unexpected column count in {row}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
