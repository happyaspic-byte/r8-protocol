import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("q3", ROOT / "bench/q3.py")
q3 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(q3)


class Q3Tests(unittest.TestCase):
    def test_fixture_is_current_ed25519_and_pinned(self):
        cert = x509.load_pem_x509_certificate(q3.CERT.read_bytes())
        self.assertLessEqual(cert.not_valid_before_utc.year, 2026)
        self.assertLess(2026, cert.not_valid_after_utc.year)
        self.assertEqual(cert.public_key().__class__.__name__, "Ed25519PublicKey")
        actual = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(q3.spki_pin(), hashlib.sha256(actual).hexdigest())

    def test_smoke_workers_execute_real_loopback(self):
        for mechanism in q3.MECHANISMS:
            with self.subTest(mechanism=mechanism):
                result = subprocess.run(
                    [sys.executable, str(ROOT / "bench/q3.py"), "worker", "--mechanism", mechanism],
                    text=True,
                    capture_output=True,
                    timeout=12,
                    check=True,
                )
                row = json.loads(result.stdout)
                self.assertEqual(row["status"], "success")
                self.assertGreater(row["network"]["rx_packets"], 0)

    def test_primary_and_smoke_cardinality_and_balanced_blocks(self):
        primary = list(q3.planned_trials(q3.WARMUPS + q3.MEASURED, False))
        smoke = list(q3.planned_trials(2, True))
        self.assertEqual(len(primary), 2 * (q3.WARMUPS + q3.MEASURED))
        self.assertEqual(len(primary) * 2, 4200)
        self.assertEqual(len(smoke), 2 * 2)
        for mechanism in q3.MECHANISMS:
            mechanism_primary = [row for row in primary if row[2] == mechanism]
            mechanism_smoke = [row for row in smoke if row[2] == mechanism]
            self.assertEqual(len(mechanism_primary), 1050)
            self.assertEqual(len(mechanism_smoke), 2)
            self.assertEqual([row[3] for row in mechanism_primary], list(range(1050)))
            self.assertEqual(sum(row[4] for row in mechanism_primary), 50)
            self.assertFalse(any(row[4] for row in mechanism_smoke))
        self.assertEqual(primary, list(q3.planned_trials(q3.WARMUPS + q3.MEASURED, False)))
        for block in range(105):
            entries = [row for row in primary if row[0] == block]
            self.assertEqual(len(entries), 20)
            self.assertEqual({row[2] for row in entries}, set(q3.MECHANISMS))
            self.assertEqual(sum(row[2] == q3.MECHANISMS[0] for row in entries), 10)

    def test_bootstrap_failure_timeout_and_p99_rules(self):
        rows = []
        for block in range(10):
            for mechanism in q3.MECHANISMS:
                for _ in range(10):
                    rows.append({"series": "warm-process", "mechanism": mechanism, "excluded": False, "block": block, "status": "success", "latency_ns": 10 + block, "cpu_ns": 1, "network": {k: 1 for k in q3.net()}})
                    rows.append({"series": "cold-process-primary", "mechanism": mechanism, "excluded": False, "block": block, "status": "success", "latency_ns": 5_000_000_000, "cpu_ns": 1, "network": {k: 1 for k in q3.net()}})
        rows.append({"series": "warm-process", "mechanism": q3.MECHANISMS[0], "excluded": False, "block": 0, "status": "timeout", "latency_ns": 5_000_000_000, "cpu_ns": 1, "network": {k: 1 for k in q3.net()}})
        result = q3.summary(rows)
        warm = result["series"]["warm-process"][q3.MECHANISMS[0]]
        cold = result["series"]["cold-process-primary"][q3.MECHANISMS[0]]
        self.assertTrue(warm["latency_ns"]["confidence_intervals_95"]["p50"])
        self.assertTrue(warm["p99_supported"])
        self.assertGreater(warm["failure_rate"], 0)
        self.assertEqual(cold["latency_ns"]["p99"], "unsupported")
        self.assertFalse(cold["p99_supported"])
        insufficient = rows[:10]
        self.assertEqual(q3.summary(insufficient)["series"]["warm-process"][q3.MECHANISMS[0]]["latency_ns"]["p99"], "unsupported")

    def test_preregistration_has_no_results_and_fixed_counts(self):
        prereg = json.loads(q3.PROTOCOL.read_text())
        self.assertEqual(prereg["warmups"]["count"], q3.WARMUPS)
        self.assertEqual(q3.WARMUPS, 50)
        self.assertEqual(prereg["measured_trials"]["count"], q3.MEASURED)
        self.assertEqual(q3.MEASURED, 1000)
        self.assertTrue(set(prereg).isdisjoint({"observed_values", "digests", "summary", "confidence_intervals"}))

    def test_regenerate_requires_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises((FileNotFoundError, ValueError)):
                q3.regenerate(type("Args", (), {"output": temporary})())

    def test_raw_schema_is_redacted(self):
        forbidden = {"key", "plaintext", "argv", "endpoint", "loc"}
        allowed = {"schema", "source_identity", "series", "mechanism", "host_epoch", "block", "order", "trial", "excluded", "smoke_non_result", "status", "error_category", "latency_ns", "cpu_ns", "network"}
        self.assertTrue(forbidden.isdisjoint(allowed))
    def test_r8_budget_bucket_and_tls_ticket_controls(self):
        self.assertEqual(q3.R8_BINDING_BUDGET, 1252)
        self.assertEqual(q3.cookie_bucket(lambda: 109.99), 10)
        self.assertEqual(q3.cookie_bucket(lambda: 110.0), 11)
        context = __import__("ssl").SSLContext(__import__("ssl").PROTOCOL_TLS_CLIENT)
        before = context.options
        q3._disable_tickets(context)
        if hasattr(__import__("ssl"), "OP_NO_TICKET"):
            self.assertEqual(context.options & __import__("ssl").OP_NO_TICKET, __import__("ssl").OP_NO_TICKET)
        else:
            self.assertEqual(context.options, before)
    def test_run_creates_missing_nested_output_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "missing" / "nested" / "result"
            args = type("Args", (), {"output": str(destination), "source_identity": "source-A", "host_epoch": "epoch-A", "smoke": True})()
            original_worker, original_trial = q3.invoke_worker, q3.trial
            sample = {"status": "success", "error_category": None, "latency_ns": 1, "cpu_ns": 1, "network": {key: 1 for key in q3.net()}}
            q3.invoke_worker = lambda mechanism: dict(sample)
            q3.trial = lambda mechanism: dict(sample)
            try:
                q3.run(args)
            finally:
                q3.invoke_worker, q3.trial = original_worker, original_trial
            self.assertTrue(destination.is_dir())
            self.assertTrue((destination / "raw.jsonl").is_file())
            manifest = json.loads((destination / "run-manifest.json").read_text())
            self.assertEqual(manifest["schema"], "q3-run-manifest-v1")
            self.assertEqual(manifest["status"], "smoke-non-result")
            self.assertEqual(manifest["row_count"], 8)
            self.assertEqual(len(manifest["group_counts"]), 4)
            for group in manifest["group_counts"]:
                self.assertEqual((group["warmups"], group["measured"], group["rows"]), (2, 0, 2))
            for name, expected in manifest["sha256"].items():
                self.assertEqual(q3.digest(destination / name), expected)
            environment = json.loads((destination / "environment.json").read_text())
            self.assertIn("cryptography", environment["toolchain"])
            self.assertEqual(set(environment["os"]), {"platform", "kernel", "arch"})
            before_manifest = (destination / "run-manifest.json").read_bytes()
            q3.regenerate(type("Args", (), {"output": str(destination)})())
            self.assertEqual((destination / "run-manifest.json").read_bytes(), before_manifest)
            raw = (destination / "raw.jsonl").read_text()
            (destination / "raw.jsonl").write_text("{}\n")
            with self.assertRaises(ValueError):
                q3.regenerate(type("Args", (), {"output": str(destination)})())
            (destination / "raw.jsonl").write_text(raw)
            environment_text = (destination / "environment.json").read_text()
            (destination / "environment.json").write_text("{}\n")
            with self.assertRaises(ValueError):
                q3.regenerate(type("Args", (), {"output": str(destination)})())
            (destination / "environment.json").write_text(environment_text)
