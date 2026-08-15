import hashlib
import importlib.util
import io
import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import builtins
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("q3", ROOT / "bench/q3.py")
q3 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(q3)


class Q3Tests(unittest.TestCase):
    def test_fixture_is_current_ed25519(self):
        cert = x509.load_pem_x509_certificate(q3.CERT.read_bytes())
        self.assertLessEqual(cert.not_valid_before_utc.year, 2026)
        self.assertLess(2026, cert.not_valid_after_utc.year)
        self.assertEqual(cert.public_key().__class__.__name__, "Ed25519PublicKey")
        actual = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(q3._fixture_spki_pin(), hashlib.sha256(actual).hexdigest())
    def test_tls_pin_setup_precedes_measurement_boundary(self):
        original_start = q3._measurement_start
        boundary_started = False
        original_read_bytes = Path.read_bytes
        original_import = builtins.__import__
        original_load_pem = x509.load_pem_x509_certificate
        original_fixture_spki_pin = q3._fixture_spki_pin
        pin_calls = []

        def measurement_start():
            nonlocal boundary_started
            boundary_started = True
            return original_start()

        def guarded_read_bytes(path, *args, **kwargs):
            if boundary_started and path == q3.CERT:
                self.fail("expected certificate read after measurement start")
            return original_read_bytes(path, *args, **kwargs)

        def guarded_import(name, *args, **kwargs):
            if boundary_started and name.startswith("cryptography"):
                self.fail("x509 import after measurement start")
            return original_import(name, *args, **kwargs)

        def guarded_load_pem(*args, **kwargs):
            if boundary_started:
                self.fail("expected-pin derivation after measurement start")
            return original_load_pem(*args, **kwargs)
        def guarded_fixture_spki_pin():
            if boundary_started:
                self.fail("expected-pin derivation after measurement start")
            pin_calls.append(boundary_started)
            return original_fixture_spki_pin()


        with (
            mock.patch.object(q3, "_measurement_start", measurement_start),
            mock.patch.object(Path, "read_bytes", guarded_read_bytes),
            mock.patch.object(builtins, "__import__", guarded_import),
            mock.patch.object(x509, "load_pem_x509_certificate", guarded_load_pem),
            mock.patch.object(q3, "_fixture_spki_pin", guarded_fixture_spki_pin),
        ):
            result = q3.trial(q3.MECHANISMS[1])

        self.assertEqual(result["status"], "success")
        self.assertEqual(pin_calls, [False])

    def test_tls_peer_pin_mismatch_is_failure(self):
        original_load_der = x509.load_der_x509_certificate

        class MismatchedPublicKey:
            def public_bytes(self, *_args):
                return b"mismatched-spki"

        class MismatchedCertificate:
            def __init__(self, certificate):
                self.certificate = certificate

            def public_key(self):
                return MismatchedPublicKey()

        def mismatched_load_der(*args, **kwargs):
            return MismatchedCertificate(original_load_der(*args, **kwargs))

        with mock.patch.object(x509, "load_der_x509_certificate", mismatched_load_der):
            result = q3.trial(q3.MECHANISMS[1])

        self.assertEqual(result["status"], "failure")
        self.assertEqual(result["error_category"], "SSLError")
    def test_source_identity_is_canonical_and_deterministic(self):
        sources = q3.source_hashes()
        expected = "sha256:" + hashlib.sha256(
            json.dumps(sources, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(q3.source_identity(), expected)
        self.assertEqual(q3.source_identity(), q3.source_identity())
        self.assertEqual(set(sources), {
            ".github/workflows/q3-full.yml",
            "bench/fixtures/q3-cert.pem",
            "bench/fixtures/q3-key.pem",
            "bench/protocols/q3.json",
            "bench/protocols/manifest.json",
            "bench/q3.py",
            "reference/r8ref.py",
            "reference/r8session.py",
            "requirements-dev.txt",
            "spec/0004-wire-format-v0.2.md",
            "spec/0005-session-security-v0.1.md",
            "spec/parameters-v0.1.md",
        })

    def test_full_run_rejects_wrong_source_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = type("Args", (), {
                "output": str(Path(temporary) / "result"),
                "source_identity": "sha256:" + "0" * 64,
                "host_epoch": "epoch-A",
                "smoke": False,
                "git_commit": None,
            })()
            with self.assertRaises(ValueError):
                q3.run(args)

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
    def test_r8_handshakes_use_fresh_production_randomness(self):
        original_random = q3.r8._random
        calls = []

        def tracked_random(size):
            value = original_random(size)
            calls.append((size, value))
            return value

        q3.r8._random = tracked_random
        try:
            q3.r8_trial()
            first = list(calls)
            q3.r8_trial()
        finally:
            q3.r8._random = original_random

        expected_lengths = [16, 32, 32, 16, 8, 32, 32, 32, 32]
        self.assertEqual([size for size, _ in first], expected_lengths)
        self.assertEqual([size for size, _ in calls], expected_lengths * 2)
        self.assertNotEqual(int.from_bytes(first[4][1], "big"), 0)
        for (_, previous), (_, current) in zip(first, calls[len(first):]):
            self.assertNotEqual(previous, current)
        source = (ROOT / "bench/q3.py").read_text()
        self.assertNotRegex(source, r"""b["'][BKLQCDEN]["']\s*\*\s*(?:16|32)""")

    def test_r8_retries_zero_scid_with_production_random_helper(self):
        original_random = q3.r8._random
        calls, scid_attempts = [], 0

        def controlled_random(size):
            nonlocal scid_attempts
            calls.append(size)
            if size == 8:
                scid_attempts += 1
                return b"\0" * 8 if scid_attempts == 1 else (1).to_bytes(8, "big")
            return bytes((len(calls),)) * size

        q3.r8._random = controlled_random
        try:
            q3.r8_trial()
        finally:
            q3.r8._random = original_random

        self.assertEqual(calls, [16, 32, 32, 16, 8, 8, 32, 32, 32, 32])
        self.assertEqual(scid_attempts, 2)

    def test_r8_rng_failure_propagates(self):
        original_random = q3.r8._random

        def rng_failure(_size):
            raise q3.r8.SessionError("RNG_FAILURE")

        q3.r8._random = rng_failure
        try:
            with self.assertRaises(q3.r8.SessionError) as raised:
                q3.r8_trial()
        finally:
            q3.r8._random = original_random

        self.assertEqual(raised.exception.category, "RNG_FAILURE")
    def test_r8_client_randomness_starts_at_measurement_boundary(self):
        original_random = q3.r8._random
        original_measurement_start = q3._measurement_start
        calls = []
        boundary_started = False

        def measurement_start():
            nonlocal boundary_started
            boundary_started = True
            return original_measurement_start()

        def tracked_random(size):
            calls.append((size, boundary_started))
            return original_random(size)

        q3._measurement_start = measurement_start
        q3.r8._random = tracked_random
        try:
            result = q3.trial(q3.MECHANISMS[0])
        finally:
            q3.r8._random = original_random
            q3._measurement_start = original_measurement_start

        self.assertEqual(result["status"], "success")
        self.assertEqual([size for size, _ in calls], [16, 32, 32, 16, 8, 32, 32, 32, 32])
        self.assertEqual([started for _, started in calls], [False, False, False, False, True, True, True, True, True])
    def test_client_trust_and_configuration_are_prebound(self):
        r8_setup = inspect.getsource(q3._r8_server_ready)
        tls_setup = inspect.getsource(q3._tls_server_ready)
        r8_client = r8_setup.split("def client():", 1)[1]
        tls_client = tls_setup.split("def client():", 1)[1]

        self.assertLess(r8_setup.index("machine = r8.ClientMachine"), r8_setup.index("def client"))
        self.assertLess(tls_setup.index("context = ssl.create_default_context"), tls_setup.index("def client"))
        self.assertNotIn("ClientMachine", r8_client)
        self.assertNotIn("create_default_context", tls_client)
        self.assertIn("machine.start(_random_scid())", r8_client)
        self.assertIn("socket.create_connection", tls_client)
        self.assertIn("context.wrap_socket", tls_client)
    def test_trial_uses_the_same_post_readiness_boundary_for_both_mechanisms(self):
        original_r8_ready, original_tls_ready = q3._r8_server_ready, q3._tls_server_ready
        original_measurement_start = q3._measurement_start
        events = []

        def ready(name):
            events.append(name + "-ready")
            def client():
                events.append(name + "-client")
                return {key: 0 for key in q3.net()}, 0, 0
            client.close = lambda: events.append(name + "-close")
            client.join = lambda: events.append(name + "-join")
            return client

        def measurement_start():
            events.append("measurement-start")
            return {key: 0 for key in q3.net()}, 0, 0

        q3._r8_server_ready = lambda: ready("r8")
        q3._tls_server_ready = lambda: ready("tls")
        q3._measurement_start = measurement_start
        try:
            for mechanism, name in zip(q3.MECHANISMS, ("r8", "tls")):
                events.clear()
                result = q3.trial(mechanism)
                self.assertEqual(result["status"], "success")
                self.assertEqual(events, [name + "-ready", "measurement-start", name + "-client", name + "-close", name + "-join"])
        finally:
            q3._r8_server_ready, q3._tls_server_ready = original_r8_ready, original_tls_ready
            q3._measurement_start = original_measurement_start

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

    def test_censor_aware_summary_and_nonestimable_cells(self):
        rows = []
        for block in range(10):
            for mechanism in q3.MECHANISMS:
                for _ in range(10):
                    rows.append({"series": "warm-process", "mechanism": mechanism, "excluded": False, "block": block, "status": "success", "latency_ns": 10 + block, "cpu_ns": 1, "network": {k: 1 for k in q3.net()}})
                    rows.append({"series": "cold-process-primary", "mechanism": mechanism, "excluded": False, "block": block, "status": "timeout", "latency_ns": 5_000_000_000, "cpu_ns": 1, "network": {k: 1 for k in q3.net()}})
        rows.append({"series": "warm-process", "mechanism": q3.MECHANISMS[0], "excluded": False, "block": 0, "status": "timeout", "latency_ns": 5_000_000_000, "cpu_ns": 7, "network": {k: 3 for k in q3.net()}})
        result = q3.summary(rows)
        warm = result["series"]["warm-process"][q3.MECHANISMS[0]]
        cold = result["series"]["cold-process-primary"][q3.MECHANISMS[0]]
        self.assertEqual(warm["latency_ns"]["estimator"], "kaplan-meier-right-censored")
        self.assertTrue(warm["latency_ns"]["confidence_intervals_95"]["p50"])
        self.assertGreater(warm["failure_rate"], 0)
        self.assertIsNone(cold["latency_ns"]["p50"])
        self.assertIsNone(cold["latency_ns"]["confidence_intervals_95"]["p50"])
        self.assertEqual(set(warm["latency_ns"]), {"estimator", "p50", "p90", "confidence_intervals_95"})
        self.assertGreater(warm["mean_cpu_ns"], 1)
        self.assertGreater(warm["mean_network"]["rx_bytes"], 1)

    def test_post_start_failure_retains_observed_deltas(self):
        start = ({key: 10 for key in q3.net()}, 20, 30)
        end = ({key: 14 for key in q3.net()}, 25, 40)
        original_ready, original_start, original_end = q3._tls_server_ready, q3._measurement_start, q3._measurement_end
        def broken():
            raise RuntimeError("broken")
        broken.close = lambda: None
        broken.join = lambda: None
        q3._tls_server_ready = lambda: broken
        q3._measurement_start = lambda: start
        q3._measurement_end = lambda: end
        try:
            result = q3.trial(q3.MECHANISMS[1])
        finally:
            q3._tls_server_ready, q3._measurement_start, q3._measurement_end = original_ready, original_start, original_end
        self.assertEqual((result["status"], result["error_category"]), ("failure", "RuntimeError"))
        self.assertEqual((result["latency_ns"], result["cpu_ns"]), (10, 5))
        self.assertEqual(result["network"], {key: 4 for key in q3.net()})

    def test_setup_failure_is_separately_typed(self):
        original_ready = q3._tls_server_ready
        q3._tls_server_ready = lambda: (_ for _ in ()).throw(RuntimeError("setup"))
        try:
            result = q3.trial(q3.MECHANISMS[1])
        finally:
            q3._tls_server_ready = original_ready
        self.assertEqual(result["error_category"], "setup:RuntimeError")
        self.assertEqual((result["latency_ns"], result["cpu_ns"]), (0, 0))
    def test_cold_normal_exit_returns_authoritative_child_snapshot(self):
        parent, child = q3.socket.socketpair()
        marker = {"network": {key: 10 for key in q3.LO_COUNTERS}, "cpu_ns": 20, "started_ns": q3.time.monotonic_ns()}
        child.sendall(json.dumps(marker).encode())
        snapshot = {"status": "success", "error_category": None, "latency_ns": 41, "cpu_ns": 42, "network": {key: 43 for key in q3.LO_COUNTERS}}
        process = type("Process", (), {"pid": 123, "stdout": io.StringIO(json.dumps(snapshot))})()
        usage = type("Usage", (), {"ru_utime": 99, "ru_stime": 99})()
        with (
            mock.patch.object(q3.socket, "socketpair", return_value=(parent, child)),
            mock.patch.object(q3.subprocess, "Popen", return_value=process),
            mock.patch.object(q3.os, "wait4", return_value=(123, 0, usage)),
            mock.patch.object(q3, "_measurement_end", return_value=({key: 100 for key in q3.LO_COUNTERS}, 100, 100)) as measurement_end,
        ):
            self.assertEqual(q3.invoke_worker(q3.MECHANISMS[0]), snapshot)
            measurement_end.assert_not_called()

    def test_readiness_factory_failures_join_started_threads_boundedly(self):
        threads = []

        class Thread:
            def __init__(self, target):
                self.target, self.join_timeouts = target, []

            def start(self):
                pass

            def join(self, timeout):
                self.join_timeouts.append(timeout)

        def make_thread(*args, **kwargs):
            thread = Thread(*args, **kwargs)
            threads.append(thread)
            return thread

        with mock.patch.object(q3.threading, "Thread", side_effect=make_thread), mock.patch.object(q3, "TIMEOUT", 0):
            for factory in (q3._r8_server_ready, q3._tls_server_ready):
                with self.assertRaises(TimeoutError):
                    factory()
        self.assertEqual([thread.join_timeouts for thread in threads], [[0], [0]])

    def test_post_ready_construction_failures_terminate_server_threads(self):
        actual_thread, threads = q3.threading.Thread, []

        def make_thread(*args, **kwargs):
            thread = actual_thread(*args, **kwargs)
            threads.append(thread)
            return thread

        with mock.patch.object(q3.threading, "Thread", side_effect=make_thread):
            with mock.patch.object(q3.r8, "ClientMachine", side_effect=RuntimeError("R8 client setup")):
                with self.assertRaisesRegex(RuntimeError, "R8 client setup"):
                    q3._r8_server_ready()
            self.assertFalse(threads[-1].is_alive())
            with mock.patch.object(q3.ssl, "create_default_context", side_effect=RuntimeError("TLS client setup")):
                with self.assertRaisesRegex(RuntimeError, "TLS client setup"):
                    q3._tls_server_ready()
            self.assertFalse(threads[-1].is_alive())

    def test_validator_requires_exact_runtime_outcome(self):
        source_identity = "sha256:" + "0" * 64
        rows = []
        for series in ("cold-process-primary", "warm-process"):
            for block, position, mechanism, ordinal, excluded in q3.planned_trials(q3.WARMUPS + q3.MEASURED, False):
                failed = series == "cold-process-primary" and mechanism == q3.MECHANISMS[0] and ordinal == q3.WARMUPS
                rows.append({"schema": "q3-raw-v1", "source_identity": source_identity, "series": series, "mechanism": mechanism, "host_epoch": "closed-lab-epoch-001", "block": block, "order": position, "trial": ordinal, "excluded": excluded, "smoke_non_result": False, "status": "failure" if failed else "success", "error_category": "RuntimeError" if failed else None, "latency_ns": 1, "cpu_ns": 0, "network": {key: 0 for key in q3.net()}})
        groups = [{"series": series, "mechanism": mechanism, "warmups": 50, "measured": 1000, "rows": 1050, "failures": sum(row["series"] == series and row["mechanism"] == mechanism and row["status"] != "success" for row in rows)} for series in ("cold-process-primary", "warm-process") for mechanism in q3.MECHANISMS]
        manifest = {"status": "completed-evidence", "source_identity": source_identity, "host_epoch": "closed-lab-epoch-001", "git_commit": "0" * 40, "isolated_netns_proof": True, "group_counts": groups, "row_count": 4200, "failures": 1, "post_hoc_exclusions": 0, "publication_eligible": True, "runtime_outcome": "success"}
        saved = {"source_identity": source_identity, "isolated_netns_proof": True, "loopback_interface": "lo", "loopback_mtu": 65536}
        with self.assertRaisesRegex(ValueError, "completed evidence status"):
            q3._validate_rows(manifest, saved, rows)
    def test_full_validator_retains_mixed_outcomes(self):
        source_identity = "sha256:" + "0" * 64
        rows = []
        for series in ("cold-process-primary", "warm-process"):
            for block, position, mechanism, ordinal, excluded in q3.planned_trials(q3.WARMUPS + q3.MEASURED, False):
                setup_failure = series == "cold-process-primary" and mechanism == q3.MECHANISMS[0] and ordinal == q3.WARMUPS
                rows.append({"schema": "q3-raw-v1", "source_identity": source_identity, "series": series, "mechanism": mechanism, "host_epoch": "closed-lab-epoch-001", "block": block, "order": position, "trial": ordinal, "excluded": excluded, "smoke_non_result": False, "status": "failure" if setup_failure else "success", "error_category": "setup:RuntimeError" if setup_failure else None, "latency_ns": 0 if setup_failure else 1, "cpu_ns": 0, "network": {key: 0 for key in q3.net()}})
        groups = []
        for series in ("cold-process-primary", "warm-process"):
            for mechanism in q3.MECHANISMS:
                group = [row for row in rows if row["series"] == series and row["mechanism"] == mechanism]
                groups.append({"series": series, "mechanism": mechanism, "warmups": 50, "measured": 1000, "rows": 1050, "failures": sum(row["status"] != "success" for row in group)})
        manifest = {"status": "completed-evidence", "source_identity": source_identity, "host_epoch": "closed-lab-epoch-001", "git_commit": "0" * 40, "isolated_netns_proof": True, "group_counts": groups, "row_count": 4200, "failures": 1, "post_hoc_exclusions": 0, "publication_eligible": True, "runtime_outcome": "failures-retained"}
        saved = {"source_identity": source_identity, "isolated_netns_proof": True, "loopback_interface": "lo", "loopback_mtu": 65536}
        q3._validate_rows(manifest, saved, rows)
    def test_workflow_accepts_zero_delta_setup_failures_and_exact_outcomes(self):
        workflow = (ROOT / ".github/workflows/q3-full.yml").read_text()
        self.assertNotIn('row["status"] == "success" or row["latency_ns"] > 0', workflow)
        self.assertIn('manifest["runtime_outcome"] == ("success" if manifest["failures"] == 0 else "failures-retained")', workflow)

    def test_setup_categories_are_prefixed_once(self):
        result = q3._measurement_result("failure", "worker_marker_invalid", None, None, None)
        self.assertEqual(result["error_category"], "setup:worker_marker_invalid")
    def test_noncurrent_source_bound_package_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source_identity = "source-A"
            historical_sources = {key: "0" * 64 for key in q3.SOURCE_INPUTS}
            implementation_identity = q3.implementation_source_identity(historical_sources)
            rows = []
            for series in ("cold-process-primary", "warm-process"):
                for block, position, mechanism, ordinal, excluded in q3.planned_trials(2, True):
                    rows.append({"schema": "q3-raw-v1", "source_identity": source_identity, "series": series, "mechanism": mechanism, "host_epoch": "epoch-A", "block": block, "order": position, "trial": ordinal, "excluded": excluded, "smoke_non_result": True, "status": "success", "error_category": None, "latency_ns": 1, "cpu_ns": 1, "network": {key: 0 for key in q3.net()}})
            environment = {"source_identity": source_identity, "isolated_netns_proof": True, "loopback_interface": "lo", "loopback_mtu": 65536, "implementation_sources": historical_sources, "implementation_source_identity": implementation_identity}
            (directory / "raw.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
            (directory / "environment.json").write_text(json.dumps(environment, sort_keys=True) + "\n")
            (directory / "summary.json").write_text('{"historical":"v8"}\n')
            manifest = {"schema": "q3-run-manifest-v1", "status": q3.SMOKE_STATUS, "runtime_outcome": q3.SMOKE_STATUS, "source_identity": source_identity, "implementation_sources": historical_sources, "implementation_source_identity": implementation_identity, "host_epoch": "epoch-A", "git_commit": None, "isolated_netns_proof": True, "group_counts": [{"series": series, "mechanism": mechanism, "warmups": 0, "measured": 2, "rows": 2, "failures": 0} for series in ("cold-process-primary", "warm-process") for mechanism in q3.MECHANISMS], "row_count": 8, "failures": 0, "post_hoc_exclusions": 0, "sha256": {name: q3.digest(directory / name) for name in ("raw.jsonl", "environment.json", "summary.json")}}
            (directory / "run-manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
            with self.assertRaisesRegex(ValueError, "current implementation"):
                q3.regenerate(type("Args", (), {"output": str(directory)})())

    def test_preregistration_has_no_results_and_fixed_counts(self):
        prereg = json.loads(q3.PROTOCOL.read_text())
        self.assertEqual(prereg["warmups"]["count"], q3.WARMUPS)
        self.assertEqual(q3.WARMUPS, 50)
        self.assertEqual(prereg["measured_trials"]["count"], q3.MEASURED)
        self.assertEqual(q3.MEASURED, 1000)
        self.assertEqual(prereg["analysis"]["quantiles"], ["p50", "p90"])
        self.assertEqual(prereg["analysis"]["estimators"][1], "Kaplan-Meier-right-censored-latency-quantiles")
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
        q3._disable_tickets(context)
        self.assertEqual(context.options & __import__("ssl").OP_NO_TICKET, __import__("ssl").OP_NO_TICKET)
        with mock.patch.object(q3.ssl, "OP_NO_TICKET", new=None):
            with self.assertRaises(RuntimeError):
                q3._disable_tickets(context)
    def test_tls_server_tickets_fail_closed(self):
        class Context:
            num_tickets = 1
        context = Context()
        q3._disable_server_tickets(context)
        self.assertEqual(context.num_tickets, 0)
        with self.assertRaises(RuntimeError):
            q3._disable_server_tickets(object())

        class Ineffective:
            @property
            def num_tickets(self):
                return 1
            @num_tickets.setter
            def num_tickets(self, _value):
                pass
        with self.assertRaises(RuntimeError):
            q3._disable_server_tickets(Ineffective())

    def test_warm_cleanup_is_outside_the_snapshot_and_unconditional(self):
        source = inspect.getsource(q3._attempt)
        cleanup = source.index("client.close()")
        self.assertLess(source.index("snapshot = client()"), cleanup)
        self.assertLess(source.index("except TimeoutError"), cleanup)
        self.assertLess(source.index("except Exception"), cleanup)
        self.assertEqual(source.count("_measurement_end()"), 2)
        self.assertLess(source.rindex("_measurement_end()"), cleanup)
        self.assertLess(source.index("finally:"), cleanup)
        self.assertLess(cleanup, source.index("client.join()"))
    def test_run_creates_missing_nested_output_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "missing" / "nested" / "result"
            args = type("Args", (), {"output": str(destination), "source_identity": "source-A", "host_epoch": "epoch-A", "git_commit": None, "smoke": True})()
            original_worker, original_trial = q3.invoke_worker, q3.trial
            sample = {"status": "success", "error_category": None, "latency_ns": 1, "cpu_ns": 1, "network": {key: 1 for key in q3.net()}}
            q3.invoke_worker = lambda mechanism: dict(sample)
            q3.trial = lambda mechanism: dict(sample)
            try:
                with mock.patch.object(q3, "isolated_netns_proof", return_value=True):
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
            self.assertEqual(manifest["source_identity"], "source-A")
            for group in manifest["group_counts"]:
                self.assertEqual((group["warmups"], group["measured"], group["rows"]), (0, 2, 2))
            for name, expected in manifest["sha256"].items():
                self.assertEqual(q3.digest(destination / name), expected)
            environment = json.loads((destination / "environment.json").read_text())
            self.assertIn("cryptography", environment["toolchain"])
            self.assertEqual(set(environment["os"]), {"platform", "kernel", "arch"})
            self.assertEqual(environment["implementation_source_identity"], q3.source_identity())
            self.assertEqual(environment["implementation_sources"], q3.source_hashes())
            self.assertNotIn("fixture_spki_sha256", environment)
            before_manifest = (destination / "run-manifest.json").read_bytes()
            q3.regenerate(type("Args", (), {"output": str(destination)})())
            self.assertEqual((destination / "run-manifest.json").read_bytes(), before_manifest)
            raw = (destination / "raw.jsonl").read_text()
            (destination / "raw.jsonl").write_text("{}\n")
            with self.assertRaises(ValueError):
                q3.regenerate(type("Args", (), {"output": str(destination)})())
            (destination / "raw.jsonl").write_text(raw)
            environment_path = destination / "environment.json"
            environment_text = environment_path.read_text()
            manifest_path = destination / "run-manifest.json"
            manifest_text = manifest_path.read_text()
            for source in ("requirements-dev.txt", "reference/r8ref.py", "reference/r8session.py"):
                tampered = json.loads(environment_text)
                tampered["implementation_sources"][source] = "0" * 64
                environment_path.write_text(json.dumps(tampered, sort_keys=True, indent=2) + "\n")
                changed_manifest = json.loads(manifest_text)
                changed_manifest["sha256"]["environment.json"] = q3.digest(environment_path)
                manifest_path.write_text(json.dumps(changed_manifest, sort_keys=True, indent=2) + "\n")
                with self.subTest(source=source):
                    with self.assertRaises(ValueError):
                        q3.regenerate(type("Args", (), {"output": str(destination)})())
                environment_path.write_text(environment_text)
                manifest_path.write_text(manifest_text)
            changed_manifest = json.loads(manifest_text)
            changed_manifest["post_hoc_exclusions"] = 1
            manifest_path.write_text(json.dumps(changed_manifest, sort_keys=True, indent=2) + "\n")
            with self.assertRaises(ValueError):
                q3.regenerate(type("Args", (), {"output": str(destination)})())
            manifest_path.write_text(manifest_text)
            changed_rows = [json.loads(line) for line in raw.splitlines()]
            changed_rows[0]["latency_ns"] = -1
            (destination / "raw.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in changed_rows))
            changed_manifest = json.loads(manifest_text)
            changed_manifest["sha256"]["raw.jsonl"] = q3.digest(destination / "raw.jsonl")
            manifest_path.write_text(json.dumps(changed_manifest, sort_keys=True, indent=2) + "\n")
            with self.assertRaises(ValueError):
                q3.regenerate(type("Args", (), {"output": str(destination)})())
    def test_clean_repository_gate_includes_tracked_and_untracked_changes(self):
        command = ["status", "--porcelain", "--untracked-files=all"]
        for status in (" M reference/r8ref.py", "?? untracked-evidence"):
            with self.subTest(status=status), mock.patch.object(
                q3, "_git", return_value=status
            ) as git:
                with self.assertRaisesRegex(ValueError, "clean repository"):
                    q3.require_clean_repository(
                        "full package regeneration requires a clean repository")
                git.assert_called_once_with(command)
        with mock.patch.object(q3, "_git", return_value="") as git:
            q3.require_clean_repository("full run requires a clean repository")
            git.assert_called_once_with(command)
    def test_isolation_and_labels_fail_closed(self):
        for source_identity, host_epoch in (("unsafe label", "epoch-A"), ("source.label", "epoch-A"), ("source-A", "epoch/A")):
            args = type("Args", (), {"source_identity": source_identity, "host_epoch": host_epoch, "git_commit": None, "smoke": True})()
            with self.subTest(source_identity=source_identity, host_epoch=host_epoch):
                with self.assertRaises(ValueError):
                    q3.require_labels(args)
        with mock.patch.object(q3, "isolated_netns_proof", return_value=False):
            with self.assertRaises(ValueError):
                q3.require_isolated_netns()

    def test_isolation_uses_current_netns_proc_and_ioctl_not_sysfs(self):
        stat = type("Stat", (), {"st_ino": 1})
        proc = "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n lo: 10 11 0 0 0 0 0 0 12 13 0 0 0 0 0 0\n"

        def read_text(path, *_args, **_kwargs):
            self.assertEqual(str(path), "/proc/net/dev")
            return proc

        with (
            mock.patch.dict(q3.os.environ, {"Q3_ISOLATED_NETNS": "1"}),
            mock.patch.object(q3.os, "stat", side_effect=[stat(), type("Stat", (), {"st_ino": 2})()]),
            mock.patch.object(q3, "_loopback_flags_mtu", return_value=(1, 65536)),
            mock.patch.object(Path, "read_text", autospec=True, side_effect=read_text),
        ):
            self.assertTrue(q3.isolated_netns_proof())

    def test_proc_net_dev_maps_loopback_without_rejecting_worker_interfaces(self):
        valid = "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n lo: 10 11 0 0 0 0 0 0 12 13 0 0 0 0 0 0\n eth0: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n"
        with mock.patch.object(Path, "read_text", autospec=True, return_value=valid):
            self.assertEqual(q3.net(), {"rx_bytes": 10, "rx_packets": 11, "tx_bytes": 12, "tx_packets": 13})
        for content in (
            "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n lo: 10 not-a-counter\n",
            "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n eth0: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n",
        ):
            with self.subTest(content=content), mock.patch.object(Path, "read_text", autospec=True, return_value=content):
                with self.assertRaises(ValueError):
                    q3.net()
        malformed_header = "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier wrong\n lo: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n"
        with mock.patch.object(Path, "read_text", autospec=True, return_value=malformed_header):
            with self.assertRaises(ValueError):
                q3.net()

    def test_isolation_rejects_extra_proc_interfaces(self):
        stat = type("Stat", (), {"st_ino": 1})
        with (
            mock.patch.dict(q3.os.environ, {"Q3_ISOLATED_NETNS": "1"}),
            mock.patch.object(q3.os, "stat", side_effect=[stat(), type("Stat", (), {"st_ino": 2})()]),
            mock.patch.object(q3, "_loopback_flags_mtu", return_value=(1, 65536)),
            mock.patch.object(q3, "_proc_net_dev", return_value=({"lo", "eth0"}, {"rx_bytes": 0, "rx_packets": 0, "tx_bytes": 0, "tx_packets": 0})),
        ):
            self.assertFalse(q3.isolated_netns_proof())

    def test_loopback_ioctl_flags_and_mtu_are_required(self):
        stat = type("Stat", (), {"st_ino": 1})
        with (
            mock.patch.dict(q3.os.environ, {"Q3_ISOLATED_NETNS": "1"}),
            mock.patch.object(q3.os, "stat", side_effect=[stat(), type("Stat", (), {"st_ino": 2})()]),
            mock.patch.object(q3, "_proc_net_dev", return_value=({"lo"}, {"rx_bytes": 0, "rx_packets": 0, "tx_bytes": 0, "tx_packets": 0})),
            mock.patch.object(q3, "_loopback_flags_mtu", return_value=(0, 65536)),
        ):
            self.assertFalse(q3.isolated_netns_proof())
        with (
            mock.patch.dict(q3.os.environ, {"Q3_ISOLATED_NETNS": "1"}),
            mock.patch.object(q3.os, "stat", side_effect=[stat(), type("Stat", (), {"st_ino": 2})()]),
            mock.patch.object(q3, "_proc_net_dev", return_value=({"lo"}, {"rx_bytes": 0, "rx_packets": 0, "tx_bytes": 0, "tx_packets": 0})),
            mock.patch.object(q3, "_loopback_flags_mtu", return_value=(1, 1500)),
        ):
            self.assertFalse(q3.isolated_netns_proof())

    def test_loopback_delta_requires_symmetric_counters(self):
        q3.require_loopback_delta({"rx_bytes": 1, "tx_bytes": 1, "rx_packets": 2, "tx_packets": 2})
        with self.assertRaises(ValueError):
            q3.require_loopback_delta({"rx_bytes": 1, "tx_bytes": 2, "rx_packets": 1, "tx_packets": 1})
    def test_cold_worker_marker_owns_post_start_exposure_and_child_cpu(self):
        source = inspect.getsource(q3.invoke_worker)
        self.assertIn("select.select([parent], [], [], TIMEOUT)", source)
        self.assertIn("started + int(TIMEOUT * 1_000_000_000)", source)
        self.assertIn("usage.ru_utime + usage.ru_stime", source)
        self.assertNotIn("_supervisor_cpu - child_cpu", source)

    def test_current_q3_and_v8_history_are_explicitly_separated(self):
        registry = json.loads((ROOT / "bench/protocols/manifest.json").read_text())
        entry = next(item for item in registry["preregistrations"] if item["protocol_id"] == "Q3")
        historical = entry["prior_source_evidence"][0]
        self.assertEqual(entry["status"], "frozen-preregistered-no-current-source-results")
        self.assertEqual(historical["contract_sha256"], "86de498d4690d9de98333d8a99b74c985e8561e57f060b7c6bb68a833ba58cbf")
        self.assertEqual(historical["contract_size_bytes"], 3014)
        self.assertIn("does not evidence the current censor-aware Q3 contract", historical["interpretation"])

    def test_strict_source_key_sets_and_full_public_binding_are_required(self):
        source = inspect.getsource(q3.regenerate)
        self.assertIn("recorded_keys != set(SOURCE_INPUTS)", source)
        self.assertIn("package is not bound to the current implementation", source)
        self.assertIn("require_frozen_protocol()", source)
        self.assertIn("full package public source identity binding verification failed", source)
        self.assertIn("recorded component hash verification failed", source)
