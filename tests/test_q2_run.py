import importlib.util
import inspect
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("q2_run", ROOT / "bench/q2_run.py")
q2_run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q2_run)


class Q2RunTests(unittest.TestCase):
    def test_type7(self):
        self.assertEqual(q2_run.type7([0, 10], .5), 5)
        self.assertEqual(q2_run.type7([], .95), None)
    def test_preflight_requires_namespace_sysctl_dependency(self):
        self.assertIn('"sysctl"', inspect.getsource(q2_run.preflight))

    def test_atomic_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / "output"
            target.mkdir()
            with self.assertRaisesRegex(RuntimeError, "output-exists"):
                q2_run.atomic_output(target, lambda _: None)

    def test_gate_rejects_unbound_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "gate.json"
            path.write_text(json.dumps({"ok": True, "binary_hash": "1" * 64,
                                        "privilege_dropped": True, "revocation_verified": True,
                                        "cleanup_verified": True, "counts": {}}))
            with self.assertRaisesRegex(RuntimeError, "gate-evidence"):
                q2_run.gate(path, "0" * 64, "gate4-one")
    def test_gate5_requires_exact_independently_recomputed_success_evidence(self):
        counts = {"frames_sent": 27, "frames_received": 27,
                  "application_deliveries": 6, "suppressions": 5,
                  "rust_endpoint_authentications": 1, "cached_retries": 1,
                  "degraded_events": 2, "path_removals": 2,
                  "negative_drops": 4, "budget_rejects": 1,
                  "daemon_exits": 2, "cleanup_failures": 0}
        value = {"ok": True, "error_category": None, "counts": counts,
                 "source_hash": q2_run.gate5_native.aggregate_hash(
                     "r8-redundant-source-v1", q2_run.gate5_native.source_records()),
                 "binary_hash": "b" * 64, "endpoint_binary_hash": "e" * 64,
                 "manifest_hash": q2_run._expected_gate5_manifest_hash(),
                 "filter_hash": q2_run._expected_filter_hash(),
                 "interface_ordinals": [2, 3, 4, 5],
                 "privilege_dropped": True, "revocation_verified": True,
                 "cleanup_verified": True}
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "gate.json"
            path.write_text(q2_run.canonical(value) + "\n")
            self.assertEqual(q2_run.gate(path, "b" * 64, "gate5", "e" * 64),
                             q2_run.file_sha(path))
            for field, bad in (("manifest_hash", "0" * 64),
                               ("filter_hash", "0" * 64),
                               ("interface_ordinals", [2, 3, 4]),
                               ("counts", {**counts, "cleanup_failures": 1}),
                               ("revocation_verified", False)):
                hostile = dict(value)
                hostile[field] = bad
                path.write_text(q2_run.canonical(hostile) + "\n")
                with self.assertRaisesRegex(RuntimeError, "gate-evidence"):
                    q2_run.gate(path, "b" * 64, "gate5", "e" * 64)

    def test_gate_manifest_hash_goldens_match_hosted_workflow(self):
        self.assertEqual(q2_run._expected_gate4_manifest_hash(1),
                         "e61d83820cb1e2b3da44d03dd75975e2f26ffad83e202048b4367d8f48eab375")
        self.assertEqual(q2_run._expected_gate4_manifest_hash(2),
                         "9b7331a01c0fd5d047188d2c612a94a39279384548def887af9cff29fd932374")
        self.assertEqual(q2_run._expected_gate5_manifest_hash(),
                         "77f608ffc3c7deec66680f21553e85d19819f8378e78880a48d8495f996710f8")
        workflow = (ROOT / ".github/workflows/q2-full.yml").read_text()
        self.assertIn("gate5_run:", workflow)
        self.assertIn('test "$(jq -r .name <<<"$RUN")" = "Native full"', workflow)
        self.assertIn('test "$(jq -r .head_sha <<<"$RUN")" = "$GITHUB_SHA"', workflow)
    def test_trial_supervisor_bounds_observation_and_emergency_cleanup(self):
        source = inspect.getsource(q2_run.execute_trial)
        self.assertIn("lab.drain(supervisor_deadline)", source)
        self.assertIn("lab.state_digests(supervisor_deadline)", source)
        self.assertIn("lab.counters(supervisor_deadline)", source)
        self.assertIn("emergency_deadline = raw_ns() + 3_000_000_000", source)
        self.assertIn("lab.clean_qdisc(cleanup_deadline)", source)
        self.assertIn("lab.state_digests(cleanup_deadline)", source)
        self.assertIn("finally:", source)
        self.assertIn("endpoint.terminate()", source)
        self.assertIn("endpoint.kill()", source)
        self.assertIn("endpoint.close()", source)

    def test_admission_drain_and_cpu_baseline_ordering(self):
        source = inspect.getsource(q2_run.execute_trial)
        child_start = source.index("endpoint.start()")
        admission_ready = source.index("ready.wait")
        drains = [index for index in range(len(source)) if source.startswith("lab.drain", index)]
        post_admission_drain = drains[1]
        origin = source.index("origin.value =")
        gate = source.index("gate.set()", origin)
        parent_baseline = source.index("_resource_snapshot(lab)", gate)
        qdisc = source.index("lab.qdisc")
        self.assertLess(drains[0], child_start)
        self.assertLess(admission_ready, post_admission_drain)
        self.assertLess(post_admission_drain, origin)
        self.assertLess(origin, gate)
        self.assertLess(gate, parent_baseline)
        self.assertLess(parent_baseline, qdisc)
        endpoint = inspect.getsource(q2_run._trial_endpoint_process)
        self.assertLess(endpoint.index("gate.wait"), endpoint.index("child_before"))
        self.assertIn("child_cpu[0]", source)
        self.assertNotIn("RUSAGE_CHILDREN", inspect.getsource(q2_run._resource_snapshot))

    def test_summary_excludes_warmup(self):
        rows = []
        for seed in (0, 20):
            for mechanism in q2_run.q2.MECHANISMS:
                rows.append({"trial_id": f"{seed:064x}", "seed": seed,
                             "block": seed // 20, "condition": "no-flap",
                             "mechanism": mechanism, "status": "completed",
                             "lost_packets": 0, "recovery_eligible": False,
                             "recovery_relative_ns": None})
        values = q2_run.summary(rows, [], bootstrap_resamples=1)
        self.assertEqual(next(item for item in values
                              if item.get("condition") == "no-flap"
                              and item.get("mechanism") == "REDUNDANT")["trial_denominator"], 1)

    def test_source_identity_binds_real_endpoint_and_native_daemon(self):
        sources = q2_run.source_hashes()
        self.assertIn("reference/r8redundant.py", sources)
        self.assertIn("rust/crates/r8d/src/native.rs", sources)
        self.assertIn("bench/q2_run.py", sources)
        self.assertNotIn("bench/q2_endpoint.py", sources)
        self.assertEqual(len(q2_run.source_identity()), 71)

    def test_packet_payload_is_fixed_and_indexed(self):
        first = q2_run._payload(7, 12)
        self.assertEqual(len(first), 64)
        self.assertEqual(int.from_bytes(first[:4], "big"), 12)
        self.assertEqual(first, q2_run._payload(7, 12))
        self.assertNotEqual(first, q2_run._payload(7, 13))

    def test_live_security_material_is_fresh_and_admission_is_authenticated(self):
        plan = next(row for row in q2_run.q2.plan_rows()
                    if row["mechanism"] == "REDUNDANT")
        original_token, original_below, original_session_random = (
            q2_run.secrets.token_bytes, q2_run.secrets.randbelow,
            q2_run.session._random)
        calls = []
        seeds = iter((100, 200))
        def token_bytes(length):
            calls.append(length)
            return bytes([len(calls) % 255 or 1]) * length
        q2_run.secrets.token_bytes = token_bytes
        q2_run.secrets.randbelow = lambda bound: next(seeds)
        q2_run.session._random = token_bytes
        source = destination = None
        try:
            class FakeTransport:
                def __init__(self):
                    self.calls = []

                def transfer(self, name, packet):
                    self.calls.append((name, packet))
                    _, _, _, _, _, peer, descriptor = q2_run._control_specs(plan["seed"])[name]
                    return packet, q2_run._binding(descriptor, q2_run._mac(plan["seed"], peer))

            transport = FakeTransport()
            source, destination, mapping, _ = q2_run._states(plan, transport)
            self.assertEqual(mapping, {0: 0, 1: 1})
            self.assertEqual(q2_run.redundant._REDUNDANT_CORES[source]._next_delivery_id, 104)
            self.assertEqual(q2_run.redundant._REDUNDANT_CORES[destination]._next_delivery_id, 203)
        finally:
            q2_run.secrets.token_bytes, q2_run.secrets.randbelow = (
                original_token, original_below)
            q2_run.session._random = original_session_random
            if source is not None: source.close()
            if destination is not None: destination.close()
        self.assertGreaterEqual(calls.count(32), 8)
        self.assertIn(8, calls)
        self.assertIn(16, calls)
        state_source = inspect.getsource(q2_run._states)
        for label in ("scid", "boot", "cookie", "limiter", "client-x25519",
                      "client-nonce", "server-x25519", "server-nonce",
                      "candidate-source", "candidate-destination", "candidate-id", "probe"):
            self.assertNotIn(f'_material(seed, trial_id, "{label}"', state_source)
        state_source = inspect.getsource(q2_run._states)
        self.assertIn("control_transport.transfer", state_source)
        self.assertIn("preview_mobility", state_source)
        self.assertNotIn("object()", state_source)
        self.assertEqual([name for name, _ in transport.calls],
                         ["update", "probe", "challenge", "response", "result"])
        self.assertTrue(all(packet for _, packet in transport.calls))
        self.assertEqual(
            [q2_run._control_specs(plan["seed"])[name][:2] for name, _ in transport.calls],
            [("source-A", "destination-A"), ("source-B", "destination-B"),
             ("destination-B", "source-B"), ("source-B", "destination-B"),
             ("destination-B", "source-B")])
        self.assertEqual(
            [q2_run._control_specs(plan["seed"])[name][5:] for name, _ in transport.calls],
            [(2, 4), (6, 8), (5, 5), (6, 8), (5, 5)])
        with self.assertRaisesRegex(RuntimeError, "admission-transport"):
            q2_run._states(plan)
    def test_setup_failure_rows_are_schema_and_relation_complete(self):
        plan = next(q2_run.q2.plan_rows())
        environment = q2_run.environment({"binary_hash": "1" * 64})
        lab = q2_run.Lab(0, "/missing")
        try:
            lab.documents = [q2_run.canonical(lab._manifest("A")),
                             q2_run.canonical(lab._manifest("B"))]
            topology = lab.topology()
            trial, packets, evidence = q2_run.failure_trial(plan, environment, topology, True)
        finally:
            q2_run.shutil.rmtree(lab.temp, ignore_errors=True)
        self.assertEqual(q2_run.q2.validate([trial], packets, [evidence], require_complete=False), [])
        self.assertEqual(len(packets), 400)
        self.assertEqual(trial["lost_packets"], 400)


if __name__ == "__main__":
    unittest.main()
