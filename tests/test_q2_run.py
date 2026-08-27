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
    def test_retained_packages_prohibit_sensitive_keys_and_pins(self):
        forbidden_substrings = ("client_x25519_secret", "server_x25519_secret", "cookie_key", "client_ed25519_seed", "server_ed25519_seed")
        for results_dir in (ROOT / "bench/results").iterdir():
            if not results_dir.is_dir():
                continue
            for file in results_dir.glob("*.json*"):
                content = file.read_text()
                for forbidden in forbidden_substrings:
                    self.assertNotIn(forbidden, content, f"Sensitive key {forbidden} leaked in {file}")

    def test_operations_runbook_covers_rollout_rollback_and_incidents(self):
        runbook = (ROOT / "docs/operations-runbook.md").read_text()
        for heading in (
            "## Preconditions", "## Deployment", "## Observability",
            "## Rollback", "## Capacity limits", "## Incident response",
        ):
            self.assertIn(heading, runbook)
        self.assertIn("public and third-party networks are prohibited", runbook.lower())
        self.assertIn("make demo", runbook)
        self.assertIn("make compare-smoke", runbook)

    def test_repository_uses_apache_2_license(self):
        license_text = (ROOT / "LICENSE").read_text()
        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0, January 2004", license_text)
        workspace = (ROOT / "rust/Cargo.toml").read_text()
        self.assertIn('license = "Apache-2.0"', workspace)
        self.assertNotIn('license = "UNLICENSED"', workspace)

    def test_systemd_unit_is_loopback_only_and_hardened(self):
        unit = (ROOT / "packaging/debian/lib/systemd/system/r8d.service").read_text()
        self.assertIn("--bind 127.0.0.1:52808", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("CapabilityBoundingSet=", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("PrivateDevices=true", unit)

    def test_debian_package_target_and_metadata(self):
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("package-deb:", makefile)
        control = (ROOT / "packaging/debian/DEBIAN/control").read_text()
        self.assertIn("Package: r8-protocol", control)
        self.assertIn("Architecture: amd64", control)
        self.assertIn("License: Apache-2.0", control)

    def test_dockerfile_and_compose_present(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn("FROM rust:", dockerfile)
        self.assertIn("r8d", dockerfile)
        self.assertIn("r8ping", dockerfile)
        compose = (ROOT / "docker-compose.yml").read_text()
        self.assertIn("services:", compose)

    def test_makefile_provides_compare_smoke_target(self):
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("compare-smoke:", makefile)

    def test_makefile_provides_demo_and_test_targets(self):
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("demo:", makefile)
        self.assertIn("test:", makefile)
        self.assertIn("check:", makefile)
        self.assertIn("netns-topo.sh", makefile)
        self.assertIn("teardown", makefile)

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

    def test_ci_has_hosted_product_smoke_job(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("product-smoke:", workflow)
        product_job = workflow[workflow.index("product-smoke:"):workflow.index("native-smoke:")]
        self.assertIn("pip install --requirement requirements-dev.txt", product_job)
        self.assertIn("make package-deb", product_job)
        self.assertIn("python3 examples/loopback_client.py", workflow)
        self.assertIn("python3 -m unittest tests/test_gateway.py", workflow)

    def test_q2_workflow_restores_package_ownership_after_failed_run(self):
        workflow = (ROOT / ".github/workflows/q2-full.yml").read_text()
        restore = workflow.index("Restore Q2 package ownership")
        upload = workflow.index("Upload Q2 package")
        self.assertLess(restore, upload)
        ownership_step = workflow[restore:upload]
        self.assertIn("if: always()", ownership_step)
        self.assertIn("sudo chown -R", ownership_step)
        self.assertIn("sudo chmod -R u+rwX", ownership_step)

    def test_gate_manifest_hash_goldens_match_hosted_workflow(self):
        self.assertEqual(q2_run._expected_gate4_manifest_hash(1),
                         "e61d83820cb1e2b3da44d03dd75975e2f26ffad83e202048b4367d8f48eab375")
        self.assertEqual(q2_run._expected_gate4_manifest_hash(2),
                         "9b7331a01c0fd5d047188d2c612a94a39279384548def887af9cff29fd932374")
        # Observed from hosted native-full run 32656014108 artifact
        # redundant-native.json (ok=true); supersedes the pre-d62cd80 golden
        # 77f608... captured before the redundant topology rework.
        self.assertEqual(q2_run._expected_gate5_manifest_hash(),
                         "4e3223aac7e405db0a3e9ac76d9edd08d7eed3a568b5312c1d78c07c3da3e73e")
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
