import json
import os
import inspect
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import redundant_netns as native
import native_netns as one_router


class RedundantNativeTests(unittest.TestCase):
    def test_manifest_is_exact_and_deterministic(self):
        destination = native.session.ipaddress.IPv6Address("8::1")
        value = native.manifest([(2, "p0", 4), (3, "p1", 7)], [(destination, 3, native.mac(7))])
        self.assertEqual(value, native.manifest([(2, "p0", 4), (3, "p1", 7)], [(destination, 3, native.mac(7))]))
        self.assertEqual([item["descriptor_id"] for item in value["interfaces"]], [2, 3])
        self.assertEqual(value["routes"][0]["egress_descriptor_id"], 3)
    def test_endpoint_bindings_are_canonical_and_match_manifest_ordinals(self):
        source_bindings = (native.session.NativeBinding(2, native.mac(1)),
                           native.session.NativeBinding(3, native.mac(10)))
        destination_bindings = (native.session.NativeBinding(4, native.mac(5)),
                                native.session.NativeBinding(5, native.mac(14)))
        endpoint_source = inspect.getsource(native.Lab.endpoints)
        self.assertIn("source_bindings = (session.NativeBinding(2, mac(1)), session.NativeBinding(3, mac(10)))",
                      endpoint_source)
        self.assertIn("destination_bindings = (session.NativeBinding(4, mac(5)), session.NativeBinding(5, mac(14)))",
                      endpoint_source)
        for binding in source_bindings + destination_bindings:
            self.assertEqual(native.session.validate_binding(binding), binding.encode())
        self.assertEqual([binding.ingress_descriptor_id for binding in source_bindings], [2, 3])
        self.assertEqual([binding.ingress_descriptor_id for binding in destination_bindings], [4, 5])
        self.assertEqual([binding.ingress_descriptor_id for binding in source_bindings + destination_bindings],
                         [2, 3, 4, 5])
        self.assertEqual(native.Lab.links, ((0, 1), (1, 3), (0, 2), (2, 3)))
        self.assertEqual([binding.next_hop_mac for binding in source_bindings + destination_bindings],
                         [native.mac(1), native.mac(10), native.mac(5), native.mac(14)])
        launch_source = inspect.getsource(native.Lab.launch)
        self.assertIn("((1, (2, 3), (0, 1), (0, 3)), (2, (4, 5), (2, 3), (0, 3)))",
                      launch_source)

    def test_packet_socket_ignores_outgoing(self):
        sock = MagicMock()
        with patch.object(native.socket, "socket", return_value=sock):
            self.assertIs(native.socket_for("p0"), sock)
        sock.setsockopt.assert_called_once_with(native.SOL_PACKET, native.PACKET_IGNORE_OUTGOING, 1)
        sock.bind.assert_called_once_with(("p0", native.ETHERTYPE))
        sock.setblocking.assert_called_once_with(False)

    def test_nonroot_refuses_without_json(self):
        with patch.object(os, "geteuid", return_value=1000):
            self.assertEqual(native.main(["--binary", "/missing"]), 1)

    def test_hash_framing_and_redacted_result(self):
        records = [("b", 2, b"x"), ("a", 1, b"yz")]
        self.assertEqual(native.aggregate_hash("domain", records), native.sha(native.canonical_frame("domain", records)))
        self.assertNotEqual(native.aggregate_hash("domain", records), native.aggregate_hash("other", records))
        lab = type("Lab", (), {"error_category": None, "counts": {
            "cleanup_failures": 0, "daemon_exits": 2, "rust_endpoint_authentications": 1}, "docs": []})()
        result = native.result_json(lab, "/missing", "/missing-endpoint")
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
        self.assertEqual(result["interface_ordinals"], [2, 3, 4, 5])
        self.assertTrue(result["revocation_verified"])
        self.assertFalse(result["privilege_dropped"])
        self.assertEqual(len(result["endpoint_binary_hash"]), 64)
        self.assertIn("rust/crates/r8-redundant/src/bin/r8-redundant-native.rs",
                      [record[0] for record in native.source_records()])
        for forbidden in ("namespace", "argv", "mac", "plaintext", "pid"):
            self.assertNotIn(forbidden, encoded)

    def test_rust_endpoint_is_mandatory_for_proof(self):
        self.assertIn("self.rust_endpoint_proof()", inspect.getsource(native.Lab.proof))
    def test_slot_one_admission_controls_are_receive_derived(self):
        python_source = inspect.getsource(native.Lab.endpoint_process) + inspect.getsource(native.Lab.rust_endpoint_proof)
        rust_source = (Path(__file__).resolve().parents[1]
                       / "rust/crates/r8-redundant/src/bin/r8-redundant-native.rs").read_text()
        self.assertIn("pass_fds=(read_fd,)", python_source)
        self.assertIn("os.urandom(32)", python_source)
        self.assertIn("endpoint_counters", python_source)
        self.assertNotIn('frames_sent"] += 7', python_source)
        self.assertIn("libc::recvfrom", rust_source)
        self.assertIn("address.sll_ifindex != index", rust_source)
        self.assertIn("binding(descriptor_id, source)", rust_source)
        self.assertIn("candidate_secret: random()?", rust_source)
        self.assertNotIn("SigningKey::from_bytes(&[role; 32])", rust_source)

    def test_rust_admission_ready_follows_result_and_activation(self):
        source = (Path(__file__).resolve().parents[1]
                  / "rust/crates/r8-redundant/src/bin/r8-redundant-native.rs").read_text()
        self.assertIn('println!("R8-ENDPOINT-LISTENING")', source)
        self.assertEqual(source.count("Duration::from_millis(500)"), 1)
        self.assertEqual(source.count("Duration::from_secs(1)"), 1)
        self.assertEqual(source.count("Duration::from_secs(2)"), 1)
        self.assertLess(source.find("let mut results = receiver.take_results()"),
                        source.find("receiver.take_profile3_admissions()"))
        self.assertIn("handshake=5 candidate=5 application=2 total=12", source)

    def test_harness_measures_native_frames(self):
        rust_harness = inspect.getsource(native.Lab.rust_endpoint_proof)
        self.assertIn("before = self.endpoint_counters()", rust_harness)
        self.assertIn("after = self.endpoint_counters()", rust_harness)
        self.assertIn("(sent, received, path0, path1) != (12, 12, 7, 5)", rust_harness)
        self.assertNotIn('frames_received"] += 7', rust_harness)
        self.assertEqual(12 + 5 + 10, 27)
    def test_rust_endpoint_rejects_appended_frames_after_the_exact_bound(self):
        source = (Path(__file__).resolve().parents[1] / "rust/crates/r8-redundant/src/bin/r8-redundant-native.rs").read_text()
        self.assertIn("const MAX_FRAME_LEN: usize = 14 + 1280;", source)
        self.assertIn("let mut buffer = [0u8; MAX_FRAME_LEN + 1];", source)
        self.assertIn("!(14..=MAX_FRAME_LEN).contains(&count)", source)
        self.assertIn("endpoint_accepts_exact_maximum_frame_but_rejects_an_appended_tail", source)
    def test_source_closures_bind_launchers_and_manifests_and_match_workflow(self):
        native_paths = (
            "tests/native_netns.py", "tests/vectors/session-v0.1.json",
            "spec/0004-wire-format-v0.2.md", "spec/0005-session-security-v0.1.md",
            "spec/0007-native-binding-v0.1.md", "spec/parameters-v0.1.md",
            "reference/r8ref.py", "reference/r8session.py",
            "rust/Cargo.toml", "rust/Cargo.lock",
            "rust/crates/r8d/Cargo.toml", "rust/crates/r8d/src/bin/r8-native.rs",
            "rust/crates/r8d/src/lib.rs", "rust/crates/r8d/src/native.rs",
            "rust/crates/r8d/src/linux.rs", "rust/crates/r8d/src/manifest.rs",
            "rust/crates/r8d/src/forward.rs",
            "rust/crates/r8-proto/Cargo.toml", "rust/crates/r8-proto/src/lib.rs",
            "rust/crates/r8-session/Cargo.toml", "rust/crates/r8-session/src/lib.rs",
            ".github/workflows/native-full.yml", ".github/workflows/ci.yml",
        )
        redundant_paths = (
            "tests/redundant_netns.py", "tests/vectors/session-v0.1.json",
            "spec/0004-wire-format-v0.2.md", "spec/0005-session-security-v0.1.md",
            "spec/0006-mobility-v0.1.md", "spec/0007-native-binding-v0.1.md",
            "spec/0008-redundant-v0.1.md", "spec/parameters-v0.1.md",
            "reference/r8ref.py", "reference/r8session.py", "reference/r8mobility.py",
            "reference/r8redundant.py",
            "rust/Cargo.toml", "rust/Cargo.lock",
            "rust/crates/r8d/Cargo.toml", "rust/crates/r8d/src/bin/r8-native.rs",
            "rust/crates/r8d/src/lib.rs", "rust/crates/r8d/src/native.rs",
            "rust/crates/r8d/src/linux.rs", "rust/crates/r8d/src/manifest.rs",
            "rust/crates/r8d/src/forward.rs",
            "rust/crates/r8-proto/Cargo.toml", "rust/crates/r8-proto/src/lib.rs",
            "rust/crates/r8-session/Cargo.toml", "rust/crates/r8-session/src/lib.rs",
            "rust/crates/r8-redundant/Cargo.toml", "rust/crates/r8-redundant/src/lib.rs",
            "rust/crates/r8-redundant/src/bin/r8-redundant-native.rs",
            "rust/crates/r8-mobility/Cargo.toml", "rust/crates/r8-mobility/src/lib.rs",
            ".github/workflows/native-full.yml", ".github/workflows/ci.yml",
        )
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/native-full.yml").read_text()

        def workflow_paths(name):
            match = re.search(rf"          {name} = \(\n(.*?)\n          \)", workflow, re.DOTALL)
            self.assertIsNotNone(match)
            return tuple(re.findall(r'"([^"]+)"', match.group(1)))

        def assert_bound(module, domain, expected, required):
            records = module.source_records()
            self.assertEqual(tuple(path for path, _, _ in records), expected)
            self.assertEqual(workflow_paths("native_paths" if module is one_router else "redundant_paths"), expected)
            baseline = module.aggregate_hash(domain, records)
            for path in required:
                altered = [(name, ordinal, value + b"\0") if name == path else (name, ordinal, value)
                           for name, ordinal, value in records]
                self.assertNotEqual(module.aggregate_hash(domain, altered), baseline)

        assert_bound(one_router, "r8-native-source-v1", native_paths,
                     ("rust/crates/r8d/src/bin/r8-native.rs", "rust/Cargo.toml",
                      "rust/crates/r8d/Cargo.toml", "rust/crates/r8-proto/Cargo.toml",
                      "rust/crates/r8-session/Cargo.toml"))
        assert_bound(native, "r8-redundant-source-v1", redundant_paths,
                     ("rust/crates/r8d/src/bin/r8-native.rs",
                      "rust/crates/r8-redundant/src/bin/r8-redundant-native.rs",
                      "rust/Cargo.toml", "rust/crates/r8d/Cargo.toml",
                      "rust/crates/r8-proto/Cargo.toml", "rust/crates/r8-session/Cargo.toml",
                      "rust/crates/r8-redundant/Cargo.toml", "rust/crates/r8-mobility/Cargo.toml"))

    def test_native_workflow_requires_success_and_recomputed_hashes_before_upload(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/native-full.yml").read_text()
        self.assertIn('value.get("ok") is not True', workflow)
        self.assertIn('or counts != spec["counts"]', workflow)
        self.assertIn('value.get("source_hash") != spec["source"]', workflow)
        self.assertIn('value.get("binary_hash") != sha(binary.read_bytes())', workflow)
        self.assertIn('value.get("endpoint_binary_hash") != sha(endpoint.read_bytes())', workflow)
        self.assertIn('aggregate("r8-native-filter-v1"', workflow)
        self.assertIn('native-capability-preflight.txt', workflow)
        self.assertIn('if: ${{ success() }}', workflow)
        self.assertIn('"frames_sent": 27, "frames_received": 27', workflow)
        self.assertIn('set(value) != expected_fields', workflow)
        self.assertIn('object_pairs_hook=reject_duplicates', workflow)
        self.assertIn('00112233445566778899aabbccddeeff', workflow)
        self.assertIn('gate3_run:', workflow)
        self.assertIn('test "$(jq -r .name <<<"$RUN")" = "Q1 Full"', workflow)
        self.assertIn('test "$(jq -r .head_sha <<<"$RUN")" = "$GITHUB_SHA"', workflow)
        self.assertNotIn('len(value[key]) == 64', workflow)
        self.assertIn('rust/crates/r8d/src/bin/r8-native.rs', workflow)
        self.assertIn('rust/crates/r8-redundant/Cargo.toml', workflow)


if __name__ == "__main__":
    unittest.main()
