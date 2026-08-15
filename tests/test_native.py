import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_netns as native


class NativeNetnsTests(unittest.TestCase):
    def test_canonical_manifest_routes(self):
        ifaces = [(2, "e0", 0), (3, "e1", 2)]
        routes = [(native.loc(9), 3, native.mac(2))]
        value = native.manifest(ifaces, routes)
        self.assertEqual(value, native.manifest(ifaces, routes))
        self.assertEqual(value["interfaces"][0]["descriptor_id"], 2)
        self.assertEqual(value["routes"], [{"destination_prefix": {"network": list(native.loc(9).packed), "prefix_length": 128}, "egress_descriptor_id": 3, "next_hop_mac": list(native.mac(2))}])

    def test_ctl_and_frame_parse(self):
        packet = native.ctl(0, 2, hop=4)
        dst, src, (header, payload) = native.parse_frame(native.eth(native.mac(2), native.mac(0), packet))
        self.assertEqual((dst, src), (native.mac(2), native.mac(0)))
        self.assertEqual(header.hop, 4)
        self.assertEqual(native.r8ref.parse_ctl(header, payload)[0], native.r8ref.CTL_ECHO_REQUEST)
        with self.assertRaises(ValueError):
            native.parse_frame(b"bad")

    def test_packet_socket_ignores_outgoing(self):
        sock = MagicMock()
        with patch.object(native.socket, "socket", return_value=sock):
            self.assertIs(native.socket_for("e0"), sock)
        sock.setsockopt.assert_called_once_with(native.SOL_PACKET, native.PACKET_IGNORE_OUTGOING, 1)
        sock.bind.assert_called_once_with(("e0", native.ETHERTYPE))
        sock.setblocking.assert_called_once_with(False)

    def test_namespace_ip_helper_executes_ip_inside_namespace(self):
        with patch.object(native, "_run") as run:
            native.ip("link", "set", "lo", "down", ns="test")
        run.assert_called_once_with(["ip", "netns", "exec", "test", "ip", "link", "set", "lo", "down"], True)
    def test_nonroot_main_refuses(self):
        with patch.object(os, "geteuid", return_value=1000):
            self.assertEqual(native.main(["--binary", "/missing"]), 1)

    def test_canonical_aggregate_framing(self):
        records = [("b", 2, b"x"), ("a", 1, b"yz")]
        frame = native.canonical_frame("domain", records)
        self.assertEqual(native.aggregate_hash("domain", records), native.sha(frame))
        self.assertNotEqual(native.aggregate_hash("domain", records), native.aggregate_hash("domain-x", records))
        self.assertNotEqual(native.aggregate_hash("domain", records), native.aggregate_hash("domain", [("a", 1, b"y"), ("b", 2, b"zx")]))

    def test_result_privacy_and_descriptor_ordinals(self):
        lab = type("Lab", (), {"error_category": None, "counts": {"cleanup_failures": 0}, "docs": []})()
        result = native.result_json(lab, "/missing", 2)
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
        self.assertEqual(result["interface_ordinals"], [2, 3, 4, 5])
        self.assertEqual(result["manifest_hash"], native.aggregate_hash("r8-native-manifest-v1", []))
        self.assertNotIn("namespace", encoded)
        self.assertNotIn("argv", encoded)

    def test_setup_failures_use_only_finite_redacted_stages(self):
        self.assertEqual(native.setup_error_category(OSError(), "ipv6-disable"), "setup-ipv6-disable")
        self.assertEqual(native.setup_error_category(OSError(), "unknown"), "setup")
        self.assertEqual(native.setup_error_category(RuntimeError("READY"), "ipv6-disable"), "ready")
    def test_startup_diagnostics_accept_only_fixed_redacted_stages(self):
        self.assertEqual(native.startup_error("noise\nr8-native startup=manifest\n"), "STARTUP_MANIFEST")
        self.assertEqual(native.startup_error("r8-native startup=unknown\n"), "READY")

if __name__ == "__main__":
    unittest.main()
