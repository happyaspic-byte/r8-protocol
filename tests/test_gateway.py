import pathlib
import socket
import sys
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import r8gateway as gateway


class GatewayTests(unittest.TestCase):
    def test_encapsulate_and_decapsulate_udp_payload(self):
        sender = gateway.GatewayConfig(
            local_loc="8:1::10", peer_loc="8:2::20", sport=12000, dport=13000
        )
        receiver = gateway.GatewayConfig(
            local_loc="8:2::20", peer_loc="8:1::10", sport=13000, dport=12000
        )
        packet = gateway.encapsulate(sender, b"legacy-app-data")
        sport, dport, payload = gateway.decapsulate(receiver, packet)
        self.assertEqual((sport, dport, payload), (12000, 13000, b"legacy-app-data"))

    def test_default_udp_budget_matches_r8d(self):
        config = gateway.GatewayConfig(
            local_loc="8:1::10", peer_loc="8:2::20", sport=12000, dport=13000
        )
        self.assertEqual(config.binding_budget, 1252)
        with self.assertRaisesRegex(ValueError, "payload budget"):
            gateway.encapsulate(config, b"x" * 1197)

    def test_payload_budget_is_enforced(self):
        config = gateway.GatewayConfig(
            local_loc="8:1::10", peer_loc="8:2::20", sport=12000, dport=13000,
            binding_budget=1280,
        )
        with self.assertRaisesRegex(ValueError, "payload budget"):
            gateway.encapsulate(config, b"x" * 1225)

    def test_forward_once_bridges_legacy_udp_to_r8_peer(self):
        legacy_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        r8_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        r8_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        legacy_sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for sock in (legacy_in, r8_out, r8_in, legacy_sink):
            sock.bind(("127.0.0.1", 0))
            sock.settimeout(1)
        sender = gateway.GatewayConfig("8:1::10", "8:2::20", 12000, 13000)
        receiver = gateway.GatewayConfig("8:2::20", "8:1::10", 13000, 12000)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            client.sendto(b"legacy-app-data", legacy_in.getsockname())
            gateway.forward_once(legacy_in, r8_out, r8_in.getsockname(), sender)
            gateway.deliver_once(r8_in, legacy_sink, legacy_sink.getsockname(), receiver)
            payload, _ = legacy_sink.recvfrom(2048)
            self.assertEqual(payload, b"legacy-app-data")
        finally:
            for sock in (legacy_in, r8_out, r8_in, legacy_sink, client):
                sock.close()

    def test_gateway_rejects_public_underlay(self):
        with self.assertRaisesRegex(ValueError, "public underlay"):
            gateway.validate_underlay("8.8.8.8", allow_isolated=False)
        self.assertEqual(gateway.validate_underlay("127.0.0.1", False), "127.0.0.1")
        self.assertEqual(gateway.validate_underlay("10.8.1.10", True), "10.8.1.10")
