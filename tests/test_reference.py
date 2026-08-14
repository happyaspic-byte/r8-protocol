"""Independent-vector conformance tests for the Python v0.2 reference."""
import json
import contextlib
import errno
import io
import pathlib
import sys
import socket
import struct
import threading
from types import SimpleNamespace
from unittest import mock
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import r8ref  # noqa: E402

VECTORS = json.loads((ROOT / "tests" / "vectors" / "wire-v0.2.json").read_text())


class ReferenceVectors(unittest.TestCase):
    def test_positive_vectors_round_trip_exactly(self):
        for case in VECTORS["positive_cases"]:
            with self.subTest(case=case["id"]):
                packet = bytes.fromhex(case["packet_hex"])
                header, payload = r8ref.Header.unpack(packet)
                self.assertEqual(header.pack(payload), packet)
                if header.nh == r8ref.NH_CTL:
                    self.assertEqual(r8ref.parse_ctl(header, payload)[:2],
                                     (packet[48], packet[49]))
                elif header.nh == r8ref.NH_DGRAM:
                    self.assertEqual(r8ref.parse_dgram(header, payload)[:2],
                                     (0x1234, 0x5678))

    def test_negative_vectors_select_exact_error_category(self):
        for case in VECTORS["negative_cases"]:
            with self.subTest(case=case["id"]):
                with self.assertRaises(r8ref.WireError) as caught:
                    r8ref.Header.unpack(bytes.fromhex(case["packet_hex"]),
                                        case.get("binding_budget_bytes", 1280))
                self.assertEqual(caught.exception.category, case["expected_error"])

    def test_binding_boundaries_are_wire_not_serializer_limits(self):
        budgets = {"ipv4_udp_1252": 1252, "ipv6_udp_1232": 1232, "serialized_1280": 1280}
        for case in VECTORS["binding_boundary_cases"]:
            packet = bytes.fromhex(case["packet_hex"])
            header, payload = r8ref.Header.unpack(packet)
            for name, outcome in case["serializer_budget_outcomes"].items():
                with self.subTest(case=case["id"], budget=name):
                    if outcome == "accept":
                        self.assertEqual(header.pack(payload, budgets[name]), packet)
                    else:
                        with self.assertRaises(r8ref.WireError) as caught:
                            header.pack(payload, budgets[name])
                        self.assertEqual(caught.exception.category, "BINDING_BUDGET")

    def test_computed_zero_is_encoded_as_ffff(self):
        # Find a short ECHO body whose checksum arithmetic produces zero.
        header = r8ref.Header(r8ref.NH_CTL, r8ref.parse_loc("8:1::1"), r8ref.parse_loc("8:1::2"))
        for value in range(65536):
            body = value.to_bytes(4, "big")
            bare = bytes((r8ref.CTL_ECHO_REQUEST, 0, 0, 0)) + body
            if r8ref.checksum16(r8ref.pseudo_header(header, len(bare), r8ref.NH_CTL), bare) == 0:
                packet = r8ref.build_ctl(header, r8ref.CTL_ECHO_REQUEST, 0, body)
                self.assertEqual(packet[50:52], b"\xff\xff")
                return
        self.fail("no computed-zero test body found")
    def test_profile_three_session_data_allows_exact_path_pairs(self):
        src, dst = r8ref.parse_loc("8:1::1"), r8ref.parse_loc("8:1::2")
        envelope = bytes((6, 1, 3, 0))
        for flags, slot in ((1, 0), (3, 1)):
            with self.subTest(flags=flags, slot=slot):
                packet = r8ref.Header(r8ref.NH_SES, src, dst, profile=3,
                                      flags=flags, pslot=slot, scid=1).pack(envelope)
                self.assertEqual(r8ref.Header.unpack(packet)[1], envelope)

    def test_profile_three_session_data_rejects_cross_pairs(self):
        src, dst = r8ref.parse_loc("8:1::1"), r8ref.parse_loc("8:1::2")
        envelope = bytes((6, 1, 3, 0))
        for flags, slot in ((1, 1), (3, 0)):
            with self.subTest(flags=flags, slot=slot):
                header = r8ref.Header(r8ref.NH_SES, src, dst, profile=3,
                                      flags=flags, pslot=slot, scid=1)
                with self.assertRaises(r8ref.WireError) as caught:
                    header.pack(envelope)
                self.assertEqual(caught.exception.category, "PATH_SLOT")
    def test_ses_error_precedence_is_frozen(self):
        src, dst = r8ref.parse_loc("8:1::1"), r8ref.parse_loc("8:1::2")
        cases = (
            (r8ref.Header(r8ref.NH_SES, src, dst, scid=0, flags=3, pslot=1), b"", "SCID"),
            (r8ref.Header(r8ref.NH_SES, src, dst, scid=1), b"", "TRUNCATED"),
            (r8ref.Header(r8ref.NH_SES, src, dst, scid=1), b"\xff\x01\0\0", "NEXT_HEADER"),
            (r8ref.Header(r8ref.NH_SES, src, dst, scid=1), b"\x06\x01\x01\0", "PROFILE"),
            (r8ref.Header(r8ref.NH_SES, src, dst, scid=1, flags=2), b"\x06\x01\0\0", "FLAGS"),
            (r8ref.Header(r8ref.NH_SES, src, dst, scid=1, flags=1, pslot=1), b"\x06\x01\0\0", "PATH_SLOT"),
        )
        for header, payload, category in cases:
            with self.subTest(category=category):
                with self.assertRaises(r8ref.WireError) as caught:
                    header.pack(payload)
                self.assertEqual(caught.exception.category, category)
    def test_underlay_policy_and_linux_df_failure(self):
        for host in ("0.0.0.0", "224.0.0.1", "240.0.0.1", "255.255.255.255"):
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    r8ref._underlay_endpoint(host, 52808, True)
        with self.assertRaises(ValueError):
            r8ref._underlay_endpoint("8.8.8.8", 52808, True)
        self.assertEqual(r8ref._underlay_endpoint("127.0.0.1", 52808), ("127.0.0.1", 52808))
        class BrokenSocket:
            def setsockopt(self, level, option, value):
                raise OSError(errno.EPERM, "denied")
        with mock.patch.object(r8ref.sys, "platform", "linux"), self.assertRaises(OSError):
            r8ref._configure_pmtu(BrokenSocket())

    def test_send_packet_requires_full_datagram_and_maps_only_emsgsize(self):
        class SendSocket:
            def __init__(self, result=None, error=None):
                self.result, self.error = result, error
            def sendto(self, packet, endpoint):
                if self.error:
                    raise self.error
                return self.result
        self.assertIsNone(r8ref._send_packet(SendSocket(1), b"x", ("127.0.0.1", 1)))
        for result in (0, 1):
            with self.subTest(result=result):
                with self.assertRaises(OSError) as caught:
                    r8ref._send_packet(SendSocket(result), b"xy", ("127.0.0.1", 1))
                self.assertEqual(caught.exception.errno, errno.EIO)
        with self.assertRaises(r8ref.WireError) as caught:
            r8ref._send_packet(SendSocket(error=OSError(errno.EMSGSIZE, "large")), b"x", ("127.0.0.1", 1))
        self.assertEqual(caught.exception.category, "BINDING_BUDGET")
        with self.assertRaises(OSError):
            r8ref._send_packet(SendSocket(error=OSError(errno.ECONNREFUSED, "refused")), b"x", ("127.0.0.1", 1))
    def test_ping_all_emsgsize_is_bounded_and_nonbudget_io_propagates(self):
        me, target = r8ref.parse_loc("8:1::20"), r8ref.parse_loc("8:1::10")
        args = SimpleNamespace(address=str(me), loc=str(target),
                               peer=[f"{target}=127.0.0.1:52808"], bind="127.0.0.1",
                               timeout=1, count=2, interval=0, binding_budget=1252,
                               allow_isolated_underlay=False)
        class FailingSocket:
            def setsockopt(self, level, option, value):
                pass
            def bind(self, address):
                pass
            def sendto(self, packet, endpoint):
                raise OSError(errno.EMSGSIZE, "large")
        output = io.StringIO()
        with mock.patch.object(r8ref.socket, "socket", return_value=FailingSocket()), \
             mock.patch.object(r8ref.time, "time", return_value=1), \
             mock.patch.object(r8ref.time, "monotonic", return_value=0), \
             mock.patch.object(r8ref.time, "sleep"), \
             contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as caught:
            r8ref.cmd_ping(args)
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("0 sent, 0 received, 100% loss, 2 invalid", output.getvalue())
        class RefusedSocket(FailingSocket):
            def sendto(self, packet, endpoint):
                raise OSError(errno.ECONNREFUSED, "refused")
        with mock.patch.object(r8ref.socket, "socket", return_value=RefusedSocket()), \
             mock.patch.object(r8ref.time, "time", return_value=1), \
             mock.patch.object(r8ref.time, "monotonic", return_value=0), \
             mock.patch.object(r8ref.time, "sleep"), self.assertRaises(OSError):
            r8ref.cmd_ping(args)
    def test_command_handlers_propagate_zero_and_short_sends(self):
        me, target = r8ref.parse_loc("8:1::20"), r8ref.parse_loc("8:1::10")
        ping_args = SimpleNamespace(address=str(me), loc=str(target),
                                    peer=[f"{target}=127.0.0.1:52808"], bind="127.0.0.1",
                                    timeout=1, count=1, interval=0, binding_budget=1252,
                                    allow_isolated_underlay=False)
        send_args = SimpleNamespace(address=str(me), loc=str(target),
                                    peer=[f"{target}=127.0.0.1:52808"], bind="127.0.0.1",
                                    sport=1000, dport=9000, message="x", binding_budget=1252,
                                    allow_isolated_underlay=False)

        class ShortSendSocket:
            def __init__(self, count):
                self.count = count
                self.send_calls = 0
            def setsockopt(self, level, option, value):
                pass
            def bind(self, address):
                pass
            def sendto(self, packet, endpoint):
                self.send_calls += 1
                return self.count

        for count in (0, 1):
            with self.subTest(command="ping", count=count):
                sock = ShortSendSocket(count)
                output = io.StringIO()
                with mock.patch.object(r8ref.socket, "socket", return_value=sock), \
                     mock.patch.object(r8ref.time, "time", return_value=1), \
                     contextlib.redirect_stdout(output), \
                     self.assertRaises(OSError) as caught:
                    r8ref.cmd_ping(ping_args)
                self.assertEqual(caught.exception.errno, errno.EIO)
                self.assertEqual(sock.send_calls, 1)
                self.assertNotIn("R8-ECHO reply", output.getvalue())
                self.assertNotIn("sent, ", output.getvalue())
                self.assertNotIn("BINDING_BUDGET", output.getvalue())
            with self.subTest(command="send", count=count):
                sock = ShortSendSocket(count)
                output = io.StringIO()
                with mock.patch.object(r8ref.socket, "socket", return_value=sock), \
                     contextlib.redirect_stdout(output), \
                     self.assertRaises(OSError) as caught:
                    r8ref.cmd_send(send_args)
                self.assertEqual(caught.exception.errno, errno.EIO)
                self.assertEqual(sock.send_calls, 1)
                self.assertNotIn("dgram outbound", output.getvalue())
                self.assertNotIn("BINDING_BUDGET", output.getvalue())
    def test_dgram_send_binds_configured_source(self):
        class SendSocket:
            def __init__(self):
                self.bound = None
            def setsockopt(self, level, option, value):
                pass
            def bind(self, address):
                self.bound = address
            def sendto(self, packet, endpoint):
                self.endpoint = endpoint
                return len(packet)
        sock = SendSocket()
        args = SimpleNamespace(address="8:1::20", loc="8:1::10",
                               peer=["8:1::10=127.0.0.1:52808"], bind="127.0.0.1",
                               sport=1000, dport=9000, message="x", binding_budget=1252,
                               allow_isolated_underlay=False)
        with mock.patch.object(r8ref.socket, "socket", return_value=sock):
            r8ref.cmd_send(args)
        self.assertEqual(sock.bound, ("127.0.0.1", 0))
    def test_ping_ignores_malformed_wrong_and_stale_until_valid(self):
        me, target = r8ref.parse_loc("8:1::20"), r8ref.parse_loc("8:1::10")
        body = struct.pack("!HH", 1, 1)
        stale = r8ref.build_ctl(r8ref.Header(r8ref.NH_CTL, target, me),
                                 r8ref.CTL_ECHO_REPLY, 0, struct.pack("!HH", 1, 2))
        valid = r8ref.build_ctl(r8ref.Header(r8ref.NH_CTL, target, me),
                                 r8ref.CTL_ECHO_REPLY, 0, body)
        responses = [(b"\x80", ("127.0.0.1", 52808)),
                     (valid, ("127.0.0.2", 52808)),
                     (stale, ("127.0.0.1", 52808)),
                     (valid, ("127.0.0.1", 52808))]
        class FakeSocket:
            def bind(self, address):
                pass
            def settimeout(self, timeout):
                pass
            def sendto(self, packet, address):
                self.sent = packet
                return len(packet)
            def setsockopt(self, level, option, value):
                pass
            def recvfrom(self, size):
                return responses.pop(0)
        args = SimpleNamespace(address=str(me), loc=str(target),
                               peer=[f"{target}=127.0.0.1:52808"], bind="127.0.0.1",
                               timeout=1, count=1, interval=0, binding_budget=1252,
                               allow_isolated_underlay=False)
        output = io.StringIO()
        with mock.patch.object(r8ref.socket, "socket", return_value=FakeSocket()), \
             mock.patch.object(r8ref.time, "time", return_value=1), \
             mock.patch.object(r8ref.time, "monotonic", side_effect=(0, 0, .1, .2, .3)), \
             mock.patch.object(r8ref.time, "sleep"), \
             contextlib.redirect_stdout(output), \
             self.assertRaises(SystemExit) as caught:
            r8ref.cmd_ping(args)
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("R8-ECHO reply sequence=1", output.getvalue())
        self.assertIn("1 sent, 1 received, 0% loss, 3 invalid", output.getvalue())

    def test_ping_no_valid_reply_and_zero_count_fail(self):
        me, target = r8ref.parse_loc("8:1::20"), r8ref.parse_loc("8:1::10")
        class TimeoutSocket:
            def bind(self, address):
                pass
            def settimeout(self, timeout):
                pass
            def setsockopt(self, level, option, value):
                pass
            def sendto(self, packet, address):
                return len(packet)
            def recvfrom(self, size):
                raise socket.timeout
        args = SimpleNamespace(address=str(me), loc=str(target),
                               peer=[f"{target}=127.0.0.1:52808"], bind="127.0.0.1",
                               timeout=1, count=1, interval=0, binding_budget=1252,
                               allow_isolated_underlay=False)
        with mock.patch.object(r8ref.socket, "socket", return_value=TimeoutSocket()), \
             mock.patch.object(r8ref.time, "time", return_value=1), \
             mock.patch.object(r8ref.time, "monotonic", side_effect=(0, 0)), \
             mock.patch.object(r8ref.time, "sleep"), \
             self.assertRaises(SystemExit):
            r8ref.cmd_ping(args)
        args.count = 0
        with self.assertRaises(ValueError):
            r8ref.cmd_ping(args)
    def test_malformed_packet_does_not_stop_echo_server(self):
        me, peer = r8ref.parse_loc("8:1::10"), r8ref.parse_loc("8:1::20")
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        stop = threading.Event()
        thread = threading.Thread(target=r8ref.run_echo_server, args=(server, me, stop), daemon=True)
        thread.start()
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(1)
        try:
            client.sendto(b"\x80", server.getsockname())
            body = b"\0\1\0\2"
            packet = r8ref.build_ctl(r8ref.Header(r8ref.NH_CTL, peer, me),
                                     r8ref.CTL_ECHO_REQUEST, 0, body)
            client.sendto(packet, server.getsockname())
            reply, _ = client.recvfrom(1280)
            header, payload = r8ref.Header.unpack(reply)
            self.assertEqual(r8ref.parse_ctl(header, payload),
                             (r8ref.CTL_ECHO_REPLY, 0, body))
        finally:
            stop.set()
            client.close()
            server.close()


if __name__ == "__main__":
    unittest.main()
