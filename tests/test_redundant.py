import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import r8session as s
from r8ref import Header, NH_SES, parse_loc


class Profile3DataTests(unittest.TestCase):
    def header(self, slot):
        return Header(NH_SES, parse_loc("8:1::1"), parse_loc("8:1::2"), profile=3,
                      flags=1 if slot == 0 else 3, pslot=slot, scid=7)

    def assert_session_error(self, category, callable, *args):
        with self.assertRaises(s.SessionError) as raised:
            callable(*args)
        self.assertEqual(raised.exception.category, category)

    def test_slots_have_exact_packets_and_independent_ciphertexts(self):
        plain, delivery_id = b"same logical delivery", 9
        packets = []
        for slot in (0, 1):
            sender = s.Session(bytes((slot + 1,)) * 32)
            packet = s.seal_profile3_data(sender, self.header(slot), delivery_id, plain)
            self.assertEqual(len(packet), s.PROFILE3_DATA_PACKET_OVERHEAD + len(plain))
            self.assertEqual(packet[48:52], b"\x06\x01\x03\x00")
            self.assertEqual(int.from_bytes(packet[60:68], "big"), delivery_id)
            receiver = s.Session(bytes((slot + 1,)) * 32)
            preview = s.preview_profile3_data(receiver, packet)
            self.assertIsInstance(preview, s.Profile3DataPreview)
            self.assertEqual(repr(preview), "<Profile3DataPreview>")
            self.assertNotIn(plain.decode(), repr(preview))
            self.assertEqual(s.commit_profile3_data(receiver, preview), (delivery_id, plain))
            self.assert_session_error("REPLAY", s.preview_profile3_data, receiver, packet)
            packets.append(packet)
        self.assertNotEqual(packets[0][68:], packets[1][68:])

    def test_profile3_minimum_and_legacy_data_minimum(self):
        self.assert_session_error("TRUNCATED", s.encode, 6, 3, b"\0" * 31)
        for profile in (0, 1, 2):
            self.assertEqual(s.decode(s.encode(6, profile, b"\0" * 24))[:3], (6, 1, profile))

    def test_budget_id_slot_tag_abort_and_header_auth_without_counter_use(self):
        sender, receiver = s.Session(b"a" * 32), s.Session(b"a" * 32)
        header = self.header(0)
        plain = b"x" * 10
        exact = s.PROFILE3_DATA_PACKET_OVERHEAD + len(plain)
        packet = s.seal_profile3_data(sender, header, 1, plain, exact)
        self.assertEqual(sender.send_counter, 2)
        before = sender.send_counter
        self.assert_session_error("BUDGET", s.seal_profile3_data, sender, header, 2, plain, exact - 1)
        self.assert_session_error("UNEXPECTED_MESSAGE", s.seal_profile3_data, sender, header, 0, plain)
        self.assert_session_error("UNEXPECTED_MESSAGE", s.seal_profile3_data, sender, header,
                                  0xffffffffffffffff, plain)
        self.assertEqual(sender.send_counter, before)
        bad_slot = Header(NH_SES, header.src, header.dst, profile=3, flags=1, pslot=1, scid=7)
        self.assert_session_error("UNEXPECTED_MESSAGE", s.seal_profile3_data, sender, bad_slot, 2, plain)
        tampered_id = bytearray(packet); tampered_id[67] = 0
        tampered_tag = bytearray(packet); tampered_tag[-1] ^= 1
        tampered_source = bytearray(packet); tampered_source[16] ^= 1
        for hostile, category in ((tampered_id, "UNEXPECTED_MESSAGE"), (tampered_tag, "AUTH_FAILED"),
                                  (tampered_source, "AUTH_FAILED")):
            self.assert_session_error(category, s.preview_profile3_data, receiver, bytes(hostile))
            self.assertEqual(receiver.replay.highest, 0)
        hop = bytearray(packet); hop[5] ^= 1
        preview = s.preview_profile3_data(receiver, bytes(hop))
        s.abort_profile3_data(receiver, preview)
        self.assertEqual(receiver.replay.highest, 0)
        self.assert_session_error("REPLAY", s.abort_profile3_data, receiver, preview)
        self.assertEqual(s.commit_profile3_data(receiver, s.preview_profile3_data(receiver, packet)), (1, plain))

    def test_counter_max_minus_one_is_usable(self):
        maximum_usable = 0xffffffffffffffff - 1
        sender = s.Session(b"b" * 32, send_counter=maximum_usable)
        header = self.header(1)
        packet = s.seal_profile3_data(sender, header, maximum_usable, b"")
        self.assertEqual(int.from_bytes(packet[52:60], "big"), maximum_usable)
        self.assertEqual(sender.send_counter, 0xffffffffffffffff)
        self.assert_session_error("COUNTER_EXHAUSTED", s.seal_profile3_data, sender, header, 1, b"")


if __name__ == "__main__":
    unittest.main()
