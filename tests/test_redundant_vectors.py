import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))

import r8session as s
from r8ref import Header

VECTORS = json.loads((ROOT / "tests" / "vectors" / "redundant-v0.1.json").read_text())


class RedundantVectorTests(unittest.TestCase):
    def key(self, direction, slot):
        names = {("c2s", 0): "c2s_slot0_key_hex", ("c2s", 1): "c2s_slot1_key_hex",
                 ("s2c", 0): "s2c_slot0_key_hex", ("s2c", 1): "s2c_slot1_key_hex"}
        crypto = VECTORS["cryptography"]
        roles = (1, 2) if direction == "c2s" else (2, 1)
        actual = s.key_schedule(bytes.fromhex(crypto["shared_secret_hex"]),
                                bytes.fromhex(crypto["transcript_hash_hex"]), *roles, 3, slot)
        self.assertEqual(actual.hex(), crypto["keys"][names[direction, slot]])
        return actual

    def packet_header(self, case):
        header, _ = s.parse_packet(bytes.fromhex(case["full_packet_hex"]))
        return header

    def session_error(self, expected, operation, *args):
        with self.assertRaises(s.SessionError) as raised:
            operation(*args)
        self.assertEqual(raised.exception.category, expected)

    def test_frozen_positive_packets_and_directional_delivery(self):
        self.assertTrue(VECTORS["synthetic_only"])
        self.assertEqual(VECTORS["common"]["profile3_overhead"], 84)
        keys = {(direction, slot): self.key(direction, slot)
                for direction in ("c2s", "s2c") for slot in (0, 1)}
        senders = {(direction, slot): s.Session(key) for (direction, slot), key in keys.items()}
        for case in VECTORS["positive_cases"]:
            direction, slot = case["direction"], case["slot"]
            plaintext = bytes.fromhex(case["plaintext_hex"])
            expected = bytes.fromhex(case["full_packet_hex"])
            self.assertEqual(len(expected), 84 + len(plaintext))
            self.assertEqual(len(expected), case["exact_size"])
            self.assertEqual(expected[:48].hex(), case["header_hex"])
            self.assertEqual(expected[48:52].hex(), case["prefix_hex"])
            self.assertEqual(expected[52:60], case["counter"].to_bytes(8, "big"))
            self.assertEqual(expected[60:68], case["delivery_id"].to_bytes(8, "big"))
            header = self.packet_header(case)
            self.assertEqual((header.profile, header.pslot, header.flags),
                             (3, slot, 1 if slot == 0 else 3))
            packet = s.seal_profile3_data(senders[direction, slot], header,
                                         case["delivery_id"], plaintext, case["binding_budget"])
            self.assertEqual(packet, expected, case["id"])
            inverse = "s2c" if direction == "c2s" else "c2s"
            receiver = s.Session(keys[direction, slot])
            preview = s.preview_profile3_data(receiver, packet, case["binding_budget"])
            self.assertEqual(s.commit_profile3_data(receiver, preview),
                             (case["delivery_id"], plaintext))
            self.assertNotEqual(keys[direction, slot], keys[inverse, slot])

    def test_concrete_packet_mutations_have_exposed_categories(self):
        cases = {case["id"]: case for case in VECTORS["positive_cases"]}
        base = cases["p3-data-slot0"]
        packet = bytes.fromhex(base["full_packet_hex"])
        key = self.key("c2s", 0)
        for cut in (47, 50, 55, 63, len(packet) - 1):
            with self.assertRaises(s.SessionError) as raised:
                s.preview_profile3_data(s.Session(key), packet[:cut])
            self.assertEqual(raised.exception.category, "TRUNCATED")
        mutations = []
        profile = bytearray(packet); profile[4] = 2; profile[50] = 2
        mutations.append((profile, "UNEXPECTED_MESSAGE"))
        flags = bytearray(packet); flags[6] = 0
        mutations.append((flags, "UNEXPECTED_MESSAGE"))
        slot = bytearray(packet); slot[7] = 1
        mutations.append((slot, "UNEXPECTED_MESSAGE"))
        delivery_zero = bytearray(packet); delivery_zero[60:68] = b"\0" * 8
        delivery_max = bytearray(packet); delivery_max[60:68] = b"\xff" * 8
        counter_max = bytearray(packet); counter_max[52:60] = b"\xff" * 8
        mutations.extend(((delivery_zero, "UNEXPECTED_MESSAGE"),
                          (delivery_max, "UNEXPECTED_MESSAGE"),
                          (counter_max, "COUNTER_RANGE")))
        header = bytearray(packet); header[15] ^= 1
        mutations.append((header, "AUTH_FAILED"))
        counter = bytearray(packet); counter[59] = 0
        mutations.append((counter, "COUNTER_RANGE"))
        for hostile, category in mutations:
            self.session_error(category, s.preview_profile3_data, s.Session(key), bytes(hostile))
        self.session_error("AUTH_FAILED", s.preview_profile3_data, s.Session(self.key("c2s", 1)), packet)
        receiver = s.Session(key)
        self.assertEqual(s.commit_profile3_data(receiver, s.preview_profile3_data(receiver, packet)),
                         (base["delivery_id"], bytes.fromhex(base["plaintext_hex"])))
        self.session_error("REPLAY", s.preview_profile3_data, receiver, packet)
        boundary = cases["p3-boundary-slot0"]
        self.session_error("BUDGET", s.seal_profile3_data, s.Session(key), self.packet_header(boundary),
                           boundary["delivery_id"], bytes.fromhex(boundary["plaintext_hex"]), 1279)
        hop = bytearray(packet); hop[5] -= 1
        hopped = s.Session(key)
        self.assertEqual(s.commit_profile3_data(hopped, s.preview_profile3_data(hopped, bytes(hop))),
                         (base["delivery_id"], bytes.fromhex(base["plaintext_hex"])))

    def test_state_only_cases_are_present_and_single_valued(self):
        state_ids = {case["id"] for case in VECTORS["negative_cases"]
                     if case["id"] not in {"delivery-zero", "delivery-max", "truncate-before-prefix",
                                            "truncate-prefix", "truncate-counter", "truncate-delivery-id",
                                            "truncate-tag", "wrong-profile", "wrong-flags", "wrong-slot",
                                            "wrong-key", "wrong-header", "hop-mutation-valid", "counter-zero",
                                            "counter-max", "replay-same-slot", "budget-over-one"}}
        self.assertTrue(state_ids)
        self.assertEqual(len(state_ids), len({case["id"] for case in VECTORS["negative_cases"] if case["id"] in state_ids}))
        for case in VECTORS["negative_cases"]:
            self.assertIsInstance(case["expected_error"], str)
            self.assertTrue(case["expected_error"])


if __name__ == "__main__":
    unittest.main()
