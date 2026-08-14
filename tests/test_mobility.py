import copy
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import r8mobility as m
from r8session import Identity, PeerPin, UdpBinding

VECTORS = json.loads((ROOT / "tests" / "vectors" / "mobility-v0.1.json").read_text())

class Mobility(unittest.TestCase):
    def setUp(self):
        self.now = [0]
        self.a, self.b = Identity.from_seed(b"\x10" * 32), Identity.from_seed(b"\x20" * 32)
        self.binding = UdpBinding.from_endpoint("192.0.2.1", 5000, 1, b"\x90" * 16)
        self.other = UdpBinding.from_endpoint("192.0.2.2", 5001, 1, b"\x91" * 16)
        self.a_manager = m.MobilityManager(self.a, PeerPin(2, self.b.eid, self.b.public), 1, 0, 1, 7, "8::1", "8::2", self.binding, b"\x30" * 32, lambda: self.now[0])
        self.b_manager = m.MobilityManager(self.b, PeerPin(1, self.a.eid, self.a.public), 2, 0, 1, 7, "8::2", "8::1", self.binding, b"\x31" * 32, lambda: self.now[0])
    def _fixture_binding(self, encoded):
        raw = bytes.fromhex(encoded)
        if raw[:1] == b"\x02":
            self.assertEqual(len(raw), 11)
            return m.NativeBinding(int.from_bytes(raw[1:5], "big"), raw[5:])
        if raw[:2] == b"\x01\x04":
            self.assertEqual(len(raw), 25)
            return UdpBinding(raw[2:6], int.from_bytes(raw[6:8], "big"), raw[8], raw[9:])
        if raw[:2] == b"\x01\x06":
            self.assertEqual(len(raw), 37)
            return UdpBinding(raw[2:18], int.from_bytes(raw[18:20], "big"), raw[20], raw[21:])
        self.fail("invalid typed fixture binding")

    def _fixture_manager(self, setup):
        now, commits, accepted = [setup["clock_ms"]], [], set()
        def session_commit(token):
            if token in accepted:
                raise m.MobilityError("E-REPLAY")
            accepted.add(token)
            commits.append(token)
        binding = self._fixture_binding(setup["current_binding_hex"])
        roles = setup.get("roles", {})
        local_role, peer_role = roles.get("receiver", 2), roles.get("sender", 1)
        role_error = local_role not in (1, 2) or peer_role not in (1, 2) or local_role == peer_role
        if role_error: local_role, peer_role = 2, 1
        pin = PeerPin(peer_role, self.a.eid, self.a.public)
        manager = m.MobilityManager(self.b, pin, local_role,
            setup["session"]["profile"], setup["session"]["scid"], setup.get("manager_policy_id", setup.get("policy_id", 7)),
            "8::2", m.ipaddress.IPv6Address(bytes.fromhex(setup["current_loc_hex"])),
            binding, b"\x31" * 32, lambda: setup.get("issuer_clock_ms", now[0]), session_commit)
        manager.fixture_role_error = role_error
        for key, expected in (("candidate_capacity", 2), ("proposal_capacity", 2), ("result_cache_capacity", 2)):
            self.assertIn(setup.get(key, expected), (0, expected))
        manager.peer_epoch = setup.get("committed_epoch", 0)
        if "proposal_bucket" in setup:
            manager.tokens = setup["proposal_bucket"]["tokens"]
            manager.refill = setup["proposal_bucket"]["last_refill_ms"]
        def loc(entry, default="20010db8000000000000000000000002"):
            return m.ipaddress.IPv6Address(bytes.fromhex(entry.get("loc_hex", default)))
        for entry in setup["proposal_cache"]:
            cid = bytes.fromhex(entry["candidate_id_hex"])
            raw = bytes.fromhex(entry.get("canonical_input_hex", VECTORS["positive_cases"][0]["plaintext_hex"]))
            update = m.LocUpdate.parse(raw)
            if update.candidate_id != cid or any(key in entry for key in ("loc_hex", "epoch", "slot")):
                update = m.LocUpdate(cid, manager.peer_loc, loc(entry), entry.get("epoch", update.epoch), 0, 5000, entry.get("slot", update.slot), update.signature)
                raw = update.build()
            manager.proposals[cid] = (raw, update, entry.get("receipt_expiry_ms", now[0] + 5000))
        for entry in setup["result_cache"]:
            cid = bytes.fromhex(entry["candidate_id_hex"])
            result_code = {"promoted": 1, "rejected": 2, "expired": 3}.get(entry.get("result"), entry.get("result", 2))
            manager.results[cid] = (m.Result(cid, entry.get("epoch", 2), entry.get("slot", 0), result_code).build(), entry.get("expiry_ms", now[0] + 10000), entry.get("epoch", 2), entry.get("slot", 0), result_code)
        for entry in setup["live_candidates"]:
            cid = bytes.fromhex(entry["candidate_id_hex"])
            candidate_binding = self._fixture_binding(entry["binding_hex"])
            update = m.LocUpdate(cid, manager.peer_loc, loc(entry), entry.get("epoch", 2), 0, 5000, entry.get("slot", 0), b"\0" * 64)
            expiry = setup.get("challenge_expiry_ms", entry.get("expiry_ms", now[0] + 3000))
            manager.candidates[cid] = {"binding": candidate_binding, "expiry": expiry,
                "challenge": m.Challenge(cid, update.new_loc, update.epoch, update.slot, expiry, bytes.fromhex(entry["token_hex"]) if entry.get("token_hex") else b"\0" * 32),
                "state": entry["state"], "proposal": update}
            if entry.get("local_mover"):
                manager.outbound[cid] = (update.build(), (update.new_loc, update.epoch, update.slot), candidate_binding, None)
                manager.outbound_expiry[cid] = entry.get("expiry_ms", now[0] + 5000)
        for entry in setup.get("outbound_cache", setup.get("outbound_candidates", setup.get("outbound", []))):
            cid = bytes.fromhex(entry["candidate_id_hex"])
            update = m.LocUpdate(cid, manager.local_loc, loc(entry), entry.get("epoch", 2), 0, 5000, entry.get("slot", 0), b"\0" * 64)
            carrier = self._fixture_binding(entry.get("binding_hex", setup["current_binding_hex"]))
            manager.outbound[cid] = (update.build(), (update.new_loc, update.epoch, update.slot), carrier, None)
            manager.outbound_expiry[cid] = entry.get("expiry_ms", now[0] + 5000)
        for cid_hex in setup.get("failed_candidate_ids", []):
            cid = bytes.fromhex(cid_hex)
            manager.candidates[cid] = {"binding": binding, "expiry": now[0], "challenge": None, "state": "FAILED",
                "proposal": m.LocUpdate(cid, manager.peer_loc, manager.peer_loc, 1, 0, 5000, 0, b"\0" * 64)}
        if setup.get("validated_bindings") == 2:
            manager.grace = (binding, now[0] + 10000)
        cohort = setup.get("cohort")
        if cohort and cohort.get("frozen"):
            members = {}
            for cid_hex in cohort["members"]:
                cid = bytes.fromhex(cid_hex)
                members[cid] = manager.proposals.get(cid, (None, m.LocUpdate(cid, manager.peer_loc, manager.peer_loc, cohort["epoch"], 0, 5000, 0, b"\0" * 64)))[1]
            manager.cohort = (cohort["epoch"], members)
        if setup.get("restarted") or setup.get("session_restarted"):
            manager.close()
        return manager, commits

    @staticmethod
    def _fixture_snapshot(manager, commits):
        return (manager.local_loc, manager.peer_loc, manager.binding, manager.local_epoch, manager.peer_epoch, manager.generation,
                manager.tokens, manager.refill, tuple(manager.proposals.items()), tuple(manager.candidates.items()),
                tuple(manager.outbound.items()), tuple(manager.outbound_expiry.items()), tuple(manager.results.items()),
                manager.cohort, manager.grace, tuple(manager.emitted), tuple(commits))

    def _commit(self, manager, raw, binding, token=None):
        if token is None:
            token = object()
        return manager.commit(manager.preview(raw, binding, token))

    def test_all_positive_corpus_controls_round_trip_exactly(self):
        self.assertEqual(len(VECTORS["positive_cases"]), 5)
        for fixture in VECTORS["positive_cases"]:
            raw = bytes.fromhex(fixture["plaintext_hex"])
            with self.subTest(control=fixture["id"]):
                self.assertEqual(len(raw), fixture["exact_size"])
                self.assertEqual(m.parse_control(raw).build(), raw)
    def test_positive_corpus_token_transcript_and_hmac(self):
        context = VECTORS["context"]
        raw = m.token_input(
            context["profile"], context["scid"], self.a, self.b,
            bytes.fromhex(context["candidate_id_hex"]),
            m.ipaddress.IPv6Address(bytes.fromhex(context["new_loc_hex"])),
            self._fixture_binding(context["udp_binding_ipv4_hex"]),
            context["direction"], context["epoch"], context["slot"],
            context["policy_id"], context["issuer_expiry_ms"])
        self.assertEqual(raw.hex(), VECTORS["positive_cases"][2]["token_input_hex"])
        self.assertEqual(m.hmac.new(bytes.fromhex(context["candidate_secret_hex"]), raw, m.hashlib.sha256).hexdigest(),
                         VECTORS["positive_cases"][2]["token_hex"])

    def test_every_negative_fixture_runs_its_declared_operation_without_mutation(self):
        fixtures = VECTORS["negative_cases"]
        self.assertEqual(len(fixtures), 43)
        executed = set()
        for fixture in fixtures:
            with self.subTest(fixture=fixture["id"], operation=fixture["operation"]):
                manager, commits = self._fixture_manager(fixture["setup"])
                raw = bytes.fromhex(fixture["input_hex"])
                observed = self._fixture_binding(fixture["setup"].get("observed_binding_hex", fixture["setup"]["current_binding_hex"]))
                operation = fixture["operation"]
                before = copy.deepcopy(self._fixture_snapshot(manager, commits))
                if operation == "parse_control":
                    invoke = lambda: m.parse_control(raw)
                elif manager.fixture_role_error:
                    invoke = lambda: (_ for _ in ()).throw(m.MobilityError("E-CANDIDATE"))
                elif operation in ("validate_update", "submit_update", "receive_probe", "receive_response", "receive_result"):
                    invoke = lambda: manager.preview(raw, observed, fixture["setup"]["session"]["caller_replay_token"])
                elif operation == "replay_control":
                    accepted = bytes.fromhex(VECTORS["positive_cases"][0]["plaintext_hex"])
                    manager.commit(manager.preview(accepted, observed, fixture["setup"]["caller_replay_token"]))
                    before = copy.deepcopy(self._fixture_snapshot(manager, commits))
                    invoke = lambda: manager.commit(manager.preview(accepted, observed, fixture["setup"]["caller_replay_token"]))
                else:
                    self.fail(f"unknown corpus operation {operation}")
                with self.assertRaisesRegex(m.MobilityError, fixture["expected_error"]):
                    invoke()
                self.assertEqual(before, self._fixture_snapshot(manager, commits))
                self.assertEqual(manager.binding, self._fixture_binding(fixture["setup"]["current_binding_hex"]))
                self.assertEqual(tuple(commits), before[-1])
                executed.add(fixture["id"])
        self.assertEqual(len(executed), 43)

    def test_native_layout_and_typed_binding(self):
        self.assertEqual(m.NativeBinding(7, b"\x01" * 6).encode(), b"\x02\0\0\0\x07" + b"\x01" * 6)
        with self.assertRaises(m.MobilityError): m.NativeBinding(0, b"\x01" * 6).encode()
        with self.assertRaises(m.MobilityError): self.a_manager.preview(b"x", object(), 1)

    def test_role_one_mover_full_outbound_flow_and_token_direction(self):
        cid = b"\x01" * 16
        update = self.a_manager.propose_local("8::3", 1, cid, carrier=self.other)
        self._commit(self.b_manager, update, self.binding)
        probe = self.a_manager.make_probe(cid, self.other, b"\x02" * 16)
        challenge = self._commit(self.b_manager, probe, self.other)
        issued = m.Challenge.parse(challenge)
        expected = m.token_input(0, 1, self.a, self.b, cid, m.ipaddress.IPv6Address("8::3"), self.other, 1, 1, 0, 7, issued.expiry)
        self.assertEqual(issued.token, m.hmac.new(b"\x31" * 32, expected, m.hashlib.sha256).digest())
        response = self._commit(self.a_manager, challenge, self.other)
        self.assertEqual(response[4], 4)
        self._commit(self.b_manager, response, self.other)
        result = self.b_manager.take_results()[0]
        self._commit(self.a_manager, result, self.other)
        self.assertEqual(self.a_manager.local_loc, m.ipaddress.IPv6Address("8::3"))
        self.assertEqual(self.b_manager.peer_loc, m.ipaddress.IPv6Address("8::3"))
        self.assertEqual(self.a_manager.binding, self.other)
        self.assertEqual(self.b_manager.binding, self.other)
        self.assertEqual(self.a_manager.results[cid][0], result)
        self.assertEqual(self.a_manager.results[cid][1], self.now[0] + 10000)

    def test_accepted_results_fill_capacity_and_expire(self):
        def accept(candidate_id, epoch):
            self.a_manager.outbound[candidate_id] = (
                m.LocUpdate(candidate_id, self.a_manager.local_loc, m.ipaddress.IPv6Address("8::3"),
                            epoch, 0, 5000, 0, b"\0" * 64).build(),
                (m.ipaddress.IPv6Address("8::3"), epoch, 0), self.other, None)
            self.a_manager.outbound_expiry[candidate_id] = 20000
            result = m.Result(candidate_id, epoch, 0, 2).build()
            self._commit(self.a_manager, result, self.other, candidate_id)
        first, second, third = b"\x41" * 16, b"\x42" * 16, b"\x43" * 16
        accept(first, 1)
        accept(second, 2)
        self.assertEqual(set(self.a_manager.results), {first, second})
        self.a_manager.outbound[third] = (
            m.LocUpdate(third, self.a_manager.local_loc, m.ipaddress.IPv6Address("8::3"),
                        3, 0, 5000, 0, b"\0" * 64).build(),
            (m.ipaddress.IPv6Address("8::3"), 3, 0), self.other, None)
        self.a_manager.outbound_expiry[third] = 20000
        with self.assertRaisesRegex(m.MobilityError, "E-CAPACITY"):
            self.a_manager.preview(m.Result(third, 3, 0, 2).build(), self.other, third)
        self.now[0] = 10000
        self.a_manager.expire()
        accept(third, 3)
        self.assertEqual(set(self.a_manager.results), {third})
    def test_inbound_binding_grace_boundary_and_redacted_repr(self):
        old = self.binding
        self.a_manager.binding = self.other
        self.a_manager.grace = (old, 10000)
        self.now[0] = 9999
        self.assertTrue(self.a_manager.binding_allowed_inbound(self.other))
        self.assertTrue(self.a_manager.binding_allowed_inbound(old))
        self.assertFalse(self.a_manager.binding_allowed_inbound(
            UdpBinding.from_endpoint("192.0.2.99", 5999, 1, b"\x99" * 16)))
        self.now[0] = 10000
        generation = self.a_manager.generation
        self.assertFalse(self.a_manager.binding_allowed_inbound(old))
        self.assertIsNone(self.a_manager.grace)
        self.assertEqual(self.a_manager.generation, generation + 1)
        self.assertNotIn("192.0.2.", repr(self.a_manager))
        self.assertNotIn("8::", repr(self.a_manager))

    def test_role_two_mover_full_outbound_flow(self):
        cid = b"\x02" * 16
        update = self.b_manager.propose_local("8::3", 1, cid, carrier=self.other)
        self._commit(self.a_manager, update, self.binding)
        challenge = self._commit(self.a_manager, self.b_manager.make_probe(cid, self.other, b"\x03" * 16), self.other)
        response = self._commit(self.b_manager, challenge, self.other)
        self._commit(self.a_manager, response, self.other)
        self._commit(self.b_manager, self.a_manager.take_results()[0], self.other)
        self.assertEqual(self.b_manager.local_loc, m.ipaddress.IPv6Address("8::3"))
        self.assertEqual(self.a_manager.peer_loc, m.ipaddress.IPv6Address("8::3"))
    def test_inbound_cohort_uses_lexicographic_winner_not_proof_order(self):
        low, high = b"\x10" * 16, b"\x20" * 16
        for cid, loc in ((low, "8::3"), (high, "8::4")):
            self._commit(self.a_manager, self.b_manager.propose_local(loc, 1, cid, carrier=self.other), self.binding)
        challenges = {}
        for cid in (low, high):
            challenges[cid] = self._commit(self.a_manager, self.b_manager.make_probe(cid, self.other, cid), self.other)
        # Prove the larger candidate first.  The receiver freezes both cached proposals.
        self._commit(self.a_manager, self._commit(self.b_manager, challenges[high], self.other), self.other)
        self.assertEqual(self.a_manager.peer_loc, m.ipaddress.IPv6Address("8::2"))
        self._commit(self.a_manager, self._commit(self.b_manager, challenges[low], self.other), self.other)
        self.assertEqual(self.a_manager.peer_loc, m.ipaddress.IPv6Address("8::3"))
        emitted = {m.Result.parse(raw).candidate_id: m.Result.parse(raw).result for raw in self.a_manager.take_results()}
        self.assertEqual(emitted, {low: 1, high: 2})
    def test_frozen_cohort_rejects_late_equal_epoch_without_mutation(self):
        winner, pending, late = b"\x10" * 16, b"\x30" * 16, b"\x20" * 16
        update = lambda cid, loc: self.b_manager._sign_update(cid, m.ipaddress.IPv6Address(loc), 1, 0).build()
        self._commit(self.a_manager, self.b_manager.propose_local("8::3", 1, winner), self.binding)
        self._commit(self.a_manager, self.b_manager.propose_local("8::4", 1, pending), self.binding)
        challenge = self._commit(self.a_manager, self.b_manager.make_probe(
            winner, self.other, b"\x40" * 16), self.other)
        response = self._commit(self.b_manager, challenge, self.other)
        self._commit(self.a_manager, response, self.other)
        self.assertEqual(self.a_manager.cohort[0], 1)
        self.assertEqual(set(self.a_manager.cohort[1]), {winner, pending})
        before = copy.deepcopy(self._fixture_snapshot(self.a_manager, []))
        with self.assertRaisesRegex(m.MobilityError, "E-CANDIDATE"):
            self.a_manager.preview(update(late, "8::5"), self.binding, object())
        self.assertEqual(before, self._fixture_snapshot(self.a_manager, []))
        self.now[0] = 5000
        self.a_manager.expire()
        self.assertEqual(self.a_manager.peer_loc, m.ipaddress.IPv6Address("8::3"))
        self.now[0] = 15000
        self.assertFalse(self.a_manager.binding_allowed_inbound(self.binding))
        before = copy.deepcopy(self._fixture_snapshot(self.a_manager, []))
        with self.assertRaisesRegex(m.MobilityError, "E-CANDIDATE"):
            self.a_manager.preview(update(late, "8::5"), self.binding, object())
        self.assertEqual(before, self._fixture_snapshot(self.a_manager, []))
        self.assertNotIn(late, self.a_manager.proposals)
        self.assertEqual(self.a_manager.peer_epoch, 1)
    def test_frozen_cohort_keeps_prefreeze_equal_members_for_lexical_arbitration(self):
        low, high = b"\x10" * 16, b"\x20" * 16
        for cid, loc in ((low, "8::3"), (high, "8::4")):
            self._commit(self.a_manager, self.b_manager.propose_local(loc, 1, cid), self.binding)
        for cid in (high, low):
            challenge = self._commit(self.a_manager, self.b_manager.make_probe(cid, self.other, cid), self.other)
            self._commit(self.a_manager, self._commit(self.b_manager, challenge, self.other), self.other)
        self.assertEqual(self.a_manager.peer_loc, m.ipaddress.IPv6Address("8::3"))
        self.assertEqual(self.a_manager.peer_epoch, 1)

    def test_preview_callback_failure_and_stale_commit_do_not_mutate(self):
        calls = []
        def fail(token):
            calls.append(token)
            raise RuntimeError("session")
        manager = m.MobilityManager(self.a, PeerPin(2, self.b.eid, self.b.public), 1, 0, 1, 7, "8::1", "8::2", self.binding, b"\x30" * 32, lambda: self.now[0], fail)
        raw = self.b_manager.propose_local("8::3", 1, b"\x03" * 16)
        preview = manager.preview(raw, self.binding, 1)
        before = copy.deepcopy(self._fixture_snapshot(manager, []))
        with self.assertRaises(RuntimeError): manager.commit(preview)
        self.assertEqual(before, self._fixture_snapshot(manager, []))
        self.assertEqual(calls, [1])
        manager.session_commit = lambda _: None
        manager.commit(preview)
        with self.assertRaisesRegex(m.MobilityError, "E-REPLAY"): manager.commit(preview)
        self.assertEqual(calls, [1])

    def test_outbound_capacity_secret_zeroization_and_expiry_release(self):
        secret_state = self.a_manager.candidate_secret_state
        first = self.a_manager.propose_local("8::3", 1, b"\x03" * 16)
        self.assertEqual(first, self.a_manager.propose_local("8::3", 1, b"\x03" * 16))
        self.a_manager.propose_local("8::4", 2, b"\x04" * 16)
        with self.assertRaisesRegex(m.MobilityError, "E-CAPACITY"):
            self.a_manager.propose_local("8::5", 3, b"\x05" * 16)
        self.now[0] = 5000
        self.a_manager.expire()
        self.a_manager.propose_local("8::5", 3, b"\x05" * 16)
        self.a_manager.close()
        self.assertEqual(secret_state[0], self.a_manager.candidate_secret_state[0])
        self.assertTrue(self.a_manager.candidate_secret_state[1])
        with self.assertRaises(m.MobilityError): self.a_manager.preview(first, self.binding, 4)

    def test_higher_epoch_promotion_releases_lower_pending_state(self):
        low, high = b"\x31" * 16, b"\x32" * 16
        self._commit(self.a_manager, self.b_manager.propose_local("8::3", 1, low, carrier=self.other), self.binding)
        self._commit(self.a_manager, self.b_manager.propose_local("8::4", 2, high, carrier=self.other), self.binding)
        challenge = self._commit(self.a_manager, self.b_manager.make_probe(high, self.other, b"\x33" * 16), self.other)
        self._commit(self.a_manager, self._commit(self.b_manager, challenge, self.other), self.other)
        self.assertEqual(self.a_manager.peer_loc, m.ipaddress.IPv6Address("8::4"))
        self.assertNotIn(low, self.a_manager.proposals)
        self.assertNotIn(low, self.a_manager.candidates)

    def test_full_cohort_result_cache_rejects_before_session_callback(self):
        calls = []
        self.a_manager.session_commit = calls.append
        low, high = b"\x51" * 16, b"\x52" * 16
        for cid, loc in ((low, "8::3"), (high, "8::4")):
            self._commit(self.a_manager, self.b_manager.propose_local(loc, 1, cid, carrier=self.other), self.binding, cid)
        challenges = {cid: self._commit(self.a_manager, self.b_manager.make_probe(cid, self.other, cid), self.other, cid)
                      for cid in (low, high)}
        self._commit(self.a_manager, self._commit(self.b_manager, challenges[low], self.other, low), self.other, low)
        self.a_manager.results = {
            b"\xa1" * 16: (b"x", 10000, 1, 0, 2),
            b"\xa2" * 16: (b"y", 10000, 1, 0, 2),
        }
        before = copy.deepcopy(self._fixture_snapshot(self.a_manager, calls))
        response = self._commit(self.b_manager, challenges[high], self.other, high)
        with self.assertRaisesRegex(m.MobilityError, "E-CAPACITY"):
            self.a_manager.preview(response, self.other, high)
        self.assertEqual(before, self._fixture_snapshot(self.a_manager, calls))

    def test_expiry_invalidates_preview_before_session_callback(self):
        calls = []
        self.a_manager.session_commit = calls.append
        cid = b"\x53" * 16
        update = self.b_manager.propose_local("8::3", 1, cid, carrier=self.other)
        self._commit(self.a_manager, update, self.binding, cid)
        preview = self.a_manager.preview(self.b_manager.make_probe(cid, self.other, cid), self.other, object())
        callback_count = len(calls)
        self.now[0] = 5000
        self.a_manager.expire()
        with self.assertRaisesRegex(m.MobilityError, "E-REPLAY"):
            self.a_manager.commit(preview)
        self.assertEqual(len(calls), callback_count)
    def test_same_epoch_bidirectional_promotions_keep_epochs_independent(self):
        a_id, b_id = b"\x61" * 16, b"\x62" * 16
        a_update = self.a_manager.propose_local("8::3", 1, a_id, carrier=self.other)
        b_update = self.b_manager.propose_local("8::4", 1, b_id, carrier=self.other)
        self._commit(self.a_manager, b_update, self.binding, "a-update")
        self._commit(self.b_manager, a_update, self.binding, "b-update")
        a_challenge = self._commit(self.b_manager, self.a_manager.make_probe(a_id, self.other, a_id), self.other, "a-probe")
        b_challenge = self._commit(self.a_manager, self.b_manager.make_probe(b_id, self.other, b_id), self.other, "b-probe")
        a_response = self._commit(self.a_manager, a_challenge, self.other, "a-response")
        b_response = self._commit(self.b_manager, b_challenge, self.other, "b-response")
        self._commit(self.b_manager, a_response, self.other, "a-settle")
        self._commit(self.a_manager, b_response, self.other, "b-settle")
        self._commit(self.a_manager, self.b_manager.take_results()[0], self.other, "a-result")
        self._commit(self.b_manager, self.a_manager.take_results()[0], self.other, "b-result")
        self.assertEqual((self.a_manager.local_epoch, self.a_manager.peer_epoch), (1, 1))
        self.assertEqual((self.b_manager.local_epoch, self.b_manager.peer_epoch), (1, 1))
        self.assertEqual(self.a_manager.local_loc, m.ipaddress.IPv6Address("8::3"))
        self.assertEqual(self.b_manager.local_loc, m.ipaddress.IPv6Address("8::4"))

    def test_frozen_cohort_reserves_result_cache_before_local_result(self):
        calls = []
        self.a_manager.session_commit = calls.append
        winner, sibling, local = b"\x63" * 16, b"\x64" * 16, b"\x65" * 16
        for cid, loc in ((winner, "8::3"), (sibling, "8::4")):
            self._commit(self.a_manager, self.b_manager.propose_local(loc, 1, cid, carrier=self.other), self.binding, cid)
        challenge = self._commit(self.a_manager, self.b_manager.make_probe(winner, self.other, winner), self.other, "probe")
        self._commit(self.a_manager, self._commit(self.b_manager, challenge, self.other, "response"), self.other, "prove")
        self.assertEqual(set(self.a_manager.cohort[1]), {winner, sibling})
        self.a_manager.outbound[local] = (b"update", (m.ipaddress.IPv6Address("8::5"), 1, 0), self.other, None)
        before = self._fixture_snapshot(self.a_manager, calls)
        with self.assertRaisesRegex(m.MobilityError, "E-CAPACITY"):
            self.a_manager.preview(m.Result(local, 1, 0, 2).build(), self.other, "local-result")
        self.assertEqual(before, self._fixture_snapshot(self.a_manager, calls))

    def test_expiry_settles_frozen_siblings_and_invalidates_every_preview(self):
        winner, sibling = b"\x66" * 16, b"\x67" * 16
        for cid, loc in ((winner, "8::3"), (sibling, "8::4")):
            self._commit(self.a_manager, self.b_manager.propose_local(loc, 1, cid, carrier=self.other), self.binding, cid)
        preview = self.a_manager.preview(self.b_manager.make_probe(winner, self.other, winner), self.other, "stale")
        self.a_manager.expire()
        with self.assertRaisesRegex(m.MobilityError, "E-REPLAY"):
            self.a_manager.commit(preview)
        challenge = self._commit(self.a_manager, self.b_manager.make_probe(winner, self.other, winner), self.other, "probe")
        self._commit(self.a_manager, self._commit(self.b_manager, challenge, self.other, "response"), self.other, "prove")
        self.now[0] = 5000
        self.a_manager.expire()
        emitted = {m.Result.parse(raw).candidate_id: m.Result.parse(raw).result for raw in self.a_manager.take_results()}
        self.assertEqual(emitted, {winner: 1, sibling: 3})

    def test_exact_result_retry_is_idempotent(self):
        cid = b"\x68" * 16
        self.a_manager.outbound[cid] = (b"update", (m.ipaddress.IPv6Address("8::3"), 1, 0), self.other, None)
        raw = m.Result(cid, 1, 0, 2).build()
        self._commit(self.a_manager, raw, self.other, "first")
        before = self._fixture_snapshot(self.a_manager, [])
        self._commit(self.a_manager, raw, self.other, "duplicate")
        self.assertEqual(before, self._fixture_snapshot(self.a_manager, []))
    def test_response_commit_preserves_independent_preview(self):
        mover, peer = b"\x69" * 16, b"\x6a" * 16
        update = self.b_manager.propose_local("8::3", 1, mover, carrier=self.other)
        self._commit(self.a_manager, update, self.binding, "update")
        challenge = self._commit(self.a_manager, self.b_manager.make_probe(mover, self.other, mover), self.other, "probe")
        response_preview = self.b_manager.preview(challenge, self.other, "response")
        proposal_preview = self.b_manager.preview(
            self.a_manager.propose_local("8::4", 1, peer), self.binding, "proposal")
        generation = self.b_manager.generation
        response = self.b_manager.commit(response_preview)
        self.assertEqual(m.parse_control(response).typ, 4)
        self.assertEqual(self.b_manager.generation, generation)
        self.b_manager.commit(proposal_preview)
        self.assertIn(peer, self.b_manager.proposals)
    def test_probe_at_proposal_expiry_times_out(self):
        cid = b"\x70" * 16
        update = m.LocUpdate(cid, self.a_manager.peer_loc, m.ipaddress.IPv6Address("8::3"), 1, 0, 5000, 0, b"\0" * 64)
        self.a_manager.proposals[cid] = (update.build(), update, 5000)
        self.now[0] = 5000
        with self.assertRaisesRegex(m.MobilityError, "E-TIMEOUT"):
            self.a_manager.preview(m.Probe(cid, update.new_loc, update.epoch, update.slot, b"\0" * 16).build(), self.other, "expired")
if __name__ == "__main__":
    unittest.main()
