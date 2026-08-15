import json
import pathlib
import sys
import unittest
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import r8mobility as mobility
import r8redundant as redundant
import r8session as session
VECTORS = json.loads((ROOT / "tests" / "vectors" / "session-v0.1.json").read_text())


class RedundantStateTests(unittest.TestCase):
    def setUp(self):
        self.now = [100]
        self.binding0 = session.UdpBinding.from_endpoint("192.0.2.1", 4000, 1, b"a" * 16)
        self.binding1 = session.NativeBinding(9, b"\x02\x03\x04\x05\x06\x07")
        identities, context = VECTORS["identities"], VECTORS["context"]
        self.client_identity = session.Identity.from_seed(bytes.fromhex(identities["client_ed25519_seed_hex"]))
        self.server_identity = session.Identity.from_seed(bytes.fromhex(identities["server_ed25519_seed_hex"]))
        self.client_loc = session.ipaddress.IPv6Address("11:2233:4455:6677:8899:aabb:ccdd:eeff")
        self.server_loc = session.ipaddress.IPv6Address("ffee:ddcc:bbaa:9988:7766:5544:3322:1100")
        client = session.ClientMachine(self.client_identity,
            session.PeerPin(2, self.server_identity.eid, self.server_identity.public),
            context["service_context"], 3, self.client_loc, self.server_loc, lambda: self.now[0])
        server = session.ServerMachine(session.ServerConfig(self.server_identity,
            session.PeerPin(1, self.client_identity.eid, self.client_identity.public),
            context["service_context"], context["server_context_id"], 3, self.server_loc, self.client_loc, 1280, 2, 2),
            bytes.fromhex(context["server_boot_instance_hex"]), bytes.fromhex(context["cookie_key_hex"]), None, 0,
            lambda: self.now[0], session.PrevalidationLimiter(lambda: self.now[0], b"\xa0" * 32))
        opening = client.start(
            context["scid"], bytes.fromhex(identities["client_x25519_secret_hex"]),
            bytes.fromhex(context["client_nonce_hex"]),
            _authority=session._HANDSHAKE_MATERIAL_AUTHORITY)
        auth = client.receive_verify(server.receive_open_packet(opening, self.binding0, context["cookie_bucket"]))
        ack = server.receive_open_auth(
            auth, self.binding0, context["cookie_bucket"],
            bytes.fromhex(identities["server_x25519_secret_hex"]),
            bytes.fromhex(context["server_nonce_hex"]),
            _authority=session._HANDSHAKE_MATERIAL_AUTHORITY)
        server.receive_protected(client.receive_ack(ack))
        client_bootstrap = client.take_profile3()
        server_bootstrap = server.take_profile3(context["scid"])
        self.client_bootstrap_alias, self.server_bootstrap_alias = client_bootstrap, server_bootstrap
        authority = session._PROFILE3_CONSUMER_AUTHORITY
        self.client_slot0_alias, self.server_slot0_alias = client_bootstrap._context(authority)[4], server_bootstrap._context(authority)[4]
        self.a = redundant.RedundantSession(client_bootstrap, self.binding0, 1280, 11, lambda: self.now[0])
        self.b = redundant.RedundantSession(server_bootstrap, self.binding0, 1280, 91,
                                            lambda: self.now[0])

    def assert_error(self, category, call, *args):
        with self.assertRaises(redundant.RedundantError) as raised:
            call(*args)
        self.assertEqual(raised.exception.category, category)

    def move_front(self, source, dest, slot=0, binding=None):
        packet = source.front(slot)
        source.confirm(slot, packet)
        return dest.receive(slot, binding or self.binding0, packet)


    def test_constructor_exclusively_invalidates_retained_bootstrap_alias(self):
        for alias, machine in ((self.client_bootstrap_alias, self.a),
                               (self.server_bootstrap_alias, self.b)):
            for attribute in ("scid", "outbound", "inbound", "_prk", "_thash"):
                with self.assertRaises(AttributeError):
                    getattr(alias, attribute)
            with self.assertRaises(AttributeError):
                getattr(alias, "take_slot1")
            with self.assertRaises(session.SessionError):
                alias._context(object())
            alias.close()
            self.assertFalse(machine.closed)
            self.assertTrue(machine.send(b"alias cannot close owner").packets[0])
            self.assert_error("E-CANDIDATE", redundant.RedundantSession,
                              alias, self.binding0, 1280, 1, lambda: self.now[0])
        header = session.Header(session.NH_SES, self.client_loc, self.server_loc, profile=3,
                                flags=1, pslot=0, scid=VECTORS["context"]["scid"])
        for alias in (self.client_slot0_alias, self.server_slot0_alias):
            self.assertTrue(alias._released)
            self.assertIsNone(alias._key)
            with self.assertRaises(session.SessionError):
                session.seal_profile3_data(alias, header, 999, b"bypass")
    def test_send_removal_release_and_redaction(self):
        self.assertEqual(redundant._REDUNDANT_CORES[self.a].events, [redundant.Event("degraded", 1)])
        first, second = self.a.send(b"one"), self.a.send(b"two")
        self.assertEqual(self.a.queue_metrics(),
                         {"queued_packets": 2, "queued_bytes": sum(redundant._REDUNDANT_CORES[self.a].queue_bytes),
                          "overflow_packets": 0})
        self.assertEqual(first.packets[1], None)
        self.assertEqual(len(first.packets), 2)
        self.assertTrue(self.b.receive(0, self.binding0, second.packets[0]).delivered)
        lower = self.b.receive(0, self.binding0, first.packets[0])
        self.assertTrue(lower.delivered)
        self.assertEqual(lower.plaintext, b"one")
        for value in (self.a, first, lower, redundant._REDUNDANT_CORES[self.a].events):
            self.assertNotIn("one", repr(value))
            self.assertNotIn(str(VECTORS["context"]["scid"]), repr(value))
            self.assertNotIn(str(self.client_loc), repr(value))
            self.assertNotIn(repr(self.binding0), repr(value))
        self.assertFalse(hasattr(self.a, "bootstrap"))
        self.assertFalse(hasattr(self.a, "scid"))
        self.assertFalse(hasattr(self.a, "clock"))
        self.assertFalse(hasattr(self.a, "next_delivery_id"))
        self.assertFalse(hasattr(self.a, "high_water"))
        self.assertFalse(hasattr(first, "delivery_id"))
        self.assertFalse(hasattr(lower, "delivery_id"))
        self.a.remove_path(0)
        self.assertTrue(self.a.closed)
        self.assertEqual(redundant._REDUNDANT_CORES[self.a].events[-1], redundant.Event("released"))
        self.a.remove_path(0)
        self.a.close()
        self.a.restart()
        self.assertEqual(redundant._REDUNDANT_CORES[self.a].events.count(redundant.Event("released")), 1)
        self.assertTrue(all(value is None for value in redundant._REDUNDANT_CORES[self.a]._bindings))
        self.assertTrue(all(value is None for value in redundant._REDUNDANT_CORES[self.a]._local_locs))
        self.assertTrue(all(value is None for value in redundant._REDUNDANT_CORES[self.a]._peer_locs))
        self.assertEqual(redundant._REDUNDANT_CORES[self.a].queue_bytes, [0, 0])
        self.assertEqual(self.a.dedup_size, 0)
    def test_outstanding_receive_preview_blocks_removal_and_close_purges_it(self):
        packet = self.a.send(b"preview").packets[0]
        preview = self.b.preview_receive(0, self.binding0, packet)
        self.assert_error("E-CAPACITY", self.b.remove_path, 0)
        self.b.close()
        with self.assertRaisesRegex(redundant.RedundantError, "E-REPLAY"):
            preview.plaintext
        self.assertEqual(redundant._REDUNDANT_CORES[self.b]._receive_previews, {})
        self.assert_error("E-REPLAY", self.b.commit_receive, preview)
    def test_fabricated_mutated_stale_and_cross_session_handles_are_rejected(self):
        with self.assertRaisesRegex(redundant.RedundantError, "E-REPLAY"):
            redundant.ReceivePreview()
        with self.assertRaisesRegex(redundant.RedundantError, "E-REPLAY"):
            self.b.commit_receive(object())
        packet = self.a.send(b"opaque").packets[0]
        preview = self.b.preview_receive(0, self.binding0, packet)
        with self.assertRaises(AttributeError):
            preview._plaintext = b"forged"
        self.assert_error("E-REPLAY", self.a.commit_receive, preview)
        self.b.abort_receive(preview)
        self.assert_error("E-REPLAY", self.b.commit_receive, preview)

    def test_absent_invalid_removed_idempotent_and_event_history_bounded(self):
        self.assert_error("E-PATH", self.a.remove_path, 1)
        self.a.remove_path(0)
        self.a.remove_path(0)
        self.assert_error("E-CANDIDATE", self.a.activate_slot1, object(), self.binding1, 1280)
        self.setUp()
        for _ in range(256):
            self.a.send(b"")
        for _ in range(65):
            self.a.send(b"")
        self.assertLessEqual(len(redundant._REDUNDANT_CORES[self.a].events), 64)
        self.assertEqual(redundant._REDUNDANT_CORES[self.a].events[-1], redundant.Event("queue-overflow", 0))
        self.assertEqual(self.a.queue_metrics()["overflow_packets"], 65)

    def _admissions(self):
        alice = session.Identity.from_seed(b"\x11" * 32)
        bob = session.Identity.from_seed(b"\x22" * 32)
        a = mobility.MobilityManager(alice, session.PeerPin(2, bob.eid, bob.public), 1, 3,
            VECTORS["context"]["scid"], 3,
            str(self.client_loc), str(self.server_loc), self.binding0, b"c" * 32, lambda: self.now[0],
            self.a.commit_receive, self.a.issue_profile3_admission_owner(3))
        b = mobility.MobilityManager(bob, session.PeerPin(1, alice.eid, alice.public), 2, 3,
            VECTORS["context"]["scid"], 3,
            str(self.server_loc), str(self.client_loc), self.binding0, b"d" * 32, lambda: self.now[0],
            self.b.commit_receive, self.b.issue_profile3_admission_owner(3))
        def carry(source, dest, manager, plaintext, observed_binding):
            packet = source.send(plaintext).packets[0]
            return dest.commit_mobility(dest.preview_mobility(manager, 0, observed_binding, packet))
        cid = b"z" * 16
        update = a.propose_local("8::3", 1, cid, slot=1, carrier=self.binding1)
        carry(self.a, self.b, b, update, self.binding0)
        challenge = carry(self.a, self.b, b, a.make_probe(cid, self.binding1, b"n" * 16), self.binding1)
        response = carry(self.b, self.a, a, challenge, self.binding1)
        carry(self.a, self.b, b, response, self.binding1)
        carry(self.b, self.a, a, b.take_results()[0], self.binding1)
        self._mobility_managers = (a, b)
        return a.take_profile3_admissions()[0], b.take_profile3_admissions()[0]
    def test_mobility_manager_does_not_expose_signing_identity(self):
        self._admissions()
        for manager in self._mobility_managers:
            self.assertFalse(hasattr(manager, "identity"))
            with self.assertRaises(AttributeError):
                manager.identity

    def test_mobility_requires_its_exact_carrier_preview(self):
        alice = session.Identity.from_seed(b"\x11" * 32)
        bob = session.Identity.from_seed(b"\x22" * 32)
        source = mobility.MobilityManager(
            alice, session.PeerPin(2, bob.eid, bob.public), 1, 3, VECTORS["context"]["scid"], 3,
            str(self.client_loc), str(self.server_loc), self.binding0, b"c" * 32, lambda: self.now[0],
            self.a.commit_receive, self.a.issue_profile3_admission_owner(3))
        destination = mobility.MobilityManager(
            bob, session.PeerPin(1, alice.eid, alice.public), 2, 3, VECTORS["context"]["scid"], 3,
            str(self.server_loc), str(self.client_loc), self.binding0, b"d" * 32, lambda: self.now[0],
            self.b.commit_receive, self.b.issue_profile3_admission_owner(3))
        update = source.propose_local("8::3", 1, b"z" * 16, slot=1, carrier=self.binding1)
        packet = self.a.send(update).packets[0]
        ordinary = self.b.preview_receive(0, self.binding0, packet)
        with self.assertRaisesRegex(mobility.MobilityError, "E-REPLAY"):
            destination.preview(ordinary.plaintext, self.binding0, ordinary)
        with self.assertRaisesRegex(mobility.MobilityError, "E-REPLAY"):
            source.preview(ordinary.plaintext, self.binding0, ordinary)
        self.b.abort_receive(ordinary)
        preview = self.b.preview_mobility(destination, 0, self.binding0, packet)
        self.b.abort_mobility(preview)
        core = redundant._REDUNDANT_CORES[self.b]
        self.assertEqual(core._mobility_associations, {})
        self.assertEqual(core._mobility_previews, {})
    def test_profile3_owner_rejects_different_policy_manager(self):
        owner = self.a.issue_profile3_admission_owner(3)
        with self.assertRaisesRegex(mobility.MobilityError, "E-CANDIDATE"):
            mobility.MobilityManager(
                self.client_identity,
                session.PeerPin(2, self.server_identity.eid, self.server_identity.public),
                1, 3, VECTORS["context"]["scid"], 4,
                str(self.client_loc), str(self.server_loc), self.binding0, b"c" * 32,
                lambda: self.now[0], self.a.commit_receive, owner)
        self.assertEqual(redundant._REDUNDANT_CORES[self.a].states[1], redundant.ABSENT)
    def test_direct_second_owner_cannot_bypass_retained_owner(self):
        owner = mobility.issue_profile3_admission_owner(self.a, VECTORS["context"]["scid"], 3)
        with self.assertRaisesRegex(mobility.MobilityError, "E-CANDIDATE"):
            self.a.issue_profile3_admission_owner(3)
        mobility._revoke_profile3_owner(owner)
    def test_two_real_mobility_admissions_and_one_shot_failure_rollback(self):
        admission_a, admission_b = self._admissions()
        self.assert_error("E-CANDIDATE", self.a.activate_slot1, admission_b, self.binding1, 1280)
        self.assertEqual(redundant._REDUNDANT_CORES[self.a].states[1], redundant.ABSENT)
        self.assert_error("E-CANDIDATE", self.a.activate_slot1, admission_a, object(), 1280)
        self.assertEqual(redundant._REDUNDANT_CORES[self.a].states[1], redundant.ABSENT)
        self.assertTrue(redundant._REDUNDANT_CORES[self.a]._out[1] is None)
        self.assertTrue(redundant._REDUNDANT_CORES[self.a]._in[1] is None)
        self.assertTrue(redundant._REDUNDANT_CORES[self.a]._bindings[1] is None)
        original_schedule = session._key_schedule_prk
        def fail_schedule(*_args):
            raise RuntimeError("injected")
        session._key_schedule_prk = fail_schedule
        try:
            self.assert_error("E-CANDIDATE", self.a.activate_slot1, admission_a, self.binding1, 1280)
        finally:
            session._key_schedule_prk = original_schedule
        self.assertEqual(redundant._REDUNDANT_CORES[self.a].states[1], redundant.ABSENT)
        self.assertEqual(len(session._PROFILE3_SLOT1_PREPARATIONS), 0)
        self.a.activate_slot1(admission_a, self.binding1, 1280)
        self.b.activate_slot1(admission_b, self.binding1, 1280)
        self.assertEqual(redundant._REDUNDANT_CORES[self.a].states, [redundant.ACTIVE, redundant.ACTIVE])
        sent = self.a.send(b"cross-path")
        self.assertIsNotNone(sent.packets[0])
        self.assertIsNotNone(sent.packets[1])
        self.assertEqual(redundant._REDUNDANT_CORES[self.a].events[-1], redundant.Event("recovered", 1))
        self.assertTrue(self.b.receive(0, self.binding0, sent.packets[0]).delivered)
        self.assert_error("E-CANDIDATE", self.a.activate_slot1, admission_a, self.binding1, 1280)
    def test_delivery_authority_outlives_plaintext_cache_and_rejects_divergence(self):
        admission_a, admission_b = self._admissions()
        self.a.activate_slot1(admission_a, self.binding1, 1280)
        self.b.activate_slot1(admission_b, self.binding1, 1280)
        sent = self.a.send(b"retained")
        self.assertTrue(self.b.receive(0, self.binding0, sent.packets[0]).delivered)
        self.now[0] += 30000
        self.assertFalse(self.b.receive(1, self.binding1, sent.packets[1]).delivered)
        header = self.a._header(1)
        divergent = session.seal_profile3_data(redundant._REDUNDANT_CORES[self.a]._out[1], header, 11, b"divergent", 1280)
        self.assert_error("E-PATH", self.b.receive, 1, self.binding1, divergent)
        self.assertTrue(self.b.closed)
    def test_delivery_id_older_than_identity_window_fails_without_redelivery(self):
        sent = self.a.send(b"too old")
        redundant._REDUNDANT_CORES[self.b]._high_water = redundant._REDUNDANT_CORES[self.a]._next_delivery_id - 1 + 4096
        self.assert_error("E-REPLAY", self.b.receive, 0, self.binding0, sent.packets[0])
        self.assertFalse(self.b.closed)
        self.assertEqual(self.b.dedup_size, 0)

    def test_transactional_receive_aborts_without_replay_or_delivery_mutation(self):
        sent = self.a.send(b"transactional")
        preview = self.b.preview_receive(0, self.binding0, sent.packets[0])
        self.assertEqual(preview.plaintext, b"transactional")
        self.assertEqual(self.b.dedup_size, 0)
        self.assert_error(
            "E-CAPACITY", self.b.preview_receive, 0, self.binding0, sent.packets[0])
        self.b.abort_receive(preview)
        self.assertTrue(self.b.receive(0, self.binding0, sent.packets[0]).delivered)
    def test_removed_slot_cannot_activate_or_retain_session_keys(self):
        admission, _ = self._admissions()
        self.a.activate_slot1(admission, self.binding1, 1280)
        outbound, inbound = redundant._REDUNDANT_CORES[self.a]._out[1], redundant._REDUNDANT_CORES[self.a]._in[1]
        self.a.remove_path(1)
        self.assertEqual(redundant._REDUNDANT_CORES[self.a].states[1], redundant.REMOVED)
        for retained in (outbound, inbound):
            self.assertTrue(retained._released)
            self.assertIsNone(retained._key)
        self.assert_error("E-CANDIDATE", self.a.activate_slot1, object(), self.binding1, 1280)
        self.a.remove_path(1)


    def test_preview_release_race_returns_no_live_plaintext(self):
        inbound = redundant._REDUNDANT_CORES[self.a]._in[0]
        incoming = session.Header(session.NH_SES, self.server_loc, self.client_loc, profile=3,
                                  flags=1, pslot=0, scid=VECTORS["context"]["scid"])
        packet = session.seal_profile3_data(redundant._REDUNDANT_CORES[self.b]._out[0], incoming, 7, b"pending-secret")
        entered, proceed, result = threading.Event(), threading.Event(), []
        original = session.Profile3DataPreview.__init__
        def paused_init(preview, *args, **kwargs):
            original(preview, *args, **kwargs)
            entered.set()
            proceed.wait()
        session.Profile3DataPreview.__init__ = paused_init
        try:
            worker = threading.Thread(target=lambda: result.append(session.preview_profile3_data(inbound, packet)))
            worker.start()
            self.assertTrue(entered.wait(1))
            closer = threading.Thread(target=self.a.close)
            closer.start()
            proceed.set()
            worker.join(1)
            closer.join(1)
        finally:
            session.Profile3DataPreview.__init__ = original
        self.assertEqual(len(result), 1)
        with self.assertRaises(session.SessionError):
            _ = result[0].plaintext
        with self.assertRaises(session.SessionError):
            session.commit_profile3_data(inbound, result[0])
    def test_terminal_release_revokes_retained_sessions_and_previews(self):
        outbound, inbound = redundant._REDUNDANT_CORES[self.a]._out[0], redundant._REDUNDANT_CORES[self.a]._in[0]
        outgoing = session.Header(session.NH_SES, self.client_loc, self.server_loc, profile=3,
                                  flags=1, pslot=0, scid=VECTORS["context"]["scid"])
        incoming = session.Header(session.NH_SES, self.server_loc, self.client_loc, profile=3,
                                  flags=1, pslot=0, scid=VECTORS["context"]["scid"])
        packet = session.seal_profile3_data(redundant._REDUNDANT_CORES[self.b]._out[0], incoming, 7, b"pending-secret")
        preview = session.preview_profile3_data(inbound, packet)
        self.assertEqual(preview.plaintext, b"pending-secret")
        self.a.close()
        self.a.close()
        for retained in (outbound, inbound):
            self.assertTrue(retained._released)
            self.assertIsNone(retained._key)
            self.assertEqual(retained.send_counter, 0)
            self.assertEqual(retained.replay.highest, 0)
            self.assertEqual(retained.replay.bits, 0)
        with self.assertRaises(session.SessionError):
            _ = preview.plaintext
        with self.assertRaises(session.SessionError):
            session.commit_profile3_data(inbound, preview)
        with self.assertRaises(session.SessionError):
            session.seal_profile3_data(outbound, outgoing, 8, b"secret")
        with self.assertRaises(session.SessionError):
            session.preview_profile3_data(inbound, packet)
        with self.assertRaises(session.SessionError):
            session.commit_profile3_data(inbound, preview)
        with self.assertRaises(session.SessionError):
            inbound.decrypt(incoming, b"\x06\x01\x03\x00", 1, b"")
        self.assertEqual(redundant._REDUNDANT_CORES[self.a]._next_delivery_id, 0)
        self.assertIsNone(redundant._REDUNDANT_CORES[self.a]._high_water)
        self.assertEqual(redundant._REDUNDANT_CORES[self.a]._dedup, {})
    def test_facade_shadows_cannot_expose_or_change_private_delivery_authority(self):
        self.assertFalse(hasattr(self.a, "_bootstrap"))
        self.assertFalse(hasattr(self.a, "_out"))
        self.assertFalse(hasattr(self.a, "_in"))
        self.a.__dict__["states"] = [redundant.RELEASED, redundant.RELEASED]
        self.a.__dict__["_delivery"] = {}
        self.a.__dict__["_high_water"] = None
        self.assertFalse(self.a.closed)
        packet = self.a.send(b"private-core").packets[0]
        self.assertTrue(self.b.receive(0, self.binding0, packet).delivered)
    def test_reserved_authenticated_delivery_ids_abort_before_preview_registration(self):
        core_a = redundant._REDUNDANT_CORES[self.a]
        core_b = redundant._REDUNDANT_CORES[self.b]
        incoming = session.Header(session.NH_SES, self.client_loc, self.server_loc, profile=3,
            flags=1, pslot=0, scid=VECTORS["context"]["scid"])
        packet = session.seal_profile3_data(core_a._out[0], incoming, 1, b"reserved", 1280)
        original_preview, original_abort = session.preview_profile3_data, session.abort_profile3_data
        try:
            for ident in (0, redundant._MAX):
                session.preview_profile3_data = lambda *_args, ident=ident: type(
                    "_ReservedPreview", (), {"delivery_id": ident, "plaintext": b"reserved"})()
                session.abort_profile3_data = lambda *_args: None
                self.assert_error("E-COUNTER", self.b.preview_receive, 0, self.binding0, packet)
                self.assertEqual(core_b._receive_previews, {})
        finally:
            session.preview_profile3_data, session.abort_profile3_data = original_preview, original_abort
    def test_binding_bytes_subclasses_are_canonicalized_before_authority_use(self):
        class HostileBinding(bytes):
            def __eq__(self, _other):
                return True
            def __ne__(self, _other):
                return False
        encoded = HostileBinding(self.binding0.encode())
        mobility_binding = mobility._binding(encoded)
        redundant_binding = redundant._binding(encoded)
        self.assertIs(type(mobility_binding), bytes)
        self.assertIs(type(redundant_binding), bytes)
        self.assertEqual(mobility_binding, self.binding0.encode())
        self.assertEqual(redundant_binding, self.binding0.encode())
        self.assertNotEqual(redundant_binding, self.binding1.encode())
    def test_mutated_admission_and_cross_session_same_scid_are_rejected(self):
        admission_a, admission_b = self._admissions()
        original_local, original_peer = admission_a.local_loc.packed, admission_a.peer_loc.packed
        object.__setattr__(admission_a.local_loc, "_ip", int(session.ipaddress.IPv6Address("8::dead")))
        object.__setattr__(admission_a.peer_loc, "_ip", int(session.ipaddress.IPv6Address("8::dead")))
        details, _ = mobility.profile3_admission_details(admission_a, self.a)
        self.assertEqual(details[4], original_local)
        self.assertEqual(details[5], original_peer)
        self.assertIsInstance(details[4], bytes)
        object.__setattr__(admission_a, "peer_binding", self.binding0)
        self.assert_error("E-CANDIDATE", self.b.activate_slot1, admission_a, self.binding1, 1280)
        self.assert_error("E-CANDIDATE", self.a.activate_slot1, admission_b, self.binding1, 1280)
        object.__setattr__(admission_a, "peer_binding", self.binding1)
        self.a.activate_slot1(admission_a, self.binding1, 1280)
        core = redundant._REDUNDANT_CORES[self.a]
        self.assertEqual(core._local_locs[1], original_local)
        self.assertEqual(core._peer_locs[1], original_peer)
if __name__ == "__main__":
    unittest.main()
