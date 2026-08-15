import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import r8session as s

V = json.loads((ROOT / "tests" / "vectors" / "session-v0.1.json").read_text())


class Profile3BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.i, self.x, self.now = V["identities"], V["context"], [0]
        self.client_identity = s.Identity.from_seed(bytes.fromhex(self.i["client_ed25519_seed_hex"]))
        self.server_identity = s.Identity.from_seed(bytes.fromhex(self.i["server_ed25519_seed_hex"]))
        self.client_loc = s.ipaddress.IPv6Address("11:2233:4455:6677:8899:aabb:ccdd:eeff")
        self.server_loc = s.ipaddress.IPv6Address("ffee:ddcc:bbaa:9988:7766:5544:3322:1100")
        self.binding = s.UdpBinding.from_endpoint("192.0.2.10", 52808, 1, b"\x90" * 16)

    def handshake(self, profile=3):
        client = s.ClientMachine(self.client_identity, s.PeerPin(2, self.server_identity.eid, self.server_identity.public),
                                 self.x["service_context"], profile, self.client_loc, self.server_loc, lambda: self.now[0])
        server = s.ServerMachine(s.ServerConfig(self.server_identity, s.PeerPin(1, self.client_identity.eid, self.client_identity.public),
                                 self.x["service_context"], self.x["server_context_id"], profile, self.server_loc, self.client_loc, 1280, 2, 2),
                                 bytes.fromhex(self.x["server_boot_instance_hex"]), bytes.fromhex(self.x["cookie_key_hex"]), None, 0,
                                 lambda: self.now[0], s.PrevalidationLimiter(lambda: self.now[0], b"\xa0" * 32))
        opening = client.start(self.x["scid"], bytes.fromhex(self.i["client_x25519_secret_hex"]), bytes.fromhex(self.x["client_nonce_hex"]), _authority=s._HANDSHAKE_MATERIAL_AUTHORITY)
        auth = client.receive_verify(server.receive_open_packet(opening, self.binding, self.x["cookie_bucket"]))
        ack = server.receive_open_auth(auth, self.binding, self.x["cookie_bucket"], bytes.fromhex(self.i["server_x25519_secret_hex"]), bytes.fromhex(self.x["server_nonce_hex"]), _authority=s._HANDSHAKE_MATERIAL_AUTHORITY)
        accept = client.receive_ack(ack)
        server.receive_protected(accept)
        return client, server

    def receive(self, session, packet):
        preview = s.preview_profile3_data(session, packet)
        return s.commit_profile3_data(session, preview)

    def test_transfer_is_opaque_and_disposes_machines(self):
        client, server = self.handshake()
        client_aliases = (client.c2s_session, client.s2c_session)
        server_entry = server.established[self.x["scid"]]
        server_aliases = (server_entry["s2c"], server_entry["c2s"])
        client_bootstrap, server_bootstrap = client.take_profile3(), server.take_profile3(self.x["scid"])
        self.assertEqual(client.state, client.RELEASED)
        self.assertIsNone(client.c2s_session)
        self.assertNotIn(self.x["scid"], server.established)
        for alias in (*client_aliases, *server_aliases):
            self.assertTrue(alias._released)
            self.assertIsNone(alias._key)
            with self.assertRaises(s.SessionError):
                alias.__init__(b"\xff" * 32)
            with self.assertRaises(s.SessionError):
                s.seal_profile3_data(
                    alias,
                    s.Header(s.NH_SES, self.client_loc, self.server_loc,
                             profile=3, flags=1, pslot=0, scid=self.x["scid"]),
                    1,
                    b"forbidden",
                )
        self.assertNotIn(self.x["scid"].to_bytes(8, "big").hex(), repr(client_bootstrap))
        self.assertNotIn(str(self.client_loc), repr(client_bootstrap))
        for bootstrap in (client_bootstrap, server_bootstrap):
            for attribute in ("scid", "outbound", "inbound", "take_slot1", "_prk", "_thash"):
                with self.assertRaises(AttributeError):
                    getattr(bootstrap, attribute)
            with self.assertRaises(s.SessionError):
                bootstrap._context(object())
            bootstrap.close()
            bootstrap.close()

    def test_accept_counter_one_is_replayed_before_data_decryption(self):
        client, server = self.handshake()
        session = server.established[self.x["scid"]]["c2s"]
        with self.assertRaises(s.SessionError) as caught:
            session.replay.preview(1)
        self.assertEqual(caught.exception.category, "REPLAY")

    def test_direct_bootstrap_forgery_is_rejected_and_repr_is_safe(self):
        outbound, inbound = s.Session(b"\x01" * 32), s.Session(b"\x02" * 32)
        with self.assertRaises(s.SessionError) as caught:
            s.Profile3Bootstrap(self.x["scid"], 1, self.client_loc, self.server_loc,
                                outbound, inbound, b"\x03" * 32, b"\x04" * 32,
                                _authority=object())
        self.assertEqual(caught.exception.category, "UNEXPECTED_MESSAGE")
        client, _ = self.handshake()
        bootstrap = client.take_profile3()
        self.assertEqual(repr(bootstrap), "<Profile3Bootstrap>")
        self.assertNotIn(self.x["scid"].to_bytes(8, "big").hex(), repr(bootstrap))
        self.assertNotIn(str(self.client_loc), repr(bootstrap))
    def test_rejects_profile_zero_and_outstanding_preview_without_mutation(self):
        client, server = self.handshake(0)
        client_state, established = client.state, dict(server.established)
        with self.assertRaises(s.SessionError): client.take_profile3()
        with self.assertRaises(s.SessionError): server.take_profile3(self.x["scid"])
        self.assertEqual(client.state, client_state)
        self.assertEqual(server.established, established)
        client, server = self.handshake(3)
        header = s.Header(s.NH_SES, self.client_loc, self.server_loc, profile=3, flags=1, pslot=0, scid=self.x["scid"])
        packet = s.seal_profile3_data(client.c2s_session, header, 1, b"pending")
        session = server.established[self.x["scid"]]["c2s"]
        preview = s.preview_profile3_data(session, packet)
        with self.assertRaises(s.SessionError): server.take_profile3(self.x["scid"])
        self.assertIn(self.x["scid"], server.established)
        s.abort_profile3_data(session, preview)
        server.take_profile3(self.x["scid"])

    def test_server_restart_purges_profile3_preview_plaintext_and_key_references(self):
        client, server = self.handshake(3)
        header = s.Header(s.NH_SES, self.client_loc, self.server_loc, profile=3, flags=1,
                          pslot=0, scid=self.x["scid"])
        packet = s.seal_profile3_data(client.c2s_session, header, 1, b"pending-secret")
        inbound = server.established[self.x["scid"]]["c2s"]
        preview = s.preview_profile3_data(inbound, packet)
        self.assertEqual(preview.plaintext, b"pending-secret")
        with self.assertRaises(s.SessionError):
            preview.__init__(inbound, object(), 99, b"forged")
        server.restart(b"r" * 16, b"k" * 32)
        with self.assertRaises(s.SessionError):
            _ = preview.plaintext
        with self.assertRaises(s.SessionError):
            s.commit_profile3_data(inbound, preview)


    def test_close_releases_owned_and_prepared_sessions_and_preview(self):
        client, server = self.handshake(3)
        client_bootstrap, server_bootstrap = client.take_profile3(), server.take_profile3(self.x["scid"])
        authority = s._PROFILE3_CONSUMER_AUTHORITY
        client_context = client_bootstrap._context(authority)
        server_context = server_bootstrap._context(authority)
        outbound, inbound = client_context[4], client_context[5]
        preparation = client_bootstrap._prepare_slot1(authority)
        prepared = s._PROFILE3_SLOT1_PREPARATIONS[preparation][1:]
        incoming = s.Header(s.NH_SES, self.server_loc, self.client_loc, profile=3,
                            flags=1, pslot=0, scid=self.x["scid"])
        packet = s.seal_profile3_data(server_context[4], incoming, 7, b"pending-secret")
        preview = s.preview_profile3_data(inbound, packet)
        self.assertEqual(preview.plaintext, b"pending-secret")
        client_bootstrap.close()
        client_bootstrap.close()
        for retained in (outbound, inbound, *prepared):
            self.assertTrue(retained._released)
            self.assertIsNone(retained._key)
            self.assertEqual(retained.send_counter, 0)
            self.assertEqual(retained.replay.highest, 0)
            self.assertEqual(retained.replay.bits, 0)
        with self.assertRaises(s.SessionError):
            _ = preview.plaintext
        with self.assertRaises(s.SessionError):
            s.commit_profile3_data(inbound, preview)
        with self.assertRaises(s.SessionError):
            client_bootstrap._context(authority)
        server_bootstrap.close()
if __name__ == "__main__":
    unittest.main()
