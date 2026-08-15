"""Bounded hostile-input state fuzzer for the redundant reference machine."""
import json
import os
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
import r8redundant as redundant
import r8session as session
VECTORS = json.loads((ROOT / "tests" / "vectors" / "session-v0.1.json").read_text())


def make_pair(now):
    binding = session.UdpBinding.from_endpoint("192.0.2.1", 4000, 1, b"f" * 16)
    identities, context = VECTORS["identities"], VECTORS["context"]
    client_identity = session.Identity.from_seed(bytes.fromhex(identities["client_ed25519_seed_hex"]))
    server_identity = session.Identity.from_seed(bytes.fromhex(identities["server_ed25519_seed_hex"]))
    client_loc = session.ipaddress.IPv6Address("11:2233:4455:6677:8899:aabb:ccdd:eeff")
    server_loc = session.ipaddress.IPv6Address("ffee:ddcc:bbaa:9988:7766:5544:3322:1100")
    client = session.ClientMachine(client_identity, session.PeerPin(2, server_identity.eid, server_identity.public),
        context["service_context"], 3, client_loc, server_loc, lambda: now[0])
    server = session.ServerMachine(session.ServerConfig(server_identity,
        session.PeerPin(1, client_identity.eid, client_identity.public), context["service_context"],
        context["server_context_id"], 3, server_loc, client_loc, 1280, 2, 2),
        bytes.fromhex(context["server_boot_instance_hex"]), bytes.fromhex(context["cookie_key_hex"]), None, 0,
        lambda: now[0], session.PrevalidationLimiter(lambda: now[0], b"\xa0" * 32))
    opening = client.start(context["scid"], bytes.fromhex(identities["client_x25519_secret_hex"]),
                           bytes.fromhex(context["client_nonce_hex"]))
    auth = client.receive_verify(server.receive_open_packet(opening, binding, context["cookie_bucket"]))
    ack = server.receive_open_auth(auth, binding, context["cookie_bucket"],
        bytes.fromhex(identities["server_x25519_secret_hex"]), bytes.fromhex(context["server_nonce_hex"]))
    server.receive_protected(client.receive_ack(ack))
    return (redundant.RedundantSession(client.take_profile3(), binding, 1280, 1, lambda: now[0]),
            redundant.RedundantSession(server.take_profile3(context["scid"]), binding, 1280, 9, lambda: now[0]),
            binding)


def fuzz(data):
    """Never accepts hostile input into unbounded state or leaks lifecycle state."""
    data = bytes(memoryview(data).cast("B"))[:1281]
    rng, now = random.Random(data), [0]
    left, right, binding = make_pair(now)
    marker = b"fuzz-plaintext-marker"
    for _ in range(min(512, len(data) + 1)):
        now[0] += rng.randrange(0, 1000)
        action = rng.randrange(5)
        try:
            if action == 0 and not left.closed:
                left.send(marker if rng.randrange(8) == 0 else bytes(rng.randrange(256) for _ in range(rng.randrange(0, 64))))
            elif action == 1:
                right.receive(rng.randrange(2), binding, bytes(rng.randrange(256) for _ in range(rng.randrange(0, 1282))))
            elif action == 2:
                packet = left.front(0)
                if packet is not None:
                    right.receive(0, binding, packet)
                    left.confirm(0, packet)
            elif action == 3:
                left.remove_path(rng.randrange(2))
            else:
                right.receive(0, binding, data)
        except (redundant.RedundantError, ValueError):
            pass
        for machine in (left, right):
            assert machine.dedup_size <= 4096
            assert all(0 <= size <= 262144 for size in machine.queue_bytes)
            assert all(state in (redundant.ABSENT, redundant.CANDIDATE, redundant.VALIDATED,
                                 redundant.ACTIVE, redundant.DEGRADED, redundant.REMOVED,
                                 redundant.RELEASED) for state in machine.states)
            assert not hasattr(machine, "bootstrap") and not hasattr(machine, "scid")
            assert not hasattr(machine, "next_delivery_id") and not hasattr(machine, "high_water")
            assert "fuzz-plaintext-marker" not in repr(machine)
            assert machine.events.count(redundant.Event("released")) <= 1
            if machine.closed:
                core = redundant._REDUNDANT_CORES[machine]
                assert machine.states == (redundant.RELEASED, redundant.RELEASED)
                assert core._bindings == [None, None]
                assert core._local_locs == [None, None]
                assert core._peer_locs == [None, None]
                assert not core._dedup


if __name__ == "__main__":
    fuzz(os.urandom(1281))
