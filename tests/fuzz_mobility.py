import copy
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference"))
import r8mobility as m
from r8session import Identity, PeerPin, UdpBinding


def run(seed=0x52384D31, cases=2048, maximum_size=256):
    """Bounded parser fuzzing: every malformed input has a finite public category."""
    rng = random.Random(seed)
    for _ in range(cases):
        value = rng.randbytes(rng.randrange(maximum_size + 1))
        try:
            m.parse_control(value)
        except m.MobilityError as error:
            assert error.category in m.CATEGORIES
        except Exception as error:
            raise AssertionError(repr(error)) from error
def frozen_epoch_rejections(seed=0x47303034, cases=128):
    """Late equal/lower updates must fail without changing a frozen cohort."""
    rng = random.Random(seed)
    clock = [0]
    sender_identity, receiver_identity = Identity.from_seed(b"\x41" * 32), Identity.from_seed(b"\x42" * 32)
    binding = UdpBinding.from_endpoint("192.0.2.1", 5000, 1, b"\x43" * 16)
    sender = m.MobilityManager(sender_identity, PeerPin(2, receiver_identity.eid, receiver_identity.public),
                               1, 0, 1, 7, "8::1", "8::2", binding, b"\x44" * 32, lambda: clock[0])
    receiver = m.MobilityManager(receiver_identity, PeerPin(1, sender_identity.eid, sender_identity.public),
                                 2, 0, 1, 7, "8::2", "8::1", binding, b"\x45" * 32, lambda: clock[0])
    def commit(raw, token):
        return receiver.commit(receiver.preview(raw, binding, token))
    def snapshot():
        return copy.deepcopy((receiver.local_loc, receiver.peer_loc, receiver.binding, receiver.local_epoch, receiver.peer_epoch,
                              receiver.generation, receiver.tokens, receiver.refill, receiver.proposals,
                              receiver.candidates, receiver.outbound, receiver.outbound_expiry,
                              receiver.results, receiver.cohort, receiver.grace, receiver.emitted))
    for case in range(cases):
        winner = (case + 1).to_bytes(16, "big")
        pending = (case + cases + 1).to_bytes(16, "big")
        receiver.close()
        receiver = m.MobilityManager(receiver_identity, PeerPin(1, sender_identity.eid, sender_identity.public),
                                     2, 0, 1, 7, "8::2", "8::1", binding, b"\x45" * 32, lambda: clock[0])
        update = lambda cid, loc, epoch: sender._sign_update(cid, m.ipaddress.IPv6Address(loc), epoch, 0).build()
        commit(update(winner, "8::3", 1), (case, 1))
        commit(update(pending, "8::4", 1), (case, 2))
        core = m._MOBILITY_CORES[receiver]
        core.candidates[winner] = {"binding": m._binding(binding), "expiry": 3000, "challenge": None,
                                   "state": "PROVEN", "proposal": core.proposals[winner][1]}
        core.cohort = (1, {winner: core.proposals[winner][1], pending: core.proposals[pending][1]})
        before = snapshot()
        late_id = rng.randbytes(16) or b"\0" * 15 + b"\x01"
        late = update(late_id, "8::5", 1)
        try:
            receiver.preview(late, binding, (case, 3))
        except m.MobilityError as error:
            assert error.category == "E-CANDIDATE"
        else:
            raise AssertionError("late equal/lower update was accepted")
        assert before == snapshot()


if __name__ == "__main__":
    run()
    frozen_epoch_rejections()
