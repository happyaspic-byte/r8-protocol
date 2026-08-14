"""Strict R8 M1 mobility controls and transactional candidate lifecycle."""
import hashlib
import hmac
import ipaddress
import struct
import threading
from dataclasses import dataclass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from r8session import UdpBinding

CATEGORIES = frozenset(("E-CANDIDATE", "E-CAPACITY", "E-TIMEOUT", "E-REPLAY"))
MAGIC = b"R8M1"

class MobilityError(ValueError):
    def __init__(self, category):
        if category not in CATEGORIES:
            raise ValueError("invalid mobility error")
        self.category = category
        super().__init__(category)

def _fail(category="E-CANDIDATE"):
    raise MobilityError(category)

def _view(value):
    try:
        return memoryview(value).cast("B")
    except (TypeError, ValueError):
        _fail()

def _exact(value, length):
    if len(value) != length:
        _fail()

def _loc(value):
    try:
        return ipaddress.IPv6Address(value)
    except (ValueError, ipaddress.AddressValueError):
        _fail()

def _u64(value, nonzero=False):
    if type(value) is not int or not 0 <= value <= 0xffffffffffffffff or (nonzero and value == 0):
        _fail()

def _slot(profile, slot):
    if type(slot) is not int or slot not in (0, 1) or (profile == 3) != (slot == 1):
        _fail()

def _cid(value):
    _exact(value, 16)
    if bytes(value) == b"\0" * 16:
        _fail()

def _binding(value):
    if not isinstance(value, (UdpBinding, NativeBinding)):
        _fail()
    try:
        value.encode()
    except Exception:
        _fail()
    return value

def _envelope(typ, body):
    return MAGIC + bytes((typ, 1)) + b"\0\0" + body

def _parse(value, typ, total):
    view = _view(value)
    _exact(view, total)
    if view[:4].tobytes() != MAGIC or view[4] != typ or view[5] != 1 or view[6:8].tobytes() != b"\0\0":
        _fail()
    return view[8:].tobytes()

def update_input(profile, scid, sender, receiver, old, new, epoch, not_before, valid, cid, slot):
    return (b"R8 LOC_UPDATE v1" + bytes((1, profile)) + struct.pack("!Q", scid) + sender.eid + receiver.eid +
            old.packed + new.packed + struct.pack("!QQQ", epoch, not_before, valid) + cid + bytes((slot,)))

def token_input(profile, scid, sender, receiver, cid, loc, binding, direction, epoch, slot, policy, expiry):
    return (b"R8 bind v1" + bytes((1, profile)) + struct.pack("!Q", scid) + sender.eid + receiver.eid + cid + loc.packed +
            binding.encode() + bytes((direction,)) + struct.pack("!QBIQ", epoch, slot, policy, expiry))

@dataclass(frozen=True)
class LocUpdate:
    candidate_id: bytes; old_loc: ipaddress.IPv6Address; new_loc: ipaddress.IPv6Address; epoch: int; not_before: int; valid_for: int; slot: int; signature: bytes
    def build(self):
        _cid(self.candidate_id); _loc(self.old_loc); _loc(self.new_loc); _u64(self.epoch, True); _u64(self.not_before); _u64(self.valid_for); _exact(self.signature, 64)
        if self.slot not in (0, 1): _fail()
        return _envelope(1, self.candidate_id + self.old_loc.packed + self.new_loc.packed + struct.pack("!QQQB", self.epoch, self.not_before, self.valid_for, self.slot) + self.signature)
    @classmethod
    def parse(cls, value):
        body = _parse(value, 1, 145)
        obj = cls(body[:16], _loc(body[16:32]), _loc(body[32:48]), *struct.unpack("!QQQB", body[48:73]), body[73:])
        _cid(obj.candidate_id); _u64(obj.epoch, True); _slot(0 if obj.slot == 0 else 3, obj.slot)
        if obj.not_before != 0 or obj.valid_for != 5000:
            _fail()
        _exact(obj.signature, 64)
        return obj

@dataclass(frozen=True)
class Probe:
    candidate_id: bytes; loc: ipaddress.IPv6Address; epoch: int; slot: int; nonce: bytes
    def build(self):
        _cid(self.candidate_id); _loc(self.loc); _u64(self.epoch, True); _exact(self.nonce, 16)
        if self.slot not in (0, 1): _fail()
        return _envelope(2, self.candidate_id + self.loc.packed + struct.pack("!QB", self.epoch, self.slot) + self.nonce)
    @classmethod
    def parse(cls, value):
        body = _parse(value, 2, 65); obj = cls(body[:16], _loc(body[16:32]), *struct.unpack("!QB", body[32:41]), body[41:])
        _cid(obj.candidate_id); _u64(obj.epoch, True); _exact(obj.nonce, 16)
        if obj.slot not in (0, 1): _fail()
        return obj

@dataclass(frozen=True)
class Challenge:
    candidate_id: bytes; loc: ipaddress.IPv6Address; epoch: int; slot: int; expiry: int; token: bytes; typ: int = 3
    def build(self):
        _cid(self.candidate_id); _loc(self.loc); _u64(self.epoch, True); _u64(self.expiry, True); _exact(self.token, 32)
        if self.typ not in (3, 4) or self.slot not in (0, 1): _fail()
        return _envelope(self.typ, self.candidate_id + self.loc.packed + struct.pack("!QBQ", self.epoch, self.slot, self.expiry) + self.token)
    @classmethod
    def parse(cls, value, typ=3):
        body = _parse(value, typ, 89); obj = cls(body[:16], _loc(body[16:32]), *struct.unpack("!QBQ", body[32:49]), body[49:], typ)
        _cid(obj.candidate_id); _u64(obj.epoch, True); _u64(obj.expiry, True); _exact(obj.token, 32)
        if obj.slot not in (0, 1): _fail()
        return obj

@dataclass(frozen=True)
class Result:
    candidate_id: bytes; epoch: int; slot: int; result: int
    def build(self):
        _cid(self.candidate_id); _u64(self.epoch, True)
        if self.slot not in (0, 1) or self.result not in (1, 2, 3): _fail()
        return _envelope(5, self.candidate_id + struct.pack("!QBB", self.epoch, self.slot, self.result))
    @classmethod
    def parse(cls, value):
        body = _parse(value, 5, 34); obj = cls(body[:16], *struct.unpack("!QBB", body[16:]))
        obj.build(); return obj

@dataclass(frozen=True)
class NativeBinding:
    ingress_descriptor_id: int
    next_hop_mac: bytes
    def encode(self):
        if type(self.ingress_descriptor_id) is not int or not 0 < self.ingress_descriptor_id <= 0xffffffff or len(self.next_hop_mac) != 6:
            _fail()
        return b"\x02" + struct.pack("!I", self.ingress_descriptor_id) + self.next_hop_mac

def parse_control(value):
    view = _view(value)
    if len(view) < 8 or view[:4].tobytes() != MAGIC:
        _fail()
    parser = {1: LocUpdate.parse, 2: Probe.parse, 3: Challenge.parse, 4: lambda x: Challenge.parse(x, 4), 5: Result.parse}.get(view[4])
    if parser is None: _fail()
    return parser(value)

@dataclass(frozen=True)
class Preview:
    generation: int
    action: str
    control: object
    binding: object
    replay_token: object
    response: bytes | None
    prepared: tuple = ()

class MobilityManager:
    """All state changes are serialized by one lock and originate in ``commit``."""
    def __init__(self, identity, peer_pin, local_role, profile, scid, policy_id, local_loc, peer_loc, peer_binding, candidate_secret, clock, session_commit=lambda token: None):
        if local_role not in (1, 2) or peer_pin.role not in (1, 2) or local_role == peer_pin.role: _fail()
        if type(profile) is not int or not 0 <= profile <= 3 or type(scid) is not int or not 0 < scid <= 0xffffffffffffffff or type(policy_id) is not int or not 0 <= policy_id <= 0xffffffff: _fail()
        _exact(candidate_secret, 32); _binding(peer_binding)
        self.identity, self.peer_pin, self.local_role, self.profile, self.scid, self.policy_id = identity, peer_pin, local_role, profile, scid, policy_id
        self.local_loc, self.peer_loc, self.binding, self.secret, self.clock = _loc(local_loc), _loc(peer_loc), peer_binding, bytearray(candidate_secret), clock
        self.session_commit = session_commit; self.lock = threading.RLock(); self.generation = 0; self.local_epoch = 0; self.peer_epoch = 0; self.closed = False
        self.outbound = {}; self.outbound_expiry = {}; self.proposals = {}; self.candidates = {}; self.results = {}; self.cohort = None
        self.tokens = 2; self.refill = self._now(); self.grace = None; self.emitted = []
    def __repr__(self):
        return f"MobilityManager(profile={self.profile}, closed={self.closed}, generation={self.generation}, proposals={len(self.proposals)}, candidates={len(self.candidates)})"
    @property
    def candidate_secret_erased(self):
        return not any(self.secret)
    @property
    def candidate_secret_state(self):
        return id(self.secret), self.candidate_secret_erased
    def _now(self):
        value = self.clock()
        if type(value) is not int or value < 0: _fail()
        return value
    def _slot(self, slot): _slot(self.profile, slot)
    def _direction(self): return self.peer_pin.role
    def _result_entry(self, cid, proposal, candidate, code, now):
        old = self.results.get(cid)
        if old is not None:
            return old, None
        raw = Result(cid, proposal.epoch, proposal.slot, code).build()
        response = candidate["challenge"] if candidate is not None else None
        binding = candidate["binding"] if candidate is not None else None
        return (raw, now + 10000, proposal.epoch, proposal.slot, code, response, binding), raw
    def _settlement_plan(self, now, candidates, cohort, proposals=None, results=None, emitted=None, peer_loc=None, binding=None, peer_epoch=None, grace=None):
        proposals = self.proposals if proposals is None else proposals
        results = self.results if results is None else results
        emitted = self.emitted if emitted is None else emitted
        peer_loc = self.peer_loc if peer_loc is None else peer_loc
        binding = self.binding if binding is None else binding
        peer_epoch = self.peer_epoch if peer_epoch is None else peer_epoch
        grace = self.grace if grace is None else grace
        if cohort is None:
            return candidates, proposals, results, emitted, None, peer_loc, binding, peer_epoch, grace
        epoch, members = cohort
        results = dict(results)
        required = sum(cid not in results for cid in members)
        if len(results) + required > 2:
            _fail("E-CAPACITY")
        for cid in members:
            candidate = candidates.get(cid)
            if candidate is None and cid in proposals:
                return candidates, proposals, results, emitted, cohort, peer_loc, binding, peer_epoch, grace
            if candidate is not None and candidate["state"] not in ("PROVEN", "FAILED"):
                return candidates, proposals, results, emitted, cohort, peer_loc, binding, peer_epoch, grace
        proven = sorted(cid for cid in members if cid in candidates and candidates[cid]["state"] == "PROVEN")
        additions = []
        if proven:
            winner = proven[0]
            for cid, proposal in members.items():
                candidate = candidates.get(cid)
                additions.append((cid, proposal, candidate, 1 if cid == winner else (2 if candidate is not None else 3)))
        else:
            additions = [(cid, proposal, candidates.get(cid), 3) for cid, proposal in members.items()]
        emitted = list(emitted)
        for cid, proposal, candidate, code in additions:
            entry, raw = self._result_entry(cid, proposal, candidate, code, now)
            if cid not in results:
                results[cid] = entry
                emitted.append(raw)
        if proven:
            winner = proven[0]
            candidates[winner]["state"] = "PROMOTED"
            for cid in members:
                if cid != winner and cid in candidates:
                    candidates[cid]["state"] = "FAILED"
        proposals = {cid: item for cid, item in proposals.items() if item[1].epoch > epoch}
        candidates = {cid: candidate for cid, candidate in candidates.items() if candidate["proposal"].epoch > epoch}
        if not proven:
            return candidates, proposals, results, emitted, None, peer_loc, binding, peer_epoch, grace
        original = next(candidate for cid, _, candidate, _ in additions if cid == proven[0])
        return candidates, proposals, results, emitted, None, original["proposal"].new_loc, original["binding"], epoch, (binding, now + 10000)
    def _refilled(self, now):
        elapsed = (now - self.refill) // 1000
        return min(2, self.tokens + max(0, elapsed)), (self.refill + max(0, elapsed) * 1000)
    def _sign_update(self, cid, new, epoch, slot):
        raw = update_input(self.profile, self.scid, self.identity, self.peer_pin, self.local_loc, new, epoch, 0, 5000, cid, slot)
        return LocUpdate(cid, self.local_loc, new, epoch, 0, 5000, slot, self.identity.private.sign(raw))
    def propose_local(self, new_loc, epoch, candidate_id, slot=0, carrier=None):
        with self.lock:
            if self.closed or epoch <= self.local_epoch: _fail()
            _cid(candidate_id); _u64(epoch, True); self._slot(slot); new = _loc(new_loc)
            found = self.outbound.get(candidate_id)
            if found is not None:
                if found[1] == (new, epoch, slot): return found[0]
                _fail()
            if len(self.outbound) >= 2: _fail("E-CAPACITY")
            update = self._sign_update(bytes(candidate_id), new, epoch, slot); raw = update.build()
            if carrier is not None: _binding(carrier)
            self.outbound[candidate_id] = (raw, (new, epoch, slot), carrier, None); self.outbound_expiry[candidate_id] = self._now() + 5000
            self.generation += 1
            return raw
    propose = propose_local
    def make_probe(self, candidate_id, carrier, nonce):
        with self.lock:
            if self.closed: _fail()
            _cid(candidate_id); _binding(carrier); _exact(nonce, 16)
            outbound = self.outbound.get(candidate_id)
            if outbound is None: _fail()
            new_loc, epoch, slot = outbound[1]; self._slot(slot)
            if epoch <= self.local_epoch: _fail()
            old_carrier = outbound[2]
            if old_carrier is not None and old_carrier != carrier: _fail()
            self.outbound[candidate_id] = (outbound[0], outbound[1], carrier, outbound[3])
            if old_carrier != carrier:
                self.generation += 1
            return Probe(candidate_id, new_loc, epoch, slot, nonce).build()
    def preview(self, control_bytes, observed_binding, replay_token):
        with self.lock:
            if self.closed: _fail()
            _binding(observed_binding); control = parse_control(control_bytes); now = self._now()
            if isinstance(control, LocUpdate):
                self._slot(control.slot)
                raw = update_input(self.profile, self.scid, self.peer_pin, self.identity, control.old_loc, control.new_loc, control.epoch, control.not_before, control.valid_for, control.candidate_id, control.slot)
                try: Ed25519PublicKey.from_public_bytes(self.peer_pin.public_key).verify(control.signature, raw)
                except (InvalidSignature, ValueError): _fail()
                if control.old_loc != self.peer_loc or control.epoch <= self.peer_epoch: _fail()
                existing = self.proposals.get(control.candidate_id)
                if existing is not None:
                    if existing[0] == bytes(control_bytes): return Preview(self.generation, "noop", control, observed_binding, replay_token, None)
                    _fail()
                if self.cohort is not None and control.epoch <= self.cohort[0]: _fail()
                if control.candidate_id in self.candidates or control.candidate_id in self.outbound or control.candidate_id in self.results:
                    _fail()
                tokens, refill = self._refilled(now)
                if tokens < 1: _fail()
                if len(self.proposals) >= 2: _fail("E-CAPACITY")
                entry = (bytes(control_bytes), control, now + 5000)
                return Preview(self.generation, "proposal", control, observed_binding, replay_token, None,
                               (control.candidate_id, entry, tokens - 1, refill))
            if isinstance(control, Probe):
                self._slot(control.slot); proposal = self.proposals.get(control.candidate_id)
                if proposal is None: _fail()
                if now >= proposal[2]: _fail("E-TIMEOUT")
                if proposal[1].epoch <= self.peer_epoch or (proposal[1].new_loc, proposal[1].epoch, proposal[1].slot) != (control.loc, control.epoch, control.slot): _fail()
                existing = self.candidates.get(control.candidate_id)
                if existing is not None:
                    if existing["challenge"] is not None and existing["binding"] == observed_binding: return Preview(self.generation, "noop", control, observed_binding, replay_token, existing["challenge"].build())
                    _fail()
                if len(self.candidates) >= 2 or self.grace is not None: _fail("E-CAPACITY")
                expiry = now + 3000
                token = hmac.new(self.secret, token_input(self.profile, self.scid, self.peer_pin, self.identity, control.candidate_id, control.loc, observed_binding, self._direction(), control.epoch, control.slot, self.policy_id, expiry), hashlib.sha256).digest()
                ch = Challenge(control.candidate_id, control.loc, control.epoch, control.slot, expiry, token)
                candidate = {"binding": observed_binding, "expiry": ch.expiry, "challenge": ch, "state": "CHALLENGED", "proposal": proposal[1]}
                return Preview(self.generation, "challenge", control, observed_binding, replay_token, ch.build(),
                               (control.candidate_id, candidate))
            if isinstance(control, Challenge) and control.typ == 3:
                self._slot(control.slot); outbound = self.outbound.get(control.candidate_id)
                if outbound is None or control.epoch <= self.local_epoch or outbound[1] != (control.loc, control.epoch, control.slot) or outbound[2] != observed_binding: _fail()
                response = Challenge(control.candidate_id, control.loc, control.epoch, control.slot, control.expiry, control.token, 4).build()
                return Preview(self.generation, "response", control, observed_binding, replay_token, response)
            if isinstance(control, Challenge):
                self._slot(control.slot); candidate = self.candidates.get(control.candidate_id)
                cached = self.results.get(control.candidate_id)
                if candidate is None:
                    if cached is not None and len(cached) == 7 and cached[5] is not None and cached[6] == observed_binding and control == Challenge(cached[5].candidate_id, cached[5].loc, cached[5].epoch, cached[5].slot, cached[5].expiry, cached[5].token, 4):
                        return Preview(self.generation, "noop", control, observed_binding, replay_token, cached[0])
                    _fail()
                if candidate["challenge"] is None: _fail()
                expected = candidate["challenge"]
                if now >= expected.expiry: _fail("E-TIMEOUT")
                if candidate["binding"] != observed_binding or control != Challenge(expected.candidate_id, expected.loc, expected.epoch, expected.slot, expected.expiry, expected.token, 4): _fail()
                if cached is not None: return Preview(self.generation, "noop", control, observed_binding, replay_token, cached[0])
                if candidate["state"] == "PROVEN": return Preview(self.generation, "noop", control, observed_binding, replay_token, None)
                if candidate["state"] != "CHALLENGED": _fail()
                candidates = {cid: dict(item) for cid, item in self.candidates.items()}
                candidates[control.candidate_id]["state"] = "PROVEN"
                cohort = self.cohort
                greatest = max(item[1].epoch for item in self.proposals.values())
                if cohort is None and candidates[control.candidate_id]["proposal"].epoch == greatest:
                    cohort = (greatest, {cid: item[1] for cid, item in self.proposals.items() if item[1].epoch == greatest})
                return Preview(self.generation, "proven", control, observed_binding, replay_token, None,
                               self._settlement_plan(now, candidates, cohort))
            if isinstance(control, Result):
                self._slot(control.slot); outbound = self.outbound.get(control.candidate_id)
                cached = self.results.get(control.candidate_id)
                if cached is not None and len(cached) == 6 and cached[0] == bytes(control_bytes) and cached[5] == observed_binding:
                    return Preview(self.generation, "noop", control, observed_binding, replay_token, None)
                if outbound is None or outbound[1] != (outbound[1][0], control.epoch, control.slot) or outbound[2] != observed_binding: _fail()
                if outbound[3] is not None:
                    if outbound[3] == bytes(control_bytes): return Preview(self.generation, "noop", control, observed_binding, replay_token, None)
                    _fail()
                if control.epoch <= self.local_epoch: _fail()
                reserved = sum(cid not in self.results for cid in self.cohort[1]) if self.cohort is not None else 0
                if control.candidate_id not in self.results and len(self.results) + reserved >= 2: _fail("E-CAPACITY")
                result = control.build()
                result_entry = (result, now + 10000, control.epoch, control.slot, control.result, observed_binding)
                outbound_entry = (outbound[0], outbound[1], outbound[2], result)
                prepared = (control.candidate_id, outbound_entry, result_entry,
                            (outbound[1][0], outbound[2], control.epoch, (self.binding, now + 10000))
                            if control.result == 1 else None)
                return Preview(self.generation, "local-result", control, observed_binding, replay_token, None, prepared)
            _fail()
    def _settle(self, now):
        candidates = {cid: dict(candidate) for cid, candidate in self.candidates.items()}
        plan = self._settlement_plan(now, candidates, self.cohort)
        (self.candidates, self.proposals, self.results, self.emitted, self.cohort,
         self.peer_loc, self.binding, self.peer_epoch, self.grace) = plan
    def commit(self, preview):
        with self.lock:
            if not isinstance(preview, Preview) or preview.generation != self.generation: _fail("E-REPLAY")
            prepared_lengths = {"noop": 0, "response": 0, "proposal": 4, "challenge": 2, "proven": 9, "local-result": 4}
            if preview.action not in prepared_lengths or (preview.action not in ("noop", "response") and
                    (type(preview.prepared) is not tuple or len(preview.prepared) != prepared_lengths[preview.action])):
                _fail("E-REPLAY")
            # Every fallible operation is completed by preview before the session seam.
            self.session_commit(preview.replay_token)
            if preview.action in ("noop", "response"):
                return preview.response
            if preview.action == "proposal":
                cid, entry, tokens, refill = preview.prepared
                self.proposals[cid] = entry
                self.tokens, self.refill = tokens, refill
            elif preview.action == "challenge":
                cid, candidate = preview.prepared
                self.candidates[cid] = candidate
            elif preview.action == "proven":
                (self.candidates, self.proposals, self.results, self.emitted, self.cohort,
                 self.peer_loc, self.binding, self.peer_epoch, self.grace) = preview.prepared
            elif preview.action == "local-result":
                cid, outbound_entry, result_entry, promotion = preview.prepared
                self.outbound[cid] = outbound_entry
                self.results[cid] = result_entry
                if promotion is not None:
                    self.local_loc, self.binding, self.local_epoch, self.grace = promotion
            self.generation += 1
            return preview.response
    def expire(self):
        with self.lock:
            if self.closed:
                return
            now = self._now()
            proposals = {cid: item for cid, item in self.proposals.items() if now < item[2]}
            results = {cid: item for cid, item in self.results.items() if now < item[1]}
            expired_outbound = {cid for cid, expiry in self.outbound_expiry.items() if now >= expiry}
            outbound = {cid: item for cid, item in self.outbound.items() if cid not in expired_outbound}
            outbound_expiry = {cid: expiry for cid, expiry in self.outbound_expiry.items() if cid not in expired_outbound}
            candidates = {cid: dict(candidate) for cid, candidate in self.candidates.items()}
            for candidate in candidates.values():
                if candidate["state"] == "CHALLENGED" and now >= candidate["expiry"]:
                    candidate["state"] = "FAILED"
            grace = None if self.grace is not None and now >= self.grace[1] else self.grace
            plan = self._settlement_plan(now, candidates, self.cohort, proposals, results, self.emitted,
                                         self.peer_loc, self.binding, self.peer_epoch, grace)
            (candidates, proposals, results, emitted, cohort,
             peer_loc, binding, peer_epoch, grace) = plan
            self.proposals, self.results = proposals, results
            self.outbound, self.outbound_expiry = outbound, outbound_expiry
            self.candidates, self.emitted, self.cohort = candidates, emitted, cohort
            self.peer_loc, self.binding, self.peer_epoch, self.grace = peer_loc, binding, peer_epoch, grace
            self.generation += 1
    def binding_allowed_inbound(self, binding):
        with self.lock:
            binding = _binding(binding)
            now = self._now()
            if binding == self.binding:
                return True
            if self.grace is None or binding != self.grace[0]:
                return False
            if now < self.grace[1]:
                return True
            self.grace = None
            self.generation += 1
            return False
    def bind_outbound_carrier(self, candidate_id, carrier):
        """Record the caller carrier that is authorized to deliver its challenge/result."""
        with self.lock:
            _cid(candidate_id); _binding(carrier)
            if candidate_id not in self.outbound: _fail()
            raw, data, old, response = self.outbound[candidate_id]
            if old is not None and old != carrier: _fail()
            self.outbound[candidate_id] = (raw, data, carrier, response)
            if old != carrier:
                self.generation += 1
    def take_results(self):
        with self.lock:
            result, self.emitted = tuple(self.emitted), []
            if result:
                self.generation += 1
            return result
    def close(self):
        with self.lock:
            self.closed = True
            for index in range(len(self.secret)):
                self.secret[index] = 0
            self.outbound.clear(); self.outbound_expiry.clear(); self.proposals.clear(); self.candidates.clear(); self.results.clear(); self.cohort = None; self.grace = None; self.emitted.clear(); self.generation += 1
    restart = close
