"""Strict R8 M1 mobility controls and transactional candidate lifecycle."""
import hashlib
import copy
import hmac
import ipaddress
import struct
import threading
import weakref
from dataclasses import dataclass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from r8session import Binding, Identity, NativeBinding, PeerPin, UdpBinding, validate_binding


class _Redacted:
    __slots__ = ()
    def __repr__(self):
        return f"<{type(self).__name__}>"
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
    if isinstance(value, memoryview):
        if value.nbytes != length:
            _fail()
    elif type(value) is not bytes or len(value) != length:
        _fail()

def _loc(value):
    try:
        return ipaddress.IPv6Address(value)
    except (ValueError, ipaddress.AddressValueError):
        _fail()
def _loc_bytes(value):
    try:
        packed = value if isinstance(value, bytes) else ipaddress.IPv6Address(value).packed
    except (ValueError, ipaddress.AddressValueError):
        _fail()
    if type(packed) is not bytes or len(packed) != 16:
        _fail()
    return bytes(packed)

def _loc_view(value):
    if type(value) is not bytes or len(value) != 16:
        _fail()
    return ipaddress.IPv6Address(value)

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
    if isinstance(value, bytes):
        value = bytes(value)
        _binding_view(value)
        return value
    try:
        return bytes(validate_binding(value))
    except Exception:
        _fail()

def _binding_view(value):
    if not isinstance(value, bytes):
        _fail()
    try:
        if value[:2] == b"\x01\x04" and len(value) == 25:
            return UdpBinding(value[2:6], int.from_bytes(value[6:8], "big"), value[8], value[9:])
        if value[:2] == b"\x01\x06" and len(value) == 37:
            return UdpBinding(value[2:18], int.from_bytes(value[18:20], "big"), value[20], value[21:])
        if value[:1] == b"\x02" and len(value) == 11:
            return NativeBinding(int.from_bytes(value[1:5], "big"), value[5:])
    except (TypeError, ValueError):
        pass
    _fail()

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
            _loc_packed(old) + _loc_packed(new) + struct.pack("!QQQ", epoch, not_before, valid) + cid + bytes((slot,)))

def token_input(profile, scid, sender, receiver, cid, loc, binding, direction, epoch, slot, policy, expiry):
    return (b"R8 bind v1" + bytes((1, profile)) + struct.pack("!Q", scid) + sender.eid + receiver.eid + cid + _loc_packed(loc) +
            _binding(binding) + bytes((direction,)) + struct.pack("!QBIQ", epoch, slot, policy, expiry))
def _loc_packed(value):
    return value if type(value) is bytes else _loc(value).packed

@dataclass(frozen=True, repr=False)
class LocUpdate(_Redacted):
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

@dataclass(frozen=True, repr=False)
class Probe(_Redacted):
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

@dataclass(frozen=True, repr=False)
class Challenge(_Redacted):
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

@dataclass(frozen=True, repr=False)
class Result(_Redacted):
    candidate_id: bytes; epoch: int; slot: int; result: int
    def build(self):
        _cid(self.candidate_id); _u64(self.epoch, True)
        if self.slot not in (0, 1) or self.result not in (1, 2, 3): _fail()
        return _envelope(5, self.candidate_id + struct.pack("!QBB", self.epoch, self.slot, self.result))
    @classmethod
    def parse(cls, value):
        body = _parse(value, 5, 34); obj = cls(body[:16], *struct.unpack("!QBB", body[16:]))
        obj.build(); return obj


def parse_control(value):
    view = _view(value)
    if len(view) < 8 or view[:4].tobytes() != MAGIC:
        _fail()
    parser = {1: LocUpdate.parse, 2: Probe.parse, 3: Challenge.parse, 4: lambda x: Challenge.parse(x, 4), 5: Result.parse}.get(view[4])
    if parser is None: _fail()
    return parser(value)

_CAPABILITIES_LOCK = threading.Lock()
_PROFILE3_CAPABILITIES = {}
_PROFILE3_OWNERS = {}
_PROFILE3_SESSION_OWNERS = weakref.WeakKeyDictionary()

@dataclass(frozen=True, repr=False, eq=False)
class Profile3AdmissionOwner(_Redacted):
    def __repr__(self):
        return "Profile3AdmissionOwner(<redacted>)"

@dataclass(frozen=True, repr=False)
class Profile3Admission:
    candidate_id: bytes; scid: int; epoch: int; path_slot: int; local_loc: ipaddress.IPv6Address; peer_loc: ipaddress.IPv6Address; peer_binding: object; owner: object
    def __repr__(self):
        return "Profile3Admission(<redacted>)"

@dataclass(frozen=True, repr=False)
class _Profile3AdmissionIntent(_Redacted):
    candidate_id: bytes; epoch: int; path_slot: int; local_loc: bytes; peer_loc: bytes; peer_binding: bytes

@dataclass(frozen=True, repr=False)
class _Proposal(_Redacted):
    candidate_id: bytes; old_loc: bytes; new_loc: bytes; epoch: int; not_before: int; valid_for: int; slot: int; signature: bytes

@dataclass(frozen=True, repr=False)
class _Challenge(_Redacted):
    candidate_id: bytes; loc: bytes; epoch: int; slot: int; expiry: int; token: bytes; typ: int = 3

def _proposal(control):
    return _Proposal(control.candidate_id, _loc_bytes(control.old_loc), _loc_bytes(control.new_loc),
                     control.epoch, control.not_before, control.valid_for, control.slot, control.signature)

def _proposal_view(value):
    return LocUpdate(value.candidate_id, _loc_view(value.old_loc), _loc_view(value.new_loc),
                     value.epoch, value.not_before, value.valid_for, value.slot, value.signature)

def _challenge(control):
    return _Challenge(control.candidate_id, _loc_bytes(control.loc), control.epoch, control.slot,
                      control.expiry, control.token, control.typ)

def _challenge_view(value):
    return Challenge(value.candidate_id, _loc_view(value.loc), value.epoch, value.slot,
                     value.expiry, value.token, value.typ)
def _response_view(value):
    return Challenge(value.candidate_id, _loc_view(value.loc), value.epoch, value.slot,
                     value.expiry, value.token, 4)


def _drop_profile3_owner(owner_id, owner_ref, session_ref):
    with _CAPABILITIES_LOCK:
        record = _PROFILE3_OWNERS.get(owner_id)
        if record is not None and record[0] is owner_ref:
            _PROFILE3_OWNERS.pop(owner_id, None)
        session = session_ref()
        if session is not None and _PROFILE3_SESSION_OWNERS.get(session) is owner_ref:
            del _PROFILE3_SESSION_OWNERS[session]

def _drop_profile3_session(owner_id, session_ref):
    with _CAPABILITIES_LOCK:
        record = _PROFILE3_OWNERS.get(owner_id)
        if record is not None and record[1] is session_ref:
            _PROFILE3_OWNERS.pop(owner_id, None)


def issue_profile3_admission_owner(session, scid, policy):
    if (type(scid) is not int or not 0 < scid <= 0xffffffffffffffff
            or type(policy) is not int or not 0 <= policy <= 0xffffffff):
        _fail()
    owner = Profile3AdmissionOwner()
    with _CAPABILITIES_LOCK:
        existing = _PROFILE3_SESSION_OWNERS.get(session)
        if existing is not None and existing() is not None:
            _fail()
        if existing is not None:
            del _PROFILE3_SESSION_OWNERS[session]
        owner_id = id(owner)
        session_ref = weakref.ref(session,
            lambda ref: _drop_profile3_session(owner_id, ref))
        owner_ref = weakref.ref(owner,
            lambda ref: _drop_profile3_owner(owner_id, ref, session_ref))
        _PROFILE3_OWNERS[owner_id] = (owner_ref, session_ref, scid, policy, None)
        _PROFILE3_SESSION_OWNERS[session] = owner_ref
    return owner

def claim_profile3_admission_owner(owner, manager):
    if not isinstance(owner, Profile3AdmissionOwner):
        _fail()
    with _CAPABILITIES_LOCK:
        record = _PROFILE3_OWNERS.get(id(owner))
        core = _mobility_core(manager)
        if (record is None or record[0]() is not owner or record[1]() is None
                or record[2] != core.scid or record[3] != core.policy_id or record[4] is not None):
            _fail()
        _PROFILE3_OWNERS[id(owner)] = record[:4] + (weakref.ref(manager),)
    return owner
def profile3_admission_policy(admission, session):
    return profile3_admission_details(admission, session)[1]
def profile3_admission_details(admission, session):
    if not isinstance(admission, Profile3Admission):
        _fail()
    with _CAPABILITIES_LOCK:
        record = _PROFILE3_CAPABILITIES.get(id(admission))
        if record is None or record[0]() is not admission:
            _fail()
        semantics = record[3]
        owner = _PROFILE3_OWNERS.get(id(semantics[7]))
        if owner is None or owner[0]() is not semantics[7] or owner[1]() is not session:
            _fail()
        return (semantics[:4] + (_loc_bytes(semantics[4]), _loc_bytes(semantics[5])) + semantics[6:], owner[3])

def _drop_profile3_capability(capability_id, admission_ref):
    with _CAPABILITIES_LOCK:
        record = _PROFILE3_CAPABILITIES.get(capability_id)
        if record is not None and record[0] is admission_ref:
            _PROFILE3_CAPABILITIES.pop(capability_id)
            record[1].discard(capability_id)

def _revoke_profile3_capabilities(capability_ids):
    with _CAPABILITIES_LOCK:
        for capability_id in tuple(capability_ids):
            _PROFILE3_CAPABILITIES.pop(capability_id, None)
        capability_ids.clear()

def _revoke_profile3_owner(owner):
    with _CAPABILITIES_LOCK:
        record = _PROFILE3_OWNERS.pop(id(owner), None)
        if record is not None:
            session = record[1]()
            if session is not None and _PROFILE3_SESSION_OWNERS.get(session) is record[0]:
                del _PROFILE3_SESSION_OWNERS[session]

def _mint_profile3_admission(manager, intent):
    core = _mobility_core(manager)
    if core._pending_admissions.pop(id(intent), None) is not intent:
        _fail("E-REPLAY")
    admission = Profile3Admission(intent.candidate_id, core.scid, intent.epoch, intent.path_slot,
                                  _loc_view(intent.local_loc), _loc_view(intent.peer_loc), _binding_view(intent.peer_binding),
                                  core._profile3_owner)
    capability_id = id(admission)
    admission_ref = weakref.ref(admission, lambda ref: _drop_profile3_capability(capability_id, ref))
    semantics = (intent.candidate_id, core.scid, intent.epoch, intent.path_slot,
                 _loc_bytes(intent.local_loc), _loc_bytes(intent.peer_loc), intent.peer_binding, core._profile3_owner)
    with _CAPABILITIES_LOCK:
        _PROFILE3_CAPABILITIES[capability_id] = (admission_ref, core._profile3_capability_ids,
                                                  weakref.ref(manager), semantics)
        core._profile3_capability_ids.add(capability_id)
    return admission

def consume_profile3_admission(admission, session, policy):
    if not isinstance(admission, Profile3Admission) or type(policy) is not int:
        _fail()
    with _CAPABILITIES_LOCK:
        record = _PROFILE3_CAPABILITIES.get(id(admission))
        manager = None if record is None else record[2]()
    if manager is None:
        _fail()
    core = _mobility_core(manager)
    with core.lock:
        if core.closed:
            _fail()
        with _CAPABILITIES_LOCK:
            record = _PROFILE3_CAPABILITIES.get(id(admission))
            semantics = None if record is None else record[3]
            owner_record = _PROFILE3_OWNERS.get(id(semantics[7])) if semantics else None
            if (record is None or record[0]() is not admission or owner_record is None
                    or owner_record[0]() is not semantics[7] or owner_record[1]() is not session
                    or owner_record[2] != semantics[1] or owner_record[3] != policy
                    or owner_record[4]() is not manager):
                _fail()
            _PROFILE3_CAPABILITIES.pop(id(admission))
            record[1].discard(id(admission))
            _PROFILE3_OWNERS.pop(id(semantics[7]), None)
            if _PROFILE3_SESSION_OWNERS.get(session) is owner_record[0]:
                del _PROFILE3_SESSION_OWNERS[session]
        core.admissions = [candidate for candidate in core.admissions if candidate is not admission]
    return semantics
_PREVIEW_AUTHORITY = object()
_PREVIEW_OWNERS = weakref.WeakKeyDictionary()
_MOBILITY_CORES = weakref.WeakKeyDictionary()
class _MobilityCore:
    pass

def _mobility_core(manager):
    core = _MOBILITY_CORES.get(manager)
    if core is None:
        _fail("E-REPLAY")
    return core

class Preview(_Redacted):
    __slots__ = ("__weakref__",)
    def __init__(self, authority=None):
        if authority is not _PREVIEW_AUTHORITY:
            _fail("E-REPLAY")
    def __repr__(self):
        return "<MobilityPreview>"

class MobilityManager:
    """All state changes are serialized by one lock and originate in ``commit``."""
    def __init__(self, identity, peer_pin, local_role, profile, scid, policy_id, local_loc, peer_loc, peer_binding, candidate_secret, clock, session_commit=lambda token: None, profile3_admission_owner=None):
        c = _MobilityCore(); _MOBILITY_CORES[self] = c
        if (not isinstance(identity, Identity) or not isinstance(peer_pin, PeerPin)
                or type(local_role) is not int or type(peer_pin.role) is not int
                or local_role not in (1, 2) or peer_pin.role not in (1, 2)
                or local_role == peer_pin.role):
            _fail()
        if type(profile) is not int or not 0 <= profile <= 3 or type(scid) is not int or not 0 < scid <= 0xffffffffffffffff or type(policy_id) is not int or not 0 <= policy_id <= 0xffffffff: _fail()
        if profile != 3 and profile3_admission_owner is not None:
            _fail()
        _exact(candidate_secret, 32); peer_binding = _binding(peer_binding)
        c.identity = Identity(identity.private, bytes(identity.public), bytes(identity.eid))
        c.peer_pin = PeerPin(peer_pin.role, bytes(peer_pin.eid), bytes(peer_pin.public_key))
        c.local_role, c.profile, c.scid, c.policy_id = local_role, profile, scid, policy_id
        c.local_loc, c.peer_loc, c.binding, c.secret, c.clock = _loc_bytes(local_loc), _loc_bytes(peer_loc), peer_binding, bytes(candidate_secret), clock
        c.session_commit = session_commit; c.authorized_session = None; c.lock = threading.RLock(); c.generation = 0; c.local_epoch = 0; c.peer_epoch = 0; c.closed = False
        c._preview_identity, c._previews = object(), {}
        if profile == 3:
            from r8redundant import RedundantSession
            with _CAPABILITIES_LOCK:
                owner_record = _PROFILE3_OWNERS.get(id(profile3_admission_owner))
                session = None if owner_record is None else owner_record[1]()
            if (not isinstance(session, RedundantSession)
                    or getattr(session_commit, "__self__", None) is not session
                    or getattr(session_commit, "__func__", None) is not RedundantSession.commit_receive):
                _fail("E-REPLAY")
            c.authorized_session = session
        c.outbound = {}; c.outbound_expiry = {}; c.proposals = {}; c.candidates = {}; c.results = {}; c.cohort = None; c.admissions = []; c._profile3_capability_ids = set(); c._pending_admissions = {}
        c._profile3_owner = claim_profile3_admission_owner(profile3_admission_owner, self) if profile == 3 else None
        c._profile3_admitted = False
        c.tokens = 2; c.refill = self._now(); c.grace = None; c.emitted = []
        c._profile3_capability_finalizer = weakref.finalize(self, _revoke_profile3_capabilities,
                                                               c._profile3_capability_ids)
        c._profile3_owner_finalizer = weakref.finalize(self, _revoke_profile3_owner, c._profile3_owner) if profile == 3 else None
    def _now(self):
        c = _mobility_core(self)
        value = c.clock()
        if type(value) is not int or value < 0: _fail()
        return value
    def _advance_generation(self):
        c = _mobility_core(self)
        c.generation += 1
        for preview in tuple(c._previews):
            _PREVIEW_OWNERS.pop(preview, None)
        c._previews.clear()
    def _slot(self, slot):
        _slot(_mobility_core(self).profile, slot)
    def _direction(self):
        return _mobility_core(self).peer_pin.role
    def _result_entry(self, cid, proposal, candidate, code, now):
        c = _mobility_core(self)
        old = c.results.get(cid)
        if old is not None:
            return old, None
        raw = Result(cid, proposal.epoch, proposal.slot, code).build()
        response = candidate["challenge"] if candidate is not None else None
        binding = candidate["binding"] if candidate is not None else None
        return (raw, now + 10000, proposal.epoch, proposal.slot, code, response, binding), raw
    def _settlement_plan(self, now, candidates, cohort, proposals=None, results=None, emitted=None, admissions=None, peer_loc=None, binding=None, peer_epoch=None, grace=None):
        c = _mobility_core(self)
        proposals = c.proposals if proposals is None else proposals
        results = c.results if results is None else results
        emitted = c.emitted if emitted is None else emitted
        peer_loc = c.peer_loc if peer_loc is None else peer_loc
        binding = c.binding if binding is None else binding
        peer_epoch = c.peer_epoch if peer_epoch is None else peer_epoch
        grace = c.grace if grace is None else grace
        admissions = c.admissions if admissions is None else admissions
        if cohort is None:
            return candidates, proposals, results, emitted, admissions, None, peer_loc, binding, peer_epoch, grace
        epoch, members = cohort
        results = dict(results)
        required = sum(cid not in results for cid in members)
        if len(results) + required > 2 or len(emitted) + required > 2:
            _fail("E-CAPACITY")
        for cid in members:
            candidate = candidates.get(cid)
            if candidate is None and cid in proposals:
                return candidates, proposals, results, emitted, admissions, cohort, peer_loc, binding, peer_epoch, grace
            if candidate is not None and candidate["state"] not in ("PROVEN", "FAILED"):
                return candidates, proposals, results, emitted, admissions, cohort, peer_loc, binding, peer_epoch, grace
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
            return candidates, proposals, results, emitted, admissions, None, peer_loc, binding, peer_epoch, grace
        original = next(candidate for cid, _, candidate, _ in additions if cid == proven[0])
        if c.profile == 3:
            if admissions:
                _fail("E-CAPACITY")
            admissions = [_Profile3AdmissionIntent(winner, epoch, original["proposal"].slot, c.local_loc,
                                                    original["proposal"].new_loc, original["binding"])]
            return candidates, proposals, results, emitted, admissions, None, peer_loc, binding, peer_epoch, grace
        return candidates, proposals, results, emitted, admissions, None, original["proposal"].new_loc, original["binding"], epoch, (binding, now + 10000)
    def _refilled(self, now):
        c = _mobility_core(self)
        elapsed = (now - c.refill) // 1000
        return min(2, c.tokens + max(0, elapsed)), (c.refill + max(0, elapsed) * 1000)
    def _sign_update(self, cid, new, epoch, slot):
        c = _mobility_core(self)
        new = _loc_bytes(new)
        raw = update_input(c.profile, c.scid, c.identity, c.peer_pin, c.local_loc, new, epoch, 0, 5000, cid, slot)
        return LocUpdate(cid, _loc_view(c.local_loc), _loc_view(new), epoch, 0, 5000, slot, c.identity.private.sign(raw))
    def propose_local(self, new_loc, epoch, candidate_id, slot=0, carrier=None):
        c = _mobility_core(self)
        with c.lock:
            if c.closed or (c.profile == 3 and c._profile3_admitted) or epoch <= c.local_epoch: _fail()
            _cid(candidate_id); _u64(epoch, True); self._slot(slot); new = _loc_bytes(new_loc)
            found = c.outbound.get(candidate_id)
            if found is not None:
                if found[1] == (new, epoch, slot): return found[0]
                _fail()
            if len(c.outbound) >= 2: _fail("E-CAPACITY")
            update = self._sign_update(bytes(candidate_id), new, epoch, slot); raw = update.build()
            carrier = _binding(carrier) if carrier is not None else None
            c.outbound[candidate_id] = (raw, (new, epoch, slot), carrier, None); c.outbound_expiry[candidate_id] = self._now() + 5000
            self._advance_generation()
            return raw
    propose = propose_local
    def make_probe(self, candidate_id, carrier, nonce):
        c = _mobility_core(self)
        with c.lock:
            if c.closed or (c.profile == 3 and c._profile3_admitted): _fail()
            _cid(candidate_id); carrier = _binding(carrier); _exact(nonce, 16)
            outbound = c.outbound.get(candidate_id)
            if outbound is None: _fail()
            new_loc, epoch, slot = outbound[1]; self._slot(slot)
            if epoch <= c.local_epoch: _fail()
            old_carrier = outbound[2]
            if old_carrier is not None and old_carrier != carrier: _fail()
            c.outbound[candidate_id] = (outbound[0], outbound[1], carrier, outbound[3])
            if old_carrier != carrier:
                self._advance_generation()
            return Probe(candidate_id, _loc_view(new_loc), epoch, slot, nonce).build()
    def _validate_profile3_replay(self, replay_token, plaintext, observed_binding):
        c = _mobility_core(self)
        if c.profile != 3:
            return
        from r8redundant import profile3_receive_matches
        if not profile3_receive_matches(c.authorized_session, self, replay_token, plaintext, observed_binding):
            _fail("E-REPLAY")
    def preview(self, control_bytes, observed_binding, replay_token):
        c = _mobility_core(self)
        with c.lock:
            if c.closed or (c.profile == 3 and c._profile3_admitted): _fail()
            observed_binding = _binding(observed_binding); control = parse_control(control_bytes); now = self._now()
            self._validate_profile3_replay(replay_token, bytes(control_bytes), observed_binding)
            def register(action, control, binding, replay_token, response, prepared=(), deadline=None):
                preview = Preview(_PREVIEW_AUTHORITY)
                c._previews[preview] = (c.generation, min(now + 5000, deadline if deadline is not None else now + 5000),
                                        action, control.build(), binding, replay_token, response, prepared)
                _PREVIEW_OWNERS[preview] = self
                return preview
            if isinstance(control, LocUpdate):
                self._slot(control.slot)
                raw = update_input(c.profile, c.scid, c.peer_pin, c.identity, control.old_loc, control.new_loc, control.epoch, control.not_before, control.valid_for, control.candidate_id, control.slot)
                try: Ed25519PublicKey.from_public_bytes(c.peer_pin.public_key).verify(control.signature, raw)
                except (InvalidSignature, ValueError): _fail()
                if control.old_loc.packed != c.peer_loc or control.epoch <= c.peer_epoch: _fail()
                existing = c.proposals.get(control.candidate_id)
                if existing is not None:
                    if existing[0] == bytes(control_bytes): return register("noop", control, observed_binding, replay_token, None, deadline=existing[2])
                    _fail()
                if c.cohort is not None and control.epoch <= c.cohort[0]: _fail()
                if control.candidate_id in c.candidates or control.candidate_id in c.outbound or control.candidate_id in c.results:
                    _fail()
                if c.emitted: _fail("E-CAPACITY")
                tokens, refill = self._refilled(now)
                if tokens < 1: _fail()
                if len(c.proposals) >= 2 or len(c.results) + len(c.proposals) >= 2:
                    _fail("E-CAPACITY")
                entry = (bytes(control_bytes), _proposal(control), now + 5000)
                return register("proposal", control, observed_binding, replay_token, None,
                                (control.candidate_id, entry, tokens - 1, refill), entry[2])
            if isinstance(control, Probe):
                self._slot(control.slot); proposal = c.proposals.get(control.candidate_id)
                if proposal is None: _fail()
                if now >= proposal[2]: _fail("E-TIMEOUT")
                if proposal[1].epoch <= c.peer_epoch or (proposal[1].new_loc, proposal[1].epoch, proposal[1].slot) != (control.loc.packed, control.epoch, control.slot): _fail()
                existing = c.candidates.get(control.candidate_id)
                if existing is not None:
                    if existing["challenge"] is not None and existing["binding"] == observed_binding: return register("noop", control, observed_binding, replay_token, _challenge_view(existing["challenge"]).build(), deadline=existing["expiry"])
                    _fail()
                if len(c.candidates) >= 2 or c.grace is not None: _fail("E-CAPACITY")
                expiry = now + 3000
                token = hmac.new(c.secret, token_input(c.profile, c.scid, c.peer_pin, c.identity, control.candidate_id, control.loc.packed, observed_binding, self._direction(), control.epoch, control.slot, c.policy_id, expiry), hashlib.sha256).digest()
                ch = _Challenge(control.candidate_id, control.loc.packed, control.epoch, control.slot, expiry, token)
                candidate = {"binding": observed_binding, "expiry": ch.expiry, "challenge": ch, "state": "CHALLENGED", "proposal": proposal[1]}
                return register("challenge", control, observed_binding, replay_token, _challenge_view(ch).build(),
                                (control.candidate_id, candidate), ch.expiry)
            if isinstance(control, Challenge) and control.typ == 3:
                self._slot(control.slot); outbound = c.outbound.get(control.candidate_id)
                expiry = c.outbound_expiry.get(control.candidate_id, 0)
                if (outbound is None or expiry <= now or control.epoch <= c.local_epoch
                        or outbound[1] != (control.loc.packed, control.epoch, control.slot)
                        or outbound[2] != observed_binding): _fail("E-TIMEOUT" if expiry <= now else "E-CANDIDATE")
                response = Challenge(control.candidate_id, control.loc, control.epoch, control.slot, control.expiry, control.token, 4).build()
                return register("response", control, observed_binding, replay_token, response,
                                deadline=expiry)
            if isinstance(control, Challenge):
                self._slot(control.slot); candidate = c.candidates.get(control.candidate_id)
                cached = c.results.get(control.candidate_id)
                if candidate is None:
                    if cached is not None and len(cached) == 7 and cached[5] is not None and cached[6] == observed_binding and control == _response_view(cached[5]):
                        return register("noop", control, observed_binding, replay_token, cached[0], deadline=cached[1])
                    _fail()
                if candidate["challenge"] is None: _fail()
                expected = candidate["challenge"]
                if now >= expected.expiry: _fail("E-TIMEOUT")
                if candidate["binding"] != observed_binding or control != _response_view(expected): _fail()
                if cached is not None: return register("noop", control, observed_binding, replay_token, cached[0], deadline=min(expected.expiry, cached[1]))
                if candidate["state"] == "PROVEN": return register("noop", control, observed_binding, replay_token, None, deadline=expected.expiry)
                if candidate["state"] != "CHALLENGED": _fail()
                candidates = {cid: dict(item) for cid, item in c.candidates.items()}
                candidates[control.candidate_id]["state"] = "PROVEN"
                cohort = c.cohort
                greatest = max(item[1].epoch for item in c.proposals.values())
                if cohort is None and candidates[control.candidate_id]["proposal"].epoch == greatest:
                    if c.emitted: _fail("E-CAPACITY")
                    cohort = (greatest, {cid: item[1] for cid, item in c.proposals.items() if item[1].epoch == greatest})
                return register("proven", control, observed_binding, replay_token, None,
                                self._settlement_plan(now, candidates, cohort), expected.expiry)
            if isinstance(control, Result):
                self._slot(control.slot); outbound = c.outbound.get(control.candidate_id)
                cached = c.results.get(control.candidate_id)
                if cached is not None and len(cached) == 6 and cached[0] == bytes(control_bytes) and cached[5] == observed_binding:
                    return register("noop", control, observed_binding, replay_token, None, deadline=cached[1])
                if outbound is None or outbound[1] != (outbound[1][0], control.epoch, control.slot) or outbound[2] != observed_binding:
                    _fail("E-CANDIDATE")
                if now >= c.outbound_expiry.get(control.candidate_id, 0):
                    _fail("E-TIMEOUT")
                if outbound[3] is not None:
                    if outbound[3] == bytes(control_bytes): return register("noop", control, observed_binding, replay_token, None, deadline=c.outbound_expiry[control.candidate_id])
                    _fail()
                if control.epoch <= c.local_epoch: _fail()
                reserved = sum(cid not in c.results for cid in c.cohort[1]) if c.cohort is not None else 0
                if control.candidate_id not in c.results and len(c.results) + reserved >= 2: _fail("E-CAPACITY")
                if control.result == 1 and c.profile == 3 and c.admissions: _fail("E-CAPACITY")
                result = control.build()
                result_entry = (result, now + 10000, control.epoch, control.slot, control.result, observed_binding)
                outbound_entry = (outbound[0], outbound[1], outbound[2], result)
                prepared = (control.candidate_id, outbound_entry, result_entry,
                            (outbound[1][0], outbound[2], control.epoch, (c.binding, now + 10000))
                            if control.result == 1 and c.profile != 3 else None,
                            _Profile3AdmissionIntent(control.candidate_id, control.epoch, control.slot, outbound[1][0],
                                                     c.peer_loc, observed_binding)
                            if control.result == 1 and c.profile == 3 else None)
                return register("local-result", control, observed_binding, replay_token, None, prepared,
                                c.outbound_expiry[control.candidate_id])
            _fail()
    def _settle(self, now):
        c = _mobility_core(self)
        candidates = {cid: dict(candidate) for cid, candidate in c.candidates.items()}
        plan = self._settlement_plan(now, candidates, c.cohort)
        (c.candidates, c.proposals, c.results, c.emitted, c.admissions, c.cohort,
         c.peer_loc, c.binding, c.peer_epoch, c.grace) = plan
    def commit(self, preview):
        c = _mobility_core(self)
        with c.lock:
            if not isinstance(preview, Preview) or _PREVIEW_OWNERS.get(preview) is not self:
                _fail("E-REPLAY")
            record = c._previews.pop(preview, None)
            _PREVIEW_OWNERS.pop(preview, None)
            if record is None:
                _fail("E-REPLAY")
            generation, deadline, action, control, binding, replay_token, response, prepared = record
            if generation != c.generation or self._now() >= deadline:
                _fail("E-REPLAY")
            prepared_lengths = {"noop": 0, "response": 0, "proposal": 4, "challenge": 2, "proven": 10, "local-result": 5}
            if (action not in prepared_lengths or (action not in ("noop", "response") and
                    (type(prepared) is not tuple or len(prepared) != prepared_lengths[action]))):
                _fail("E-REPLAY")
            self._validate_profile3_replay(replay_token, control, binding)
            (c.authorized_session.commit_receive if c.profile == 3 else c.session_commit)(replay_token)
            if action in ("noop", "response"):
                return response
            if action == "proposal":
                cid, entry, tokens, refill = prepared
                c.proposals[cid] = entry
                c.tokens, c.refill = tokens, refill
            elif action == "challenge":
                cid, candidate = prepared
                c.candidates[cid] = candidate
            elif action == "proven":
                (c.candidates, c.proposals, c.results, c.emitted, admissions, c.cohort,
                 c.peer_loc, c.binding, c.peer_epoch, c.grace) = prepared
                c.admissions = []
                for admission in admissions:
                    if isinstance(admission, _Profile3AdmissionIntent):
                        c._pending_admissions[id(admission)] = admission
                        c.admissions.append(_mint_profile3_admission(self, admission))
                    else:
                        c.admissions.append(admission)
                if c.profile == 3 and c.admissions:
                    c._profile3_admitted = True
                    c._profile3_owner = None
                    c._profile3_owner_finalizer.detach()
            elif action == "local-result":
                cid, outbound_entry, result_entry, promotion, admission = prepared
                c.outbound[cid] = outbound_entry
                c.results[cid] = result_entry
                if promotion is not None:
                    c.local_loc, c.binding, c.local_epoch, c.grace = promotion
                if admission is not None:
                    c._pending_admissions[id(admission)] = admission
                    c.admissions.append(_mint_profile3_admission(self, admission))
                    c._profile3_admitted = True
                    c._profile3_owner = None
                    c._profile3_owner_finalizer.detach()
            self._advance_generation()
            return response
    def expire(self):
        c = _mobility_core(self)
        with c.lock:
            if c.closed:
                return
            now = self._now()
            proposals = {cid: item for cid, item in c.proposals.items() if now < item[2]}
            results = {cid: item for cid, item in c.results.items() if now < item[1]}
            expired_outbound = {cid for cid, expiry in c.outbound_expiry.items() if now >= expiry}
            outbound = {cid: item for cid, item in c.outbound.items() if cid not in expired_outbound}
            outbound_expiry = {cid: expiry for cid, expiry in c.outbound_expiry.items() if cid not in expired_outbound}
            candidates = {cid: dict(candidate) for cid, candidate in c.candidates.items()}
            expired = set()
            for cid, candidate in candidates.items():
                if candidate["state"] == "CHALLENGED" and now >= candidate["expiry"]:
                    candidate["state"] = "FAILED"
                    expired.add(cid)
            emitted = list(c.emitted)
            if c.cohort is None:
                for cid in expired:
                    candidate = candidates.get(cid)
                    proposal = c.proposals.get(cid)
                    if (proposal is not None and cid not in results
                            and len(results) < 2 and len(emitted) < 2):
                        entry, raw = self._result_entry(cid, proposal[1], candidate, 3, now)
                        results[cid] = entry
                        emitted.append(raw)
                    if candidate is not None:
                        candidate["challenge"] = None
                    candidates.pop(cid, None)
                    proposals.pop(cid, None)
            cohort = c.cohort
            if cohort is None:
                proven = [cid for cid, candidate in candidates.items()
                          if cid in proposals and candidate["state"] == "PROVEN"]
                if proven:
                    epoch = max(proposals[cid][1].epoch for cid in proven)
                    cohort = (epoch, {cid: item[1] for cid, item in proposals.items()
                                      if item[1].epoch == epoch})
            grace = None if c.grace is not None and now >= c.grace[1] else c.grace
            plan = self._settlement_plan(now, candidates, cohort, proposals, results, emitted,
                                         c.admissions, c.peer_loc, c.binding, c.peer_epoch, grace)
            (candidates, proposals, results, emitted, admissions, cohort,
             peer_loc, binding, peer_epoch, grace) = plan
            c.proposals, c.results = proposals, results
            c.outbound, c.outbound_expiry = outbound, outbound_expiry
            c.candidates, c.emitted, c.admissions, c.cohort = candidates, emitted, admissions, cohort
            c.peer_loc, c.binding, c.peer_epoch, c.grace = peer_loc, binding, peer_epoch, grace
            self._advance_generation()
    def binding_allowed_inbound(self, binding):
        c = _mobility_core(self)
        with c.lock:
            binding = _binding(binding)
            now = self._now()
            if binding == c.binding:
                return True
            if c.grace is None or binding != c.grace[0]:
                return False
            if now < c.grace[1]:
                return True
            c.grace = None
            self._advance_generation()
            return False
    def bind_outbound_carrier(self, candidate_id, carrier):
        c = _mobility_core(self)
        """Record the caller carrier that is authorized to deliver its challenge/result."""
        with c.lock:
            _cid(candidate_id); carrier = _binding(carrier)
            if candidate_id not in c.outbound: _fail()
            raw, data, old, response = c.outbound[candidate_id]
            if old is not None and old != carrier: _fail()
            c.outbound[candidate_id] = (raw, data, carrier, response)
            if old != carrier:
                self._advance_generation()
    def take_results(self):
        c = _mobility_core(self)
        with c.lock:
            result, c.emitted = tuple(c.emitted), []
            if result:
                self._advance_generation()
            return result
    def take_profile3_admissions(self):
        c = _mobility_core(self)
        with c.lock:
            return tuple(c.admissions)
    def close(self):
        c = _mobility_core(self)
        with c.lock:
            c.closed = True
            c.secret = None
            c.outbound.clear(); c.outbound_expiry.clear(); c.proposals.clear(); c.candidates.clear(); c.results.clear(); c.cohort = None; c.grace = None; c.emitted.clear(); _revoke_profile3_capabilities(c._profile3_capability_ids)
            for admission in c.admissions:
                _revoke_profile3_owner(admission.owner)
            c.admissions.clear()
            if c._profile3_owner is not None:
                _revoke_profile3_owner(c._profile3_owner); c._profile3_owner = None
            if c._profile3_owner_finalizer is not None:
                c._profile3_owner_finalizer.detach()
            self._advance_generation()
    def _preview(self, *args, **kwargs):
        _fail("E-REPLAY")
    @property
    def session_commit(self):
        return None
    @property
    def lock(self):
        return threading.RLock()
    @property
    def peer_pin(self):
        peer = _mobility_core(self).peer_pin
        return PeerPin(peer.role, bytes(peer.eid), bytes(peer.public_key))
    @property
    def local_role(self):
        return _mobility_core(self).local_role
    @property
    def profile(self):
        return _mobility_core(self).profile
    @property
    def scid(self):
        return _mobility_core(self).scid
    @property
    def policy_id(self):
        return _mobility_core(self).policy_id
    @property
    def local_loc(self):
        return _loc_view(_mobility_core(self).local_loc)
    @property
    def peer_loc(self):
        return _loc_view(_mobility_core(self).peer_loc)
    @property
    def binding(self):
        return _binding_view(_mobility_core(self).binding)
    @property
    def generation(self):
        return _mobility_core(self).generation
    @property
    def local_epoch(self):
        return _mobility_core(self).local_epoch
    @property
    def peer_epoch(self):
        return _mobility_core(self).peer_epoch
    @property
    def closed(self):
        return _mobility_core(self).closed
    @property
    def tokens(self):
        return _mobility_core(self).tokens
    @property
    def refill(self):
        return _mobility_core(self).refill
    @property
    def grace(self):
        grace = _mobility_core(self).grace
        return None if grace is None else (_binding_view(grace[0]), grace[1])
    @property
    def outbound(self):
        return {cid: (raw, (_loc_view(data[0]), data[1], data[2]),
                      None if binding is None else _binding_view(binding), response)
                for cid, (raw, data, binding, response) in _mobility_core(self).outbound.items()}
    @property
    def outbound_expiry(self):
        return copy.deepcopy(_mobility_core(self).outbound_expiry)
    @property
    def proposals(self):
        return {cid: (raw, _proposal_view(proposal), expiry)
                for cid, (raw, proposal, expiry) in _mobility_core(self).proposals.items()}
    @property
    def candidates(self):
        return {cid: {**candidate, "binding": _binding_view(candidate["binding"]),
                      "challenge": None if candidate["challenge"] is None else _challenge_view(candidate["challenge"]),
                      "proposal": _proposal_view(candidate["proposal"])}
                for cid, candidate in _mobility_core(self).candidates.items()}
    @property
    def results(self):
        return {cid: entry[:5] + (None if entry[5] is None else _challenge_view(entry[5]),) + entry[6:]
                if len(entry) == 7 else entry
                for cid, entry in _mobility_core(self).results.items()}
    @property
    def cohort(self):
        cohort = _mobility_core(self).cohort
        return None if cohort is None else (cohort[0], {cid: _proposal_view(proposal) for cid, proposal in cohort[1].items()})
    @property
    def emitted(self):
        return tuple(_mobility_core(self).emitted)
    @property
    def admissions(self):
        return tuple(_mobility_core(self).admissions)
    @property
    def secret(self):
        return None
    restart = close
