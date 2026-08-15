"""Carrier-neutral Profile-3 redundant delivery state machine."""
from collections import deque
from dataclasses import dataclass
import hashlib
import threading
import weakref

import r8mobility
import r8session
from r8ref import Header, NH_SES, WireError


CATEGORIES = frozenset(("E-BUDGET", "E-CAPACITY", "E-COUNTER", "E-REPLAY",
                        "E-CANDIDATE", "E-PATH", "E-TIMEOUT"))
ABSENT, CANDIDATE, VALIDATED, ACTIVE, DEGRADED, REMOVED, RELEASED = range(7)
_QUEUE_PACKETS, _QUEUE_BYTES, _DEDUP_MAX, _DEDUP_LIFETIME, _GAP = 256, 262144, 4096, 30000, 65536
_MAX = 0xffffffffffffffff


class RedundantError(ValueError):
    __slots__ = ("category",)
    def __init__(self, category):
        if category not in CATEGORIES:
            raise ValueError("invalid redundant error")
        self.category = category
        super().__init__(category)


def _fail(category):
    raise RedundantError(category)


def _budget(value):
    if type(value) is not int or not 48 <= value <= 1280:
        _fail("E-BUDGET")
    return value


def _binding(value):
    if isinstance(value, bytes):
        value = bytes(value)
        _binding_view(value)
        return value
    try:
        return bytes(r8session.validate_binding(value))
    except Exception:
        _fail("E-CANDIDATE")
def _binding_view(value):
    try:
        if value[:2] == b"\x01\x04" and len(value) == 25:
            return r8session.UdpBinding(value[2:6], int.from_bytes(value[6:8], "big"), value[8], value[9:])
        if value[:2] == b"\x01\x06" and len(value) == 37:
            return r8session.UdpBinding(value[2:18], int.from_bytes(value[18:20], "big"), value[20], value[21:])
        if value[:1] == b"\x02" and len(value) == 11:
            return r8session.NativeBinding(int.from_bytes(value[1:5], "big"), value[5:])
    except (TypeError, ValueError):
        pass
    _fail("E-CANDIDATE")
def _loc(value):
    try:
        packed = value if isinstance(value, bytes) else value.packed
    except AttributeError:
        _fail("E-CANDIDATE")
    if type(packed) is not bytes or len(packed) != 16:
        _fail("E-CANDIDATE")
    return bytes(packed)

def _loc_view(value):
    return r8mobility.ipaddress.IPv6Address(value)



@dataclass(frozen=True, repr=False)
class Event:
    kind: str
    slot: int | None = None
    def __repr__(self):
        return "<RedundantEvent>"


@dataclass(frozen=True, repr=False)
class Outbound:
    packets: tuple[bytes | None, bytes | None]
    def __repr__(self):
        return "<RedundantOutbound>"


@dataclass(frozen=True, repr=False)
class Inbound:
    plaintext: bytes
    delivered: bool
    def __repr__(self):
        return "<RedundantInbound>"
_HANDLE_AUTHORITY = object()
_RECEIVE_OWNERS = weakref.WeakKeyDictionary()
_MOBILITY_OWNERS = weakref.WeakKeyDictionary()
_REDUNDANT_CORES = weakref.WeakKeyDictionary()
class _RedundantCore:
    pass

def _redundant_core(session):
    core = _REDUNDANT_CORES.get(session)
    if core is None:
        _fail("E-REPLAY")
    return core

def profile3_receive_matches(session, manager, preview, plaintext):
    core = _redundant_core(session)
    record = core._receive_previews.get(preview)
    return (record is not None and (plaintext is None or record[4] == plaintext) and record[0] == core._receive_generation
            and core._mobility_manager is manager)

class ReceivePreview:
    __slots__ = ("__weakref__",)
    def __init__(self, authority=None):
        if authority is not _HANDLE_AUTHORITY:
            _fail("E-REPLAY")
    @property
    def plaintext(self):
        owner = _RECEIVE_OWNERS.get(self)
        if owner is None:
            _fail("E-REPLAY")
        core = _redundant_core(owner)
        with core._lock:
            record = core._receive_previews.get(self)
            if record is None:
                _fail("E-REPLAY")
            return bytes(record[4])
    def __repr__(self):
        return "<RedundantReceivePreview>"

class MobilityReceivePreview:
    __slots__ = ("__weakref__",)
    def __init__(self, authority=None):
        if authority is not _HANDLE_AUTHORITY:
            _fail("E-REPLAY")
    def __repr__(self):
        return "<RedundantMobilityPreview>"






@dataclass(repr=False)
class _Queued:
    delivery_id: int
    packet: bytes
    def __repr__(self):
        return "<QueuedPacket>"


class RedundantSession:
    """Owns exactly the two Profile-3 directional sessions transferred by bootstrap."""
    def __init__(self, bootstrap, slot0_binding, slot0_budget, delivery_seed, clock):
        c = _RedundantCore(); _REDUNDANT_CORES[self] = c
        if not isinstance(bootstrap, r8session.Profile3Bootstrap):
            _fail("E-CANDIDATE")
        if (bootstrap.outbound is None or bootstrap.inbound is None or bootstrap.scid == 0
                or bootstrap._prk is None or bootstrap._thash is None):
            _fail("E-CANDIDATE")
        if type(delivery_seed) is not int or not 0 < delivery_seed < _MAX or not callable(clock):
            _fail("E-COUNTER")
        slot0_binding = _binding(slot0_binding); _budget(slot0_budget)
        try:
            now = clock()
        except Exception:
            _fail("E-TIMEOUT")
        if type(now) is not int or now < 0:
            _fail("E-TIMEOUT")
        try:
            bootstrap = bootstrap._transfer()
        except Exception:
            _fail("E-CANDIDATE")
        c._lock = threading.RLock()
        c._bootstrap, c._scid, c._clock = bootstrap, bootstrap.scid, clock
        c._local_locs, c._peer_locs = [_loc(bootstrap.local_loc), None], [_loc(bootstrap.peer_loc), None]
        c._out = [bootstrap.outbound, None]
        c._in = [bootstrap.inbound, None]
        c._bindings, c.budgets = [slot0_binding, None], [slot0_budget, None]
        c.states = [ACTIVE, ABSENT]
        c._queues = [deque(), deque()]
        c.queue_bytes = [0, 0]
        c._next_delivery_id, c._high_water = delivery_seed, None
        c._dedup, c.events, c._queue_overflow_packets = {}, [Event("degraded", 1)], 0
        c._delivery, c._profile3_owner_issued, c._profile3_owner = {}, False, None
        c._receive_generation, c._receive_previews, c._mobility_previews, c._mobility_manager, c.closed = 0, {}, {}, None, False

    def __repr__(self):
        return "<RedundantSession>"

    @property
    def closed(self):
        return _redundant_core(self).closed
    @property
    def dedup_size(self):
        c = _redundant_core(self)
        return len(c._delivery)
    def queue_metrics(self):
        c = _redundant_core(self)
        with c._lock:
            return {"queued_packets": sum(len(queue) for queue in c._queues),
                    "queued_bytes": sum(c.queue_bytes),
                    "overflow_packets": c._queue_overflow_packets}

    def _now(self):
        c = _redundant_core(self)
        try:
            now = c._clock()
        except Exception:
            _fail("E-TIMEOUT")
        if type(now) is not int or now < 0:
            _fail("E-TIMEOUT")
        return now

    def _emit(self, kind, slot=None):
        c = _redundant_core(self)
        if len(c.events) >= 64:
            c.events.pop(0)
        c.events.append(Event(kind, slot))
    def _expire(self, now):
        c = _redundant_core(self)
        for ident, (_, expiry) in tuple(c._dedup.items()):
            if expiry <= now:
                del c._dedup[ident]
    def issue_profile3_admission_owner(self, policy):
        c = _redundant_core(self)
        with c._lock:
            if c.closed or c._profile3_owner_issued or type(policy) is not int or not 0 <= policy <= 0xffffffff:
                _fail("E-CANDIDATE")
            owner = r8mobility.issue_profile3_admission_owner(self, c._scid, policy)
            c._profile3_owner_issued = True
            c._profile3_owner = owner
            return owner

    def _header(self, slot, inbound=False):
        c = _redundant_core(self)
        local_loc, peer_loc = c._local_locs[slot], c._peer_locs[slot]
        src, dst = (peer_loc, local_loc) if inbound else (local_loc, peer_loc)
        return Header(NH_SES, _loc_view(src), _loc_view(dst), profile=3, flags=1 if slot == 0 else 3,
                      pslot=slot, scid=c._scid)

    def _active(self):
        c = _redundant_core(self)
        return tuple(slot for slot in (0, 1) if c.states[slot] == ACTIVE)

    def _release(self):
        c = _redundant_core(self)
        if c.closed:
            return
        for preview, record in tuple(c._receive_previews.items()):
            slot, session_preview = record[1], record[2]
            session = c._in[slot] if slot in (0, 1) else None
            if session is not None:
                try:
                    r8session.abort_profile3_data(session, session_preview)
                except r8session.SessionError:
                    pass
            _RECEIVE_OWNERS.pop(preview, None)
        c._receive_previews.clear()
        for preview in tuple(c._mobility_previews):
            _MOBILITY_OWNERS.pop(preview, None)
        c._mobility_previews.clear()
        c._receive_generation += 1
        for slot in (0, 1):
            outbound, inbound = c._out[slot], c._in[slot]
            if c._bootstrap is not None:
                c._bootstrap.release_sessions(outbound, inbound)
            else:
                if outbound is not None:
                    outbound.release()
                if inbound is not None and inbound is not outbound:
                    inbound.release()
            c._out[slot] = c._in[slot] = None
            c._bindings[slot] = c.budgets[slot] = None
            c._queues[slot].clear(); c.queue_bytes[slot] = 0
            c._local_locs[slot] = c._peer_locs[slot] = None
            c.states[slot] = RELEASED
        c._next_delivery_id, c._high_water = 0, None
        c._dedup.clear()
        c._delivery.clear(); c._profile3_owner_issued = True
        if c._profile3_owner is not None:
            r8mobility._revoke_profile3_owner(c._profile3_owner)
            c._profile3_owner = None
        if c._bootstrap is not None:
            c._bootstrap.close(); c._bootstrap = None
        c.closed = True
        self._emit("released")
    def close(self):
        c = _redundant_core(self)
        with c._lock:
            self._release()

    @property
    def states(self): return tuple(_redundant_core(self).states)
    @property
    def budgets(self): return tuple(_redundant_core(self).budgets)
    @property
    def events(self): return tuple(_redundant_core(self).events)
    @property
    def queue_bytes(self): return tuple(_redundant_core(self).queue_bytes)
    restart = close

    def activate_slot1(self, admission, binding, budget):
        c = _redundant_core(self)
        """Consume one proved mobility admission after all non-consuming checks pass."""
        with c._lock:
            if c._receive_previews:
                _fail("E-CAPACITY")
            if c.closed or c.states[1] != ABSENT or c._bootstrap is None or c._bootstrap._prk is None:
                _fail("E-CANDIDATE")
            c.states[1] = CANDIDATE
            try:
                binding = _binding(binding); _budget(budget)
                semantics, policy = r8mobility.profile3_admission_details(admission, self)
                if (semantics[7] is not c._profile3_owner or semantics[1] != c._scid
                        or semantics[3] != 1 or semantics[6] != binding):
                    _fail("E-CANDIDATE")
                c.states[1] = VALIDATED
                r8mobility.consume_profile3_admission(admission, self, policy)
                c._profile3_owner = None
                outbound, inbound = c._bootstrap.take_slot1()
                local_loc, peer_loc = _loc(semantics[4]), _loc(semantics[5])
            except Exception:
                c.states[1] = ABSENT
                _fail("E-CANDIDATE")
            c._out[1], c._in[1] = outbound, inbound
            c._bindings[1], c.budgets[1] = binding, budget
            c._local_locs[1], c._peer_locs[1] = local_loc, peer_loc
            c.states[1] = ACTIVE
            self._emit("recovered", 1)
            c._receive_generation += 1

    def send(self, plaintext):
        c = _redundant_core(self)
        try:
            plaintext = memoryview(plaintext).cast("B").tobytes()
        except (TypeError, ValueError):
            _fail("E-BUDGET")
        with c._lock:
            if c.closed or not self._active():
                _fail("E-PATH")
            paths = self._active()
            if not 0 < c._next_delivery_id < _MAX:
                self._release(); _fail("E-COUNTER")
            packet_size = r8session.PROFILE3_DATA_PACKET_OVERHEAD + len(plaintext)
            for slot in paths:
                if packet_size > c.budgets[slot]:
                    _fail("E-BUDGET")
                if len(c._queues[slot]) >= _QUEUE_PACKETS or c.queue_bytes[slot] + packet_size > _QUEUE_BYTES:
                    c._queue_overflow_packets += 1
                    self._emit("queue-overflow", slot)
                    return Outbound((None, None))
                if not 1 <= c._out[slot].send_counter < _MAX:
                    self._release(); _fail("E-COUNTER")
            ident = c._next_delivery_id
            packets = [None, None]
            for slot in paths:
                packets[slot] = r8session.seal_profile3_data(c._out[slot], self._header(slot), ident,
                                                              plaintext, c.budgets[slot])
            c._next_delivery_id += 1
            for slot in paths:
                packet = packets[slot]
                c._queues[slot].append(_Queued(ident, packet)); c.queue_bytes[slot] += len(packet)
            return Outbound(tuple(packets))

    def front(self, slot):
        c = _redundant_core(self)
        with c._lock:
            if slot not in (0, 1) or not c._queues[slot]:
                return None
            return c._queues[slot][0].packet

    def confirm(self, slot, packet):
        c = _redundant_core(self)
        with c._lock:
            if slot not in (0, 1) or not c._queues[slot] or c._queues[slot][0].packet != packet:
                _fail("E-PATH")
            queued = c._queues[slot].popleft(); c.queue_bytes[slot] -= len(queued.packet)

    def _preview_receive(self, slot, binding, packet, require_active_binding):
        c = _redundant_core(self)
        binding = _binding(binding)
        with c._lock:
            if (c.closed or slot not in (0, 1) or c.states[slot] != ACTIVE
                    or (require_active_binding and binding != c._bindings[slot])):
                _fail("E-PATH")
            if len(c._receive_previews) >= 1:
                _fail("E-CAPACITY")
            now = self._now()
            try:
                header, _ = r8session.parse_packet(packet, c.budgets[slot])
                expected = self._header(slot, inbound=True)
                if (header.nh != NH_SES or header.profile != 3 or header.scid != c._scid
                        or header.src != expected.src or header.dst != expected.dst or header.tc != 0
                        or header.flags != expected.flags or header.pslot != slot or header.hop == 0):
                    _fail("E-PATH")
                session_preview = r8session.preview_profile3_data(
                    c._in[slot], packet, c.budgets[slot])
            except RedundantError:
                raise
            except (r8session.SessionError, WireError) as error:
                _fail("E-REPLAY" if getattr(error, "category", None) in ("REPLAY", "COUNTER_RANGE")
                      else "E-PATH")
            ident, plaintext = session_preview.delivery_id, session_preview.plaintext
            if type(ident) is not int or not 0 < ident < _MAX:
                r8session.abort_profile3_data(c._in[slot], session_preview)
                _fail("E-COUNTER")
            digest = hashlib.sha256(plaintext).digest()
            existing = c._delivery.get(ident)
            if existing is None and c._high_water is not None:
                if (ident > c._high_water and ident - c._high_water > _GAP
                        or ident <= c._high_water - _DEDUP_MAX):
                    r8session.abort_profile3_data(c._in[slot], session_preview)
                    _fail("E-REPLAY")
            preview = ReceivePreview(_HANDLE_AUTHORITY)
            c._receive_previews[preview] = (c._receive_generation, slot, session_preview,
                                               ident, plaintext, digest, existing, now)
            _RECEIVE_OWNERS[preview] = self
            return preview

    def preview_receive(self, slot, binding, packet):
        c = _redundant_core(self)
        return self._preview_receive(slot, binding, packet, True)

    def preview_mobility(self, manager, slot, binding, packet):
        c = _redundant_core(self)
        manager_core = r8mobility._mobility_core(manager) if isinstance(manager, r8mobility.MobilityManager) else None
        if (manager_core is None or manager_core.profile != 3
                or manager_core.scid != c._scid or manager_core.authorized_session is not self):
            _fail("E-CANDIDATE")
        binding = _binding(binding)
        c._mobility_manager = manager
        receive_preview = self._preview_receive(slot, binding, packet, False)
        try:
            mobility_preview = manager.preview(receive_preview.plaintext, _binding_view(binding), receive_preview)
        except Exception:
            self.abort_receive(receive_preview)
            raise
        preview = MobilityReceivePreview(_HANDLE_AUTHORITY)
        with c._lock:
            c._mobility_previews[preview] = (manager, receive_preview, mobility_preview)
            _MOBILITY_OWNERS[preview] = self
        return preview
    def commit_mobility(self, preview):
        c = _redundant_core(self)
        with c._lock:
            if not isinstance(preview, MobilityReceivePreview) or _MOBILITY_OWNERS.get(preview) is not self:
                _fail("E-CANDIDATE")
            record = c._mobility_previews.pop(preview, None)
            if record is None:
                _MOBILITY_OWNERS.pop(preview, None)
                _fail("E-CANDIDATE")
            _MOBILITY_OWNERS.pop(preview, None)
        manager, receive_preview, mobility_preview = record
        try:
            return manager.commit(mobility_preview)
        except Exception:
            try:
                self.abort_receive(receive_preview)
            except RedundantError:
                pass
            raise
    def abort_mobility(self, preview):
        c = _redundant_core(self)
        with c._lock:
            if not isinstance(preview, MobilityReceivePreview) or _MOBILITY_OWNERS.get(preview) is not self:
                _fail("E-CANDIDATE")
            record = c._mobility_previews.pop(preview, None)
            if record is None:
                _MOBILITY_OWNERS.pop(preview, None)
                _fail("E-CANDIDATE")
            _MOBILITY_OWNERS.pop(preview, None)
        self.abort_receive(record[1])
    def _finish_receive_preview(self, preview):
        c = _redundant_core(self)
        c._receive_previews.pop(preview, None)
        _RECEIVE_OWNERS.pop(preview, None)
        self._drop_mobility_preview(preview)
    def _drop_mobility_preview(self, receive_preview):
        c = _redundant_core(self)
        for handle, record in tuple(c._mobility_previews.items()):
            if record[1] is receive_preview:
                c._mobility_previews.pop(handle)
                _MOBILITY_OWNERS.pop(handle, None)
    def _finish_receive_generation(self):
        c = _redundant_core(self)
        for preview, record in tuple(c._receive_previews.items()):
            slot, session_preview = record[1], record[2]
            session = c._in[slot] if slot in (0, 1) else None
            if session is not None:
                try:
                    r8session.abort_profile3_data(session, session_preview)
                except r8session.SessionError:
                    pass
            _RECEIVE_OWNERS.pop(preview, None)
        c._receive_previews.clear()
        for preview in tuple(c._mobility_previews):
            _MOBILITY_OWNERS.pop(preview, None)
        c._mobility_previews.clear()

    def commit_receive(self, preview):
        c = _redundant_core(self)
        with c._lock:
            if not isinstance(preview, ReceivePreview) or _RECEIVE_OWNERS.get(preview) is not self:
                _fail("E-REPLAY")
            record = c._receive_previews.pop(preview, None)
            _RECEIVE_OWNERS.pop(preview, None)
            self._drop_mobility_preview(preview)
            if record is None:
                _fail("E-REPLAY")
            generation, slot, session_preview, ident, plaintext, digest, existing, now = record
            if (generation != c._receive_generation or c.closed
                    or slot not in (0, 1) or c.states[slot] != ACTIVE):
                _fail("E-REPLAY")
            try:
                r8session.commit_profile3_data(c._in[slot], session_preview)
            except r8session.SessionError as error:
                _fail("E-REPLAY" if error.category in ("REPLAY", "COUNTER_RANGE") else "E-PATH")
            self._expire(now)
            if existing is None:
                if len(c._dedup) >= _DEDUP_MAX:
                    oldest = min(c._dedup, key=lambda key: c._dedup[key][1])
                    del c._dedup[oldest]
                c._dedup[ident] = (plaintext, now + _DEDUP_LIFETIME)
                c._delivery[ident] = (digest, len(plaintext))
                if c._high_water is None or ident > c._high_water:
                    c._high_water = ident
                    floor = c._high_water - _DEDUP_MAX
                    for key in tuple(c._delivery):
                        if key <= floor:
                            del c._delivery[key]
                c._receive_generation += 1
                self._finish_receive_generation()
                return Inbound(plaintext, True)
            c._receive_generation += 1
            self._finish_receive_generation()
            if existing != (digest, len(plaintext)):
                self._emit("divergence", slot)
                self._release()
                _fail("E-PATH")
            return Inbound(plaintext, False)
    def abort_receive(self, preview):
        c = _redundant_core(self)
        with c._lock:
            if not isinstance(preview, ReceivePreview) or _RECEIVE_OWNERS.get(preview) is not self:
                _fail("E-REPLAY")
            record = c._receive_previews.pop(preview, None)
            _RECEIVE_OWNERS.pop(preview, None)
            self._drop_mobility_preview(preview)
            if record is None:
                _fail("E-REPLAY")
            slot, session_preview = record[1], record[2]
            try:
                r8session.abort_profile3_data(c._in[slot], session_preview)
            except (r8session.SessionError, TypeError):
                _fail("E-REPLAY")

    def receive(self, slot, binding, packet):
        c = _redundant_core(self)
        preview = self.preview_receive(slot, binding, packet)
        try:
            return self.commit_receive(preview)
        except Exception:
            try:
                self.abort_receive(preview)
            except RedundantError:
                pass
            raise

    def remove_path(self, slot):
        c = _redundant_core(self)
        with c._lock:
            if c._receive_previews:
                _fail("E-CAPACITY")
            if slot not in (0, 1) or c.states[slot] == ABSENT:
                _fail("E-PATH")
            if c.states[slot] in (REMOVED, RELEASED):
                return
            if c.states[slot] != ACTIVE:
                _fail("E-PATH")
            c.states[slot] = DEGRADED
            outbound, inbound = c._out[slot], c._in[slot]
            if c._bootstrap is not None:
                c._bootstrap.release_sessions(outbound, inbound)
            else:
                outbound.release()
                if inbound is not outbound:
                    inbound.release()
            c._out[slot] = c._in[slot] = None; c._bindings[slot] = c.budgets[slot] = None
            c._queues[slot].clear(); c.queue_bytes[slot] = 0; c.states[slot] = REMOVED
            c._receive_generation += 1
            self._emit("degraded", slot)
            if not self._active():
                self._release()

    path_failed = remove_path
