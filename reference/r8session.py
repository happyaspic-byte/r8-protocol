#!/usr/bin/env python3
"""Strict R8 v0.1 session payload codec and cryptographic primitives.

Closed-lab only.  This module deliberately has no trust-on-first-use path.
"""
import argparse
import errno
import hmac
import hashlib
import ipaddress
import os
import socket
import struct
import sys
import time
import threading
from dataclasses import dataclass
import weakref
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
_PROFILE3_BOOTSTRAP_AUTHORITY = object()
from r8ref import Header, NH_SES, WireError

class _Redacted:
    __slots__ = ()
    def __repr__(self):
        return f"<{type(self).__name__}>"

ERRORS = frozenset((
    "ROLE_MISMATCH", "SERVICE_MISMATCH", "PIN_MISMATCH", "EID_KEY_MISMATCH",
    "COOKIE_INVALID", "AUTH_FAILED", "COUNTER_RANGE", "COUNTER_EXHAUSTED",
    "REPLAY", "TRUNCATED", "TRAILING_BYTES", "SCID_COLLISION", "CAPACITY",
    "RESTART_REQUIRED", "UNEXPECTED_MESSAGE", "TIMEOUT", "BUDGET",
    "BINDING_INVALID", "CONFIG_ERROR", "RNG_FAILURE",
))
PROFILE3_DATA_PACKET_OVERHEAD = 84

class SessionError(ValueError):
    def __init__(self, category):
        if category not in ERRORS: raise ValueError("invalid session error")
        self.category = category
        super().__init__(category)

def _fail(category): raise SessionError(category)
def _decode_fail(): _fail("UNEXPECTED_MESSAGE")
def _exact(data, size):
    if len(data) < size: _fail("TRUNCATED")
    if len(data) > size: _fail("TRAILING_BYTES")

def _random(size):
    try:
        value = os.urandom(size)
    except OSError:
        _fail("RNG_FAILURE")
    if not isinstance(value, bytes) or len(value) != size:
        _fail("RNG_FAILURE")
    return value

def eid(public_key):
    if len(public_key) != 32: _fail("EID_KEY_MISMATCH")
    return hashlib.sha256(b"R8 EID v1" + public_key).digest()[:16]

@dataclass(frozen=True, repr=False)
class Identity(_Redacted):
    private: Ed25519PrivateKey
    public: bytes
    eid: bytes
    @classmethod
    def from_seed(cls, seed):
        if len(seed) != 32: raise ValueError("seed must be 32 bytes")
        private = Ed25519PrivateKey.from_private_bytes(seed)
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return cls(private, public, eid(public))

@dataclass(frozen=True, repr=False)
class PeerPin(_Redacted):
    role: int
    eid: bytes
    public_key: bytes
    def __post_init__(self):
        if self.role not in (1, 2) or len(self.eid) != 16 or len(self.public_key) != 32 or eid(self.public_key) != self.eid:
            raise ValueError("invalid complete peer pin")

@dataclass(frozen=True, repr=False)
class UdpBinding(_Redacted):
    address: bytes
    port: int
    selector_kind: int
    selector: bytes

    def encode(self):
        try:
            valid = (isinstance(self.address, bytes) and isinstance(self.selector, bytes)
                     and self.selector_kind in (1, 2) and len(self.selector) == 16
                     and 1 <= self.port <= 65535)
            ip = ipaddress.ip_address(self.address)
        except (TypeError, ValueError):
            _fail("BINDING_INVALID")
        if not valid:
            _fail("BINDING_INVALID")
        family = b"\x01\x04" if ip.version == 4 else b"\x01\x06"
        return family + ip.packed + struct.pack("!H", self.port) + bytes((self.selector_kind,)) + self.selector

    @classmethod
    def from_endpoint(cls, host, port, selector_kind, selector):
        try:
            return cls(ipaddress.ip_address(host).packed, port, selector_kind, bytes(selector))
        except (ValueError, TypeError):
            _fail("BINDING_INVALID")
@dataclass(frozen=True, repr=False)
class NativeBinding(_Redacted):
    ingress_descriptor_id: int
    next_hop_mac: bytes

    def encode(self):
        if (type(self.ingress_descriptor_id) is not int
                or not 0 < self.ingress_descriptor_id <= 0xffffffff
                or not isinstance(self.next_hop_mac, bytes)
                or len(self.next_hop_mac) != 6):
            _fail("BINDING_INVALID")
        return b"\x02" + struct.pack("!I", self.ingress_descriptor_id) + self.next_hop_mac


Binding = UdpBinding | NativeBinding


def validate_binding(value):
    if not isinstance(value, Binding):
        _fail("BINDING_INVALID")
    try:
        encoded = value.encode()
    except (TypeError, ValueError, struct.error):
        _fail("BINDING_INVALID")
    if not isinstance(encoded, bytes):
        _fail("BINDING_INVALID")
    return encoded

_LAYOUTS = {1: 118, 2: 118, 3: 230, 4: 182, 5: None, 6: None, 7: None}
def decode(payload):
    try: view = memoryview(payload).cast("B")
    except (TypeError, ValueError): _decode_fail()
    if view.nbytes > 1280: _fail("TRAILING_BYTES")
    if view.nbytes < 4: _fail("TRUNCATED")
    typ, version, profile, flags = view[:4]
    if typ not in _LAYOUTS or version != 1 or profile > 3 or flags != 0: _decode_fail()
    expected = _LAYOUTS[typ]
    if expected is not None: _exact(view, expected + 4)
    elif typ == 5: _exact(view, 4 + 8 + 60)
    elif typ == 7: _exact(view, 4 + 8 + 18)
    elif typ == 6 and profile == 3:
        if view.nbytes < 4 + 32: _fail("TRUNCATED")
    elif view.nbytes < 4 + 8 + 16: _fail("TRUNCATED")
    return typ, version, profile, view[4:].tobytes()
def encode(typ, profile, body):
    try: view = memoryview(body).cast("B")
    except (TypeError, ValueError): _decode_fail()
    if not isinstance(typ, int) or not isinstance(profile, int) or not 0 <= profile <= 3: _decode_fail()
    payload = bytes((typ, 1, profile, 0)) + view.tobytes()
    decode(payload)
    return payload
def build_packet(header, payload, binding_budget=1280):
    if not isinstance(header, Header) or header.nh != NH_SES:
        _decode_fail()
    decode(payload)
    return header.pack(payload, binding_budget)

def parse_packet(packet, binding_budget=1280):
    try:
        header, payload = Header.unpack(packet, binding_budget)
    except WireError as error:
        category = getattr(error, "category", None)
        if category == "TRUNCATED": _fail("TRUNCATED")
        if category == "TRAILING_BYTES": _fail("TRAILING_BYTES")
        if category in ("BINDING_BUDGET", "PACKET_CAP"): _fail("BUDGET")
        _decode_fail()
    if header.nh != NH_SES: _decode_fail()
    decode(payload)
    return header, payload

def _open_fields(body):
    _exact(body, 118)
    return body[0], body[1], struct.unpack("!I", body[2:6])[0], body[6:22], body[22:54], body[54:86], body[86:118]


@dataclass(frozen=True, repr=False)
class Open(_Redacted):
    sender_role: int
    receiver_role: int
    service_context: int
    sender_eid: bytes
    sender_public_key: bytes
    sender_ephemeral: bytes
    sender_nonce: bytes

    def build(self, profile=0):
        _roles(self.sender_role, self.receiver_role)
        body = (bytes((self.sender_role, self.receiver_role)) + struct.pack("!I", self.service_context) +
                self.sender_eid + self.sender_public_key + self.sender_ephemeral + self.sender_nonce)
        return encode(1, profile, body)

    @classmethod
    def parse(cls, payload):
        typ, _, _, body = decode(payload)
        if typ != 1: _decode_fail()
        role, peer, service, peer_eid, public, ephemeral, nonce_value = _open_fields(body)
        _roles(role, peer)
        if eid(public) != peer_eid: _fail("EID_KEY_MISMATCH")
        return cls(role, peer, service, peer_eid, public, ephemeral, nonce_value)


@dataclass(frozen=True, repr=False)
class VerifyCookie(_Redacted):
    receiver_role: int
    sender_role: int
    service_context: int
    client_public_key: bytes
    ephemeral_hash: bytes
    boot_instance: bytes
    cookie_value: bytes

    def build(self, profile=0):
        _roles(self.sender_role, self.receiver_role)
        body = (bytes((self.receiver_role, self.sender_role)) + struct.pack("!I", self.service_context) +
                self.client_public_key + self.ephemeral_hash + self.boot_instance + self.cookie_value)
        return encode(2, profile, body)

    @classmethod
    def parse(cls, payload):
        typ, _, _, body = decode(payload)
        if typ != 2: _decode_fail()
        _exact(body, 118)
        receiver, sender = body[:2]
        _roles(sender, receiver)
        return cls(receiver, sender, struct.unpack("!I", body[2:6])[0], body[6:38], body[38:70], body[70:86], body[86:118])


def _roles(sender, receiver):
    if sender not in (1, 2) or receiver not in (1, 2) or sender == receiver:
        _fail("ROLE_MISMATCH")


def parse_message(payload):
    typ = decode(payload)[0]
    if typ == 1: return Open.parse(payload)
    if typ == 2: return VerifyCookie.parse(payload)
    return decode(payload)

def cookie_input(binding, client_role, server_role, service, scid, client_eid, client_public, client_ephemeral, boot, bucket, server_context):
    return (b"R8 cookie v1" + validate_binding(binding) + bytes((8, 1, client_role, server_role)) +
            struct.pack("!IQ", service, scid) + client_eid + hashlib.sha256(client_public).digest() +
            hashlib.sha256(client_ephemeral).digest() + boot + struct.pack("!QI", bucket, server_context))
def cookie(key, *args):
    if len(key) != 32: raise ValueError("cookie key")
    return hmac.new(key, cookie_input(*args), hashlib.sha256).digest()
def verify_cookie(key, current_bucket, binding, client_role, server_role, service, scid, client_eid,
                  client_public, client_ephemeral, boot, server_context, supplied):
    return any(hmac.compare_digest(
        supplied, cookie(key, binding, client_role, server_role, service, scid, client_eid,
                         client_public, client_ephemeral, boot, bucket, server_context))
        for bucket in (current_bucket, current_bucket - 1))

def transcript(scid, client_role, server_role, service, client_eid, client_public, server_eid, server_public,
               client_eph, server_eph, client_nonce, server_nonce, boot):
    return (b"R8 session transcript v1" + bytes((8, 0)) + struct.pack("!QBBI", scid, client_role, server_role, service) +
            client_eid + client_public + server_eid + server_public + client_eph + server_eph + client_nonce + server_nonce + boot)
def placeholder_t0(scid, client_role, server_role, service, client_eid, client_public, server_eid, client_eph, client_nonce, boot):
    return transcript(scid, client_role, server_role, service, client_eid, client_public, server_eid, b"\0"*32, client_eph, b"\0"*32, client_nonce, b"\0"*32, boot)
def sign_open_auth(identity, t0): return identity.private.sign(b"R8 OPEN_AUTH v1" + t0)
def sign_open_ack(identity, t0): return identity.private.sign(b"R8 OPEN_ACK v1" + t0)
def verify_signature(public, label, t0, signature):
    try: Ed25519PublicKey.from_public_bytes(public).verify(signature, label + t0)
    except (InvalidSignature, ValueError): _fail("AUTH_FAILED")
def transcript_hash(t0, client_signature, server_signature): return hashlib.sha256(t0 + client_signature + server_signature).digest()
def x25519(secret, peer):
    try: shared = X25519PrivateKey.from_private_bytes(secret).exchange(X25519PublicKey.from_public_bytes(peer))
    except ValueError: _fail("AUTH_FAILED")
    if shared == b"\0" * 32: _fail("AUTH_FAILED")
    return shared
def key_prk(shared, thash):
    if len(shared) != 32 or len(thash) != 32: _fail("AUTH_FAILED")
    extract = HMAC(thash, SHA256())
    extract.update(shared)
    return extract.finalize()
def _key_schedule_prk(prk, thash, sender_role, receiver_role, profile, slot):
    if (not isinstance(prk, bytes) or len(prk) != 32 or not isinstance(thash, bytes) or len(thash) != 32
            or sender_role not in (1, 2) or receiver_role not in (1, 2)
            or not 0 <= profile <= 3 or slot not in (0, 1)):
        _fail("AUTH_FAILED")
    info = b"R8 key v1" + bytes((8, 1, profile)) + thash + bytes((sender_role, receiver_role, slot))
    return HKDFExpand(algorithm=SHA256(), length=32, info=info).derive(prk)
def key_schedule(shared, thash, sender_role, receiver_role, profile, slot):
    return _key_schedule_prk(key_prk(shared, thash), thash, sender_role, receiver_role, profile, slot)
def nonce(counter):
    if not 1 <= counter < 0xffffffffffffffff: _fail("COUNTER_RANGE")
    return b"\0\0\0\0" + struct.pack("!Q", counter)
def _aad(header, prefix, counter):
    try:
        header_view = memoryview(header).cast("B")
        prefix_view = memoryview(prefix).cast("B")
    except (TypeError, ValueError):
        _fail("AUTH_FAILED")
    if header_view.nbytes != 48 or prefix_view.nbytes != 4:
        _fail("AUTH_FAILED")
    canonical_header = bytearray(header_view)
    canonical_header[5] = 0
    return bytes(canonical_header) + prefix_view.tobytes() + struct.pack("!Q", counter)
def seal(key, header, prefix, counter, plaintext):
    return ChaCha20Poly1305(key).encrypt(nonce(counter), plaintext, _aad(header, prefix, counter))
def open_sealed(key, header, prefix, counter, ciphertext):
    try: return ChaCha20Poly1305(key).decrypt(nonce(counter), ciphertext, _aad(header, prefix, counter))
    except InvalidTag: _fail("AUTH_FAILED")

class ReplayWindow:
    WINDOW = 4096
    MAX_FORWARD_JUMP = 65536

    def __init__(self):
        self.highest = 0
        self.bits = 0
        self.generation = 0
    def preview(self, counter):
        nonce(counter)
        if self.highest and counter > self.highest + self.MAX_FORWARD_JUMP: _fail("REPLAY")
        if counter <= self.highest:
            distance = self.highest - counter
            if distance >= self.WINDOW or self.bits & (1 << distance): _fail("REPLAY")
        return self.generation
    def check_and_mark(self, counter):
        self.preview(counter)
        if counter > self.highest:
            shift = counter - self.highest
            self.highest, self.bits = counter, (1 if shift >= self.WINDOW else
                ((self.bits << shift) | 1) & ((1 << self.WINDOW) - 1))
        else:
            self.bits |= 1 << (self.highest - counter)
        self.generation += 1

_DECRYPT_PREVIEWS = weakref.WeakKeyDictionary()
_SESSION_PREVIEW_AUTHORITY = object()

class _DecryptPreview:
    __slots__ = ("__weakref__",)
    def __init__(self, session, generation, counter, *, _authority=None):
        if _authority is not _SESSION_PREVIEW_AUTHORITY or self in _DECRYPT_PREVIEWS:
            _fail("REPLAY")
        _DECRYPT_PREVIEWS[self] = (session, generation, counter, None)
    def __repr__(self):
        return "<DecryptPreview>"
    def _invalidate(self):
        record = _DECRYPT_PREVIEWS.pop(self, None)
        if record is not None and record[3] is not None:
            record[3]._purge()

_SESSION_CORES = weakref.WeakKeyDictionary()

class _SessionCore:
    __slots__ = ("key", "send_counter", "replay", "lock", "previews", "released")
    def __init__(self, key, send_counter):
        self.key = key
        self.send_counter = send_counter
        self.replay = ReplayWindow()
        self.lock = threading.RLock()
        self.previews = set()
        self.released = False

def _session_core(session):
    core = _SESSION_CORES.get(session)
    if core is None:
        _fail("UNEXPECTED_MESSAGE")
    return core

def _replay_snapshot(replay):
    snapshot = ReplayWindow()
    snapshot.highest = replay.highest
    snapshot.bits = replay.bits
    snapshot.generation = replay.generation
    return snapshot

class Session:
    __slots__ = ("__weakref__",)
    def __init__(self, key, send_counter=1):
        if self in _SESSION_CORES:
            _fail("UNEXPECTED_MESSAGE")
        _exact(key, 32)
        if type(send_counter) is not int:
            _fail("COUNTER_RANGE")
        _SESSION_CORES[self] = _SessionCore(bytes(key), send_counter)
    @property
    def send_counter(self):
        return _session_core(self).send_counter
    @property
    def replay(self):
        return _replay_snapshot(_session_core(self).replay)
    @property
    def _previews(self):
        return frozenset(_session_core(self).previews)
    @property
    def _released(self):
        return _session_core(self).released
    @property
    def _key(self):
        return None
    def _move_unlocked(self):
        core = _session_core(self)
        if core.released or core.previews or core.key is None:
            _fail("UNEXPECTED_MESSAGE")
        owned = Session(core.key, core.send_counter)
        owned_core = _session_core(owned)
        owned_core.replay.highest = core.replay.highest
        owned_core.replay.bits = core.replay.bits
        owned_core.replay.generation = core.replay.generation
        core.key = None
        core.send_counter = 0
        core.replay = ReplayWindow()
        core.released = True
        return owned
    def encrypt(self, header, prefix, plaintext):
        core = _session_core(self)
        with core.lock:
            if core.released or core.key is None:
                _fail("UNEXPECTED_MESSAGE")
            if not 1 <= core.send_counter < 0xffffffffffffffff:
                _fail("COUNTER_EXHAUSTED")
            counter = core.send_counter
            core.send_counter += 1
            return counter, seal(core.key, header, prefix, counter, plaintext)
    def preview_decrypt(self, header, prefix, counter, ciphertext):
        core = _session_core(self)
        with core.lock:
            if core.released or core.key is None:
                _fail("UNEXPECTED_MESSAGE")
            if len(core.previews) >= 64:
                _fail("CAPACITY")
            generation = core.replay.preview(counter)
            plaintext = open_sealed(core.key, header, prefix, counter, ciphertext)
            preview = _DecryptPreview(
                self, generation, counter, _authority=_SESSION_PREVIEW_AUTHORITY)
            core.previews.add(preview)
            return plaintext, preview
    def commit_decrypt(self, preview):
        core = _session_core(self)
        with core.lock:
            if not isinstance(preview, _DecryptPreview):
                _fail("REPLAY")
            record = _DECRYPT_PREVIEWS.get(preview)
            if (
                record is None
                or record[0] is not self
                or preview not in core.previews
                or record[1] != core.replay.generation
            ):
                core.previews.discard(preview)
                if isinstance(preview, _DecryptPreview):
                    preview._invalidate()
                _fail("REPLAY")
            core.replay.check_and_mark(record[2])
            for stale in tuple(core.previews):
                stale._invalidate()
            core.previews.clear()
    def abort_decrypt(self, preview):
        core = _session_core(self)
        with core.lock:
            if not isinstance(preview, _DecryptPreview):
                _fail("REPLAY")
            record = _DECRYPT_PREVIEWS.get(preview)
            valid = (
                record is not None
                and record[0] is self
                and preview in core.previews
                and record[1] == core.replay.generation
            )
            if not valid:
                if record is not None and record[0] is self:
                    core.previews.discard(preview)
                    preview._invalidate()
                _fail("REPLAY")
            core.previews.remove(preview)
            preview._invalidate()
    def _discard_previews(self):
        core = _session_core(self)
        with core.lock:
            for preview in tuple(core.previews):
                preview._invalidate()
            core.previews.clear()
    def release(self):
        """Irreversibly purge this session under its own lock."""
        core = _session_core(self)
        with core.lock:
            if core.released:
                return
            for preview in tuple(core.previews):
                preview._invalidate()
            core.previews.clear()
            core.key = None
            core.send_counter = 0
            core.replay = ReplayWindow()
            core.released = True
    def decrypt(self, header, prefix, counter, ciphertext):
        core = _session_core(self)
        with core.lock:
            plaintext, preview = self.preview_decrypt(header, prefix, counter, ciphertext)
            self.commit_decrypt(preview)
            return plaintext
_PROFILE3_BOOTSTRAPS = weakref.WeakKeyDictionary()
_PROFILE3_SLOT1_PREPARATIONS = weakref.WeakKeyDictionary()
_PROFILE3_SLOT1_AUTHORITY = object()
_PROFILE3_CONSUMER_AUTHORITY = object()
def _move_session_pair(outbound, inbound):
    if not isinstance(outbound, Session) or not isinstance(inbound, Session) or outbound is inbound:
        _fail("UNEXPECTED_MESSAGE")
    first, second = sorted((outbound, inbound), key=id)
    first_core, second_core = _session_core(first), _session_core(second)
    with first_core.lock:
        with second_core.lock:
            if (
                first_core.released or second_core.released
                or first_core.previews or second_core.previews
                or first_core.key is None or second_core.key is None
            ):
                _fail("UNEXPECTED_MESSAGE")
            return outbound._move_unlocked(), inbound._move_unlocked()

class _Profile3Slot1Preparation:
    __slots__ = ("__weakref__",)
    def __init__(self, bootstrap, outbound, inbound, *, _authority):
        if _authority is not _PROFILE3_SLOT1_AUTHORITY or self in _PROFILE3_SLOT1_PREPARATIONS:
            _fail("UNEXPECTED_MESSAGE")
        _PROFILE3_SLOT1_PREPARATIONS[self] = (bootstrap, outbound, inbound)
    def __repr__(self):
        return "<Profile3Slot1Preparation>"

class Profile3Bootstrap:
    """Opaque one-shot handle for transferred Profile-3 session material."""
    __slots__ = ("__weakref__",)

    def __init__(self, scid, role, local_loc, peer_loc, outbound, inbound, prk, thash, *, _authority):
        if _authority is not _PROFILE3_BOOTSTRAP_AUTHORITY or self in _PROFILE3_BOOTSTRAPS:
            _fail("UNEXPECTED_MESSAGE")
        _PROFILE3_BOOTSTRAPS[self] = (scid, role, local_loc, peer_loc, outbound, inbound, prk, thash,
                                      {outbound, inbound})

    def __repr__(self):
        return "<Profile3Bootstrap>"


    def _transfer(self, _authority):
        if _authority is not _PROFILE3_CONSUMER_AUTHORITY:
            _fail("UNEXPECTED_MESSAGE")
        record = _PROFILE3_BOOTSTRAPS.get(self)
        if record is None:
            _fail("UNEXPECTED_MESSAGE")
        scid, role, local_loc, peer_loc, outbound, inbound, prk, thash, _ = record
        if scid == 0 or outbound is None or inbound is None or prk is None or thash is None or outbound is inbound:
            _fail("UNEXPECTED_MESSAGE")
        owned_outbound, owned_inbound = _move_session_pair(outbound, inbound)
        _PROFILE3_BOOTSTRAPS.pop(self, None)
        return Profile3Bootstrap(scid, role, local_loc, peer_loc, owned_outbound, owned_inbound, prk, thash,
                                 _authority=_PROFILE3_BOOTSTRAP_AUTHORITY)

    def _context(self, _authority):
        if _authority is not _PROFILE3_CONSUMER_AUTHORITY:
            _fail("UNEXPECTED_MESSAGE")
        record = _PROFILE3_BOOTSTRAPS.get(self)
        if record is None:
            _fail("UNEXPECTED_MESSAGE")
        return record[:8]
    def _prepare_slot1(self, _authority):
        if _authority is not _PROFILE3_CONSUMER_AUTHORITY:
            _fail("UNEXPECTED_MESSAGE")
        record = _PROFILE3_BOOTSTRAPS.get(self)
        if record is None or record[6] is None or record[7] is None:
            _fail("UNEXPECTED_MESSAGE")
        if any(item[0] is self for item in _PROFILE3_SLOT1_PREPARATIONS.values()):
            _fail("CAPACITY")
        scid, role, local_loc, peer_loc, outbound, inbound, prk, thash, sessions = record
        peer_role = 2 if role == 1 else 1
        slot_outbound = Session(_key_schedule_prk(prk, thash, role, peer_role, 3, 1))
        try:
            slot_inbound = Session(_key_schedule_prk(prk, thash, peer_role, role, 3, 1))
        except Exception:
            slot_outbound.release()
            raise
        return _Profile3Slot1Preparation(
            self, slot_outbound, slot_inbound, _authority=_PROFILE3_SLOT1_AUTHORITY)

    def _consume_slot1(self, preparation, consumer, _authority):
        if _authority is not _PROFILE3_CONSUMER_AUTHORITY:
            _fail("UNEXPECTED_MESSAGE")
        prepared = _PROFILE3_SLOT1_PREPARATIONS.get(preparation)
        record = _PROFILE3_BOOTSTRAPS.get(self)
        if (
            prepared is None or prepared[0] is not self or record is None
            or record[6] is None or record[7] is None or not callable(consumer)
        ):
            _fail("UNEXPECTED_MESSAGE")
        consumer()
        _PROFILE3_SLOT1_PREPARATIONS.pop(preparation, None)
        scid, role, local_loc, peer_loc, outbound, inbound, _prk, _thash, sessions = record
        slot_outbound, slot_inbound = prepared[1:]
        _PROFILE3_BOOTSTRAPS[self] = (
            scid, role, local_loc, peer_loc, outbound, inbound, None, None,
            sessions | {slot_outbound, slot_inbound})
        return slot_outbound, slot_inbound

    def _abort_slot1(self, preparation, _authority):
        if _authority is not _PROFILE3_CONSUMER_AUTHORITY:
            _fail("UNEXPECTED_MESSAGE")
        prepared = _PROFILE3_SLOT1_PREPARATIONS.pop(preparation, None)
        if prepared is None or prepared[0] is not self:
            _fail("UNEXPECTED_MESSAGE")
        prepared[1].release()
        prepared[2].release()



    def close(self):
        for preparation, prepared in tuple(_PROFILE3_SLOT1_PREPARATIONS.items()):
            if prepared[0] is self:
                _PROFILE3_SLOT1_PREPARATIONS.pop(preparation, None)
                prepared[1].release()
                prepared[2].release()
        record = _PROFILE3_BOOTSTRAPS.pop(self, None)
        if record is not None:
            for session in record[8]:
                session.release()

    def release_sessions(self, *sessions, _authority):
        if _authority is not _PROFILE3_CONSUMER_AUTHORITY:
            _fail("UNEXPECTED_MESSAGE")
        record = _PROFILE3_BOOTSTRAPS.get(self)
        if record is None:
            _fail("UNEXPECTED_MESSAGE")
        for session in sessions:
            if session is not None and session in record[8]:
                session.release()
                record[8].discard(session)
_PROFILE3_DATA_PREVIEWS = weakref.WeakKeyDictionary()

class Profile3DataPreview:
    __slots__ = ("__weakref__",)
    def __init__(self, session, session_preview, delivery_id, plaintext, *, _authority=None):
        if _authority is not _SESSION_PREVIEW_AUTHORITY or self in _PROFILE3_DATA_PREVIEWS:
            _fail("REPLAY")
        try:
            session_record = _DECRYPT_PREVIEWS.get(session_preview)
        except TypeError:
            _fail("REPLAY")
        if (
            session_record is None
            or session_record[0] is not session
            or session_record[3] is not None
        ):
            _fail("REPLAY")
        _PROFILE3_DATA_PREVIEWS[self] = (
            session, session_preview, delivery_id, bytes(plaintext))
        _DECRYPT_PREVIEWS[session_preview] = (*session_record[:3], self)
    @property
    def delivery_id(self):
        record = _PROFILE3_DATA_PREVIEWS.get(self)
        if record is None:
            _fail("REPLAY")
        return record[2]
    @property
    def plaintext(self):
        record = _PROFILE3_DATA_PREVIEWS.get(self)
        if record is None:
            _fail("REPLAY")
        return record[3]
    def __repr__(self):
        return "<Profile3DataPreview>"
    def _purge(self):
        _PROFILE3_DATA_PREVIEWS.pop(self, None)


def _profile3_data_fields(payload):
    typ, version, profile, body = decode(payload)
    if typ != 6 or version != 1 or profile != 3 or len(body) < 32:
        _decode_fail()
    counter, delivery_id = struct.unpack("!QQ", body[:16])
    if not 0 < delivery_id < 0xffffffffffffffff:
        _decode_fail()
    nonce(counter)
    return counter, delivery_id, body[16:]


def _profile3_data_header(header, payload, binding_budget):
    if not isinstance(header, Header):
        _decode_fail()
    try:
        packet = header.pack(payload, binding_budget)
    except WireError as error:
        category = getattr(error, "category", None)
        if category in ("BINDING_BUDGET", "PACKET_CAP"):
            _fail("BUDGET")
        if category == "TRUNCATED":
            _fail("TRUNCATED")
        if category == "TRAILING_BYTES":
            _fail("TRAILING_BYTES")
        _decode_fail()
    parsed, _ = parse_packet(packet, binding_budget)
    if (parsed.profile != 3 or parsed.nh != NH_SES or parsed.scid == 0
            or parsed.pslot not in (0, 1)
            or parsed.flags != (1 if parsed.pslot == 0 else 3)):
        _decode_fail()
    return packet[:48]


def _profile3_aad(header, counter, delivery_id):
    if type(delivery_id) is not int or not 0 < delivery_id < 0xffffffffffffffff:
        _decode_fail()
    return _aad(header, b"\x06\x01\x03\x00", counter) + struct.pack("!Q", delivery_id)


def _profile3_seal(key, header, counter, delivery_id, plaintext):
    return ChaCha20Poly1305(key).encrypt(nonce(counter), plaintext,
                                         _profile3_aad(header, counter, delivery_id))


def _profile3_open(key, header, counter, delivery_id, ciphertext):
    try:
        return ChaCha20Poly1305(key).decrypt(nonce(counter), ciphertext,
                                             _profile3_aad(header, counter, delivery_id))
    except InvalidTag:
        _fail("AUTH_FAILED")


def seal_profile3_data(session, header, delivery_id, plaintext, binding_budget=1280):
    """Seal one exact Profile-3 SESSION_DATA packet with an existing session."""
    if not isinstance(session, Session):
        _decode_fail()
    if type(delivery_id) is not int or not 0 < delivery_id < 0xffffffffffffffff:
        _decode_fail()
    try:
        plaintext = memoryview(plaintext).cast("B").tobytes()
    except (TypeError, ValueError):
        _decode_fail()
    prefix = b"\x06\x01\x03\x00"
    placeholder = prefix + struct.pack("!QQ", 1, delivery_id) + b"\0" * (len(plaintext) + 16)
    aad_header = _profile3_data_header(header, placeholder, binding_budget)
    core = _session_core(session)
    with core.lock:
        if core.released or core.key is None:
            _fail("UNEXPECTED_MESSAGE")
        if not 1 <= core.send_counter < 0xffffffffffffffff:
            _fail("COUNTER_EXHAUSTED")
        counter = core.send_counter
        ciphertext = _profile3_seal(
            core.key, aad_header, counter, delivery_id, plaintext)
        core.send_counter += 1
    return aad_header + prefix + struct.pack("!QQ", counter, delivery_id) + ciphertext


def preview_profile3_data(session, packet, binding_budget=1280):
    """Authenticate Profile-3 SESSION_DATA without marking its counter replayed."""
    if not isinstance(session, Session):
        _decode_fail()
    header, payload = parse_packet(packet, binding_budget)
    aad_header = _profile3_data_header(header, payload, binding_budget)
    counter, delivery_id, ciphertext = _profile3_data_fields(payload)
    core = _session_core(session)
    with core.lock:
        if core.released or core.key is None:
            _fail("UNEXPECTED_MESSAGE")
        if len(core.previews) >= 64:
            _fail("CAPACITY")
        generation = core.replay.preview(counter)
        plaintext = _profile3_open(
            core.key, aad_header, counter, delivery_id, ciphertext)
        session_preview = _DecryptPreview(
            session, generation, counter, _authority=_SESSION_PREVIEW_AUTHORITY)
        preview = Profile3DataPreview(
            session, session_preview, delivery_id, plaintext,
            _authority=_SESSION_PREVIEW_AUTHORITY)
        core.previews.add(session_preview)
        return preview


def commit_profile3_data(session, preview):
    """Mark a previously authenticated Profile-3 DATA counter and return its delivery."""
    if not isinstance(preview, Profile3DataPreview):
        _fail("REPLAY")
    record = _PROFILE3_DATA_PREVIEWS.get(preview)
    if not isinstance(session, Session) or record is None or record[0] is not session:
        _fail("REPLAY")
    session_preview, delivery_id, plaintext = record[1:]
    session.commit_decrypt(session_preview)
    return delivery_id, plaintext


def abort_profile3_data(session, preview):
    """Discard a Profile-3 DATA preview without changing replay state."""
    if not isinstance(preview, Profile3DataPreview):
        _fail("REPLAY")
    record = _PROFILE3_DATA_PREVIEWS.get(preview)
    if not isinstance(session, Session) or record is None or record[0] is not session:
        _fail("REPLAY")
    session.abort_decrypt(record[1])


_DATA_PREVIEWS = weakref.WeakKeyDictionary()

class _DataPreview:
    __slots__ = ("__weakref__",)
    def __init__(self, machine, session_preview, record, close, *, _authority=None):
        if _authority is not _SESSION_PREVIEW_AUTHORITY or self in _DATA_PREVIEWS:
            _fail("REPLAY")
        try:
            session_record = _DECRYPT_PREVIEWS.get(session_preview)
        except TypeError:
            _fail("REPLAY")
        expected_session = record.get("c2s") if type(record) is dict else record
        if (
            session_record is None
            or session_record[0] is not expected_session
            or session_record[3] is not None
        ):
            _fail("REPLAY")
        _DATA_PREVIEWS[self] = (machine, session_preview, record, bool(close))
        _DECRYPT_PREVIEWS[session_preview] = (*session_record[:3], self)
    def __repr__(self):
        return "<DataPreview>"
    def _purge(self):
        wrapper = _DATA_PREVIEWS.pop(self, None)
        if wrapper is not None:
            previews = getattr(wrapper[0], "_previews", None)
            if previews is not None:
                previews.discard(self)
    def _invalidate(self):
        self._purge()

def _allowed_locs(value, current):
    if value is None:
        return frozenset((current,))
    if not isinstance(value, (tuple, list, set, frozenset)) or not value:
        _fail("AUTH_FAILED")
    allowed = frozenset(value)
    if not all(isinstance(loc, ipaddress.IPv6Address) for loc in allowed):
        _fail("AUTH_FAILED")
    return allowed

def _loc(value):
    if not isinstance(value, ipaddress.IPv6Address):
        raise ValueError("location")
    return value
_PENDING_AUTHORITY = object()
_PENDING_CORES = weakref.WeakKeyDictionary()

class _PendingCore:
    __slots__ = (
        "scid", "binding", "client", "created", "cached_ack", "auth_packet",
        "transcript_hash", "c2s", "s2c", "prk", "accept_replay",
    )
    def __init__(
        self, scid, binding, client, created, cached_ack, auth_packet,
        transcript_hash, c2s, s2c, prk,
    ):
        self.scid = scid
        self.binding = binding
        self.client = client
        self.created = created
        self.cached_ack = cached_ack
        self.auth_packet = auth_packet
        self.transcript_hash = transcript_hash
        self.c2s = c2s
        self.s2c = s2c
        self.prk = prk
        self.accept_replay = ReplayWindow()

def _pending_core(record):
    core = _PENDING_CORES.get(record)
    if core is None:
        _fail("UNEXPECTED_MESSAGE")
    return core

class Pending(_Redacted):
    __slots__ = ("__weakref__",)
    def __init__(self, *, _authority=None):
        if _authority is not _PENDING_AUTHORITY or self in _PENDING_CORES:
            _fail("UNEXPECTED_MESSAGE")


@dataclass(frozen=True, repr=False)
class ServerConfig(_Redacted):
    identity: Identity
    peer_pin: PeerPin
    service_context: int
    server_context_id: int
    profile: int
    local_loc: ipaddress.IPv6Address
    peer_loc: ipaddress.IPv6Address
    binding_budget: int
    pending_limit: int
    established_limit: int

    def __post_init__(self):
        if (self.peer_pin.role != 1 or not 0 < self.service_context <= 0xffffffff
                or not 0 < self.server_context_id <= 0xffffffff or not 0 <= self.profile <= 3
                or not 48 <= self.binding_budget <= 1280 or not 1 <= self.pending_limit <= 256
                or not 1 <= self.established_limit <= 1024
                or not isinstance(self.local_loc, ipaddress.IPv6Address)
                or not isinstance(self.peer_loc, ipaddress.IPv6Address)):
            raise ValueError("invalid server configuration")

class ServerMachine:
    """Cookie-first server, configured with one fixed authenticated peer."""
    def __init__(self, config, boot_instance, current_cookie_key, prior_cookie_key,
                 prior_key_valid_until, clock, limiter):
        if len(boot_instance) != 16 or len(current_cookie_key) != 32:
            raise ValueError("server secrets")
        if prior_cookie_key is not None and len(prior_cookie_key) != 32:
            raise ValueError("prior cookie key")
        self.config, self.identity, self.peer_pin = config, config.identity, config.peer_pin
        self.service_context, self.identity_role = config.service_context, 2
        self.server_context_id, self.cookie_key = config.server_context_id, current_cookie_key
        self.prior_cookie_key, self.prior_key_valid_until = prior_cookie_key, prior_key_valid_until
        self.boot_instance, self.clock, self.limiter = boot_instance, clock, limiter
        self.pending_limit, self.established_limit = config.pending_limit, config.established_limit
        self.pending, self.established, self._lock, self._previews = {}, {}, threading.RLock(), set()
        self.local_loc, self.peer_loc = config.local_loc, config.peer_loc
    def rotate_cookie_key(self, new_key, now):
        if not isinstance(new_key, bytes) or len(new_key) != 32:
            raise ValueError("cookie key")
        self.prior_cookie_key = self.cookie_key
        self.prior_key_valid_until = now + 20
        self.cookie_key = new_key

    def _header(self, header, protected=False, allowed_sources=None, allowed_destinations=None):
        if (header.src not in _allowed_locs(allowed_sources, self.peer_loc)
                or header.dst not in _allowed_locs(allowed_destinations, self.local_loc)
                or header.profile != self.config.profile or header.scid == 0
                or header.pslot != 0 or header.flags != (1 if protected else 0)):
            _fail("AUTH_FAILED")
    def _response_header(self, scid, protected=False, source=None, destination=None):
        return Header(NH_SES, self.local_loc if source is None else _loc(source),
                      self.peer_loc if destination is None else _loc(destination),
                      profile=self.config.profile, flags=1 if protected else 0, scid=scid)

    def _cookies(self, binding, auth, scid, bucket):
        keys = [self.cookie_key]
        if self.prior_cookie_key is not None and self.clock() <= self.prior_key_valid_until:
            keys.append(self.prior_cookie_key)
        candidates = [cookie(key, binding, auth.sender_role, auth.receiver_role,
                      auth.service_context, scid, auth.sender_eid, auth.sender_public_key,
                      auth.sender_ephemeral, self.boot_instance, candidate_bucket,
                      self.server_context_id)
                      for key in keys for candidate_bucket in (bucket, bucket - 1)]
        return any(hmac.compare_digest(auth.cookie_value, candidate) for candidate in candidates)

    def receive_open_packet(self, packet, binding, bucket):
        if len(packet) > self.config.binding_budget: _fail("BUDGET")
        header, payload = parse_packet(packet, self.config.binding_budget)
        self._header(header)
        opening = Open.parse(payload)
        if opening.sender_role != self.peer_pin.role or opening.receiver_role != self.identity_role:
            _fail("ROLE_MISMATCH")
        if opening.service_context != self.service_context: _fail("SERVICE_MISMATCH")
        if opening.sender_public_key != self.peer_pin.public_key: _fail("PIN_MISMATCH")
        if opening.sender_eid != self.peer_pin.eid: _fail("EID_KEY_MISMATCH")
        validate_binding(binding)
        value = cookie(self.cookie_key, binding, opening.sender_role, opening.receiver_role,
                       opening.service_context, header.scid, opening.sender_eid, opening.sender_public_key,
                       opening.sender_ephemeral, self.boot_instance, bucket, self.server_context_id)
        response = VerifyCookie(opening.receiver_role, opening.sender_role, opening.service_context,
                                opening.sender_public_key, hashlib.sha256(opening.sender_ephemeral).digest(),
                                self.boot_instance, value).build(self.config.profile)
        reply = build_packet(self._response_header(header.scid), response, self.config.binding_budget)
        self.limiter.admit(binding, len(packet), len(reply))
        return reply

    def _discard_record(self, record):
        core = _pending_core(record)
        core.cached_ack = b""
        core.auth_packet = None
        core.transcript_hash = None
        core.c2s = None
        core.s2c = None
        core.prk = None
        core.accept_replay = None
    def _dispose_established(self, established):
        for preview in tuple(self._previews):
            record = _DATA_PREVIEWS.get(preview)
            if record is not None and record[2] is established:
                self._previews.remove(preview)
                preview._invalidate()
        established["c2s"].release()
        established["s2c"].release()
        self._discard_record(established["record"])
    def _expire(self, now):
        with self._lock:
            expired_pending = [
                key for key, record in self.pending.items()
                if now >= _pending_core(record).created + 5
            ]
            for key in expired_pending:
                self._discard_record(self.pending.pop(key))
            expired_established = [key for key, value in self.established.items() if now >= value["last"] + 120]
            for key in expired_established:
                self._dispose_established(self.established.pop(key))
    def expire(self):
        self._expire(self.clock())

    def receive_open_auth(
        self, packet, binding, current_bucket,
        server_ephemeral_secret=None, server_nonce=None, *, _authority=None,
    ):
        if len(packet) > self.config.binding_budget: _fail("BUDGET")
        binding_bytes = validate_binding(binding)
        header, payload = parse_packet(packet, self.config.binding_budget)
        self._header(header)
        auth = OpenAuth.parse(payload)
        self._expire(self.clock())
        existing = self.pending.get(header.scid)
        if existing is None:
            existing = self.established.get(header.scid, {}).get("record")
        if existing is not None:
            existing_core = _pending_core(existing)
            if (
                existing_core.binding == binding_bytes
                and existing_core.auth_packet == bytes(packet)
            ):
                return existing_core.cached_ack
            _fail("SCID_COLLISION")
        if _authority is _HANDSHAKE_MATERIAL_AUTHORITY:
            _exact(server_ephemeral_secret, 32)
            _exact(server_nonce, 32)
            server_ephemeral_secret, server_nonce = (
                bytes(server_ephemeral_secret), bytes(server_nonce))
        elif server_ephemeral_secret is not None or server_nonce is not None:
            _fail("UNEXPECTED_MESSAGE")
        else:
            server_ephemeral_secret, server_nonce = _random(32), _random(32)
        auth = OpenAuth.parse(payload)
        if auth.boot_instance != self.boot_instance or not self._cookies(binding, auth, header.scid, current_bucket):
            _fail("COOKIE_INVALID")
        if auth.sender_role != self.peer_pin.role or auth.receiver_role != self.identity_role:
            _fail("ROLE_MISMATCH")
        if auth.service_context != self.service_context:
            _fail("SERVICE_MISMATCH")
        if auth.sender_public_key != self.peer_pin.public_key:
            _fail("PIN_MISMATCH")
        if auth.sender_eid != self.peer_pin.eid:
            _fail("EID_KEY_MISMATCH")
        t0_placeholder = placeholder_t0(header.scid, auth.sender_role, auth.receiver_role,
            auth.service_context, auth.sender_eid, auth.sender_public_key, self.identity.eid,
            auth.sender_ephemeral, auth.sender_nonce, auth.boot_instance)
        verify_signature(auth.sender_public_key, b"R8 OPEN_AUTH v1", t0_placeholder, auth.signature)
        server_ephemeral = X25519PrivateKey.from_private_bytes(server_ephemeral_secret).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        shared = x25519(server_ephemeral_secret, auth.sender_ephemeral)
        t0 = transcript(header.scid, auth.sender_role, auth.receiver_role, auth.service_context,
            auth.sender_eid, auth.sender_public_key, self.identity.eid, self.identity.public,
            auth.sender_ephemeral, server_ephemeral, auth.sender_nonce, server_nonce, auth.boot_instance)
        signature = sign_open_ack(self.identity, t0)
        ack_payload = OpenAck(self.identity_role, auth.sender_role, self.service_context,
            self.identity.eid, self.identity.public, server_ephemeral, server_nonce, signature).build(self.config.profile)
        ack_packet = build_packet(self._response_header(header.scid), ack_payload, self.config.binding_budget)
        if len(self.pending) >= self.pending_limit:
            _fail("CAPACITY")
        thash = transcript_hash(t0, auth.signature, signature)
        record = Pending(_authority=_PENDING_AUTHORITY)
        _PENDING_CORES[record] = _PendingCore(
            header.scid,
            binding_bytes,
            Open(
                auth.sender_role, auth.receiver_role, auth.service_context,
                auth.sender_eid, auth.sender_public_key, auth.sender_ephemeral,
                auth.sender_nonce,
            ),
            self.clock(),
            ack_packet,
            bytes(packet),
            thash,
            key_schedule(shared, thash, 1, 2, self.config.profile, 0),
            key_schedule(shared, thash, 2, 1, self.config.profile, 0),
            key_prk(shared, thash) if self.config.profile == 3 else None,
        )
        self.pending[header.scid] = record
        return ack_packet
    def receive_protected(self, packet):
        if len(packet) > self.config.binding_budget: _fail("BUDGET")
        header, payload = parse_packet(packet, self.config.binding_budget)
        self._header(header, True)
        self._expire(self.clock())
        record = self.pending.get(header.scid)
        if record is None:
            record = self.established.get(header.scid, {}).get("record")
        if record is None:
            _fail("UNEXPECTED_MESSAGE")
        record_core = _pending_core(record)
        message = ProtectedMessage.parse(payload)
        if message.typ == 5:
            plaintext = open_sealed(
                record_core.c2s, packet[:48], payload[:4],
                message.counter, message.ciphertext)
            if (
                message.counter != 1
                or plaintext != b"R8 ACCEPT v1" + record_core.transcript_hash
            ):
                _fail("AUTH_FAILED")
            if header.scid in self.pending:
                if len(self.established) >= self.established_limit:
                    _fail("CAPACITY")
                record_core.accept_replay.check_and_mark(message.counter)
                self.pending.pop(header.scid)
                c2s_session = Session(record_core.c2s)
                _session_core(c2s_session).replay.check_and_mark(message.counter)
                self.established[header.scid] = {
                    "record": record,
                    "c2s": c2s_session,
                    "s2c": Session(record_core.s2c),
                    "last": self.clock(),
                }
            else:
                try:
                    record_core.accept_replay.check_and_mark(message.counter)
                except SessionError as error:
                    if error.category != "REPLAY":
                        raise
            return b""
        if message.typ not in (6, 7):
            _fail("UNEXPECTED_MESSAGE")
        plaintext, _, _, preview = self.preview_data(packet)
        self.commit_data(preview)
        return plaintext
    def preview_data(self, packet, allowed_sources=None, allowed_destinations=None):
        with self._lock:
            if len(packet) > self.config.binding_budget: _fail("BUDGET")
            header, payload = parse_packet(packet, self.config.binding_budget)
            self._header(header, True, allowed_sources, allowed_destinations)
            self._expire(self.clock())
            established = self.established.get(header.scid)
            if established is None: _fail("UNEXPECTED_MESSAGE")
            message = ProtectedMessage.parse(payload)
            if message.typ not in (6, 7) or message.profile != self.config.profile: _fail("UNEXPECTED_MESSAGE")
            if self.config.profile == 3 and message.typ == 6:
                _fail("UNEXPECTED_MESSAGE")
            plaintext, session_preview = established["c2s"].preview_decrypt(
                packet[:48], payload[:4], message.counter, message.ciphertext)
            if message.typ == 7:
                _exact(plaintext, 2)
            preview = _DataPreview(
                self, session_preview, established, message.typ == 7,
                _authority=_SESSION_PREVIEW_AUTHORITY)
            self._previews.add(preview)
            return plaintext, header, message, preview
    def commit_data(self, preview):
        with self._lock:
            now = self.clock()
            self._expire(now)
            if not isinstance(preview, _DataPreview):
                _fail("REPLAY")
            record = _DATA_PREVIEWS.get(preview)
            if (record is None or record[0] is not self or preview not in self._previews
                    or self.established.get(_pending_core(record[2]["record"]).scid) is not record[2]):
                self._previews.discard(preview)
                if record is not None:
                    preview._invalidate()
                _fail("REPLAY")
            session_preview, established, close = record[1:]
            try:
                established["c2s"].commit_decrypt(session_preview)
            except SessionError:
                self._previews.discard(preview)
                preview._invalidate()
                raise
            for stale in tuple(self._previews):
                stale_record = _DATA_PREVIEWS.get(stale)
                if stale_record is not None and stale_record[2] is established:
                    self._previews.remove(stale)
                    stale._invalidate()
            if close:
                self._dispose_established(
                    self.established.pop(_pending_core(established["record"]).scid))
            else:
                established["last"] = now
    def abort_data_preview(self, preview):
        with self._lock:
            if not isinstance(preview, _DataPreview):
                _fail("REPLAY")
            record = _DATA_PREVIEWS.get(preview)
            valid = (record is not None and record[0] is self and preview in self._previews
                     and self.established.get(_pending_core(record[2]["record"]).scid) is record[2])
            if not valid:
                if record is not None and record[0] is self:
                    self._previews.discard(preview)
                    preview._invalidate()
                _fail("REPLAY")
            record[2]["c2s"].abort_decrypt(record[1])
            self._previews.discard(preview)
            preview._invalidate()
    def promote_local_loc(self, loc):
        with self._lock:
            self.local_loc = _loc(loc)
    def promote_peer_loc(self, loc):
        with self._lock:
            self.peer_loc = _loc(loc)
    def take_profile3(self, scid):
        with self._lock:
            if self.config.profile != 3:
                _fail("UNEXPECTED_MESSAGE")
            established = self.established.get(scid)
            if (established is None or established["c2s"]._previews or established["s2c"]._previews
                    or any((_DATA_PREVIEWS.get(preview) or (None, None, None))[2] is established
                           for preview in self._previews)):
                _fail("UNEXPECTED_MESSAGE")
            record = established["record"]
            record_core = _pending_core(record)
            outbound, inbound = _move_session_pair(
                established["s2c"], established["c2s"])
            bootstrap = Profile3Bootstrap(
                scid, self.identity_role, self.local_loc, self.peer_loc,
                outbound, inbound, record_core.prk, record_core.transcript_hash,
                _authority=_PROFILE3_BOOTSTRAP_AUTHORITY)
            self.established.pop(scid)
            self._discard_record(record)
            return bootstrap

    def send_data(self, scid, data, close=False):
        return self.send_data_with_locs(scid, data, self.local_loc, self.peer_loc, close)
    def send_data_with_locs(self, scid, data, source, destination, close=False):
        with self._lock:
            established = self.established.get(scid)
            if established is None: _fail("UNEXPECTED_MESSAGE")
            if self.config.profile == 3 and not close:
                _fail("UNEXPECTED_MESSAGE")
            typ = 7 if close else 6
            plaintext = struct.pack("!H", data) if close and isinstance(data, int) else bytes(data)
            header = self._response_header(scid, True, source, destination)
            prefix = bytes((typ, 1, self.config.profile, 0))
            try:
                counter, ciphertext = established["s2c"].encrypt(
                    header.pack(prefix + struct.pack("!Q", 1) + b"\0" * (len(plaintext) + 16),
                                self.config.binding_budget)[:48], prefix, plaintext)
            except SessionError:
                discarded = self.established.pop(scid, None)
                if discarded is not None:
                    self._dispose_established(discarded)
                raise
            payload = ProtectedMessage(typ, self.config.profile, counter, ciphertext).build()
            established["last"] = self.clock()
            packet = build_packet(header, payload, self.config.binding_budget)
            if close:
                self._dispose_established(self.established.pop(scid))
            return packet
    def restart(self, boot_instance, current_cookie_key, prior_cookie_key=None, prior_key_valid_until=None):
        if len(boot_instance) != 16 or len(current_cookie_key) != 32:
            raise ValueError("server secrets")
        if prior_cookie_key is not None and len(prior_cookie_key) != 32:
            raise ValueError("prior cookie key")
        with self._lock:
            for record in self.pending.values():
                self._discard_record(record)
            for established in self.established.values():
                self._dispose_established(established)
            self.pending.clear()
            self.established.clear()
            self.boot_instance, self.cookie_key = boot_instance, current_cookie_key
            self.prior_cookie_key, self.prior_key_valid_until = prior_cookie_key, prior_key_valid_until
class PrevalidationLimiter:
    def __init__(self, clock, hash_key, max_sources=4096, window=20, burst=2000, refill=1000):
        if (len(hash_key) != 32 or type(max_sources) is not int or not 1 <= max_sources <= 4096
                or type(window) is not int or not 1 <= window <= 20
                or type(burst) is not int or not 1 <= burst <= 2000
                or type(refill) is not int or not 0 <= refill <= 1000):
            raise ValueError("limiter configuration")
        self.clock, self.hash_key, self.max_sources, self.window = clock, bytes(hash_key), max_sources, window
        self.burst, self.refill, self.tokens, self.updated, self.sources = burst, refill, burst, clock(), {}

    def _slot(self, source):
        encoded = source.encode() if isinstance(source, str) else source.encode()
        return hmac.new(self.hash_key, encoded, hashlib.sha256).digest()

    def admit(self, source, request_bytes, response_bytes):
        now = self.clock()
        if (type(now) not in (int, float) or now < self.updated
                or type(request_bytes) is not int or request_bytes < 0
                or type(response_bytes) is not int or response_bytes < 0):
            _fail("CAPACITY")
        elapsed = int(now - self.updated)
        if elapsed:
            self.tokens = min(self.burst, self.tokens + elapsed * self.refill)
            self.updated += elapsed
        self.sources = {key: value for key, value in self.sources.items()
                        if now - value[1] < self.window}
        slot = self._slot(source)
        if slot not in self.sources and len(self.sources) >= self.max_sources:
            _fail("CAPACITY")
        prior = self.sources.get(slot, (now, now, 0, 0))
        if now - prior[0] >= self.window:
            prior = (now, prior[1], 0, 0)
        requests, responses = prior[2] + request_bytes, prior[3] + response_bytes
        if response_bytes > request_bytes or responses > requests or self.tokens < 1:
            _fail("CAPACITY")
        self.tokens -= 1
        self.sources[slot] = (prior[0], now, requests, responses)

@dataclass(frozen=True, repr=False)
class OpenAuth(_Redacted):
    sender_role: int; receiver_role: int; service_context: int; sender_eid: bytes
    sender_public_key: bytes; sender_ephemeral: bytes; sender_nonce: bytes
    boot_instance: bytes; cookie_value: bytes; signature: bytes
    def build(self, profile=0):
        _roles(self.sender_role, self.receiver_role)
        return encode(3, profile, bytes((self.sender_role, self.receiver_role)) + struct.pack("!I", self.service_context) +
                      self.sender_eid + self.sender_public_key + self.sender_ephemeral + self.sender_nonce +
                      self.boot_instance + self.cookie_value + self.signature)
    @classmethod
    def parse(cls, payload):
        typ, _, _, body = decode(payload)
        if typ != 3: _decode_fail()
        _exact(body, 230); _roles(body[0], body[1])
        if eid(body[22:54]) != body[6:22]: _fail("EID_KEY_MISMATCH")
        return cls(body[0], body[1], struct.unpack("!I", body[2:6])[0], body[6:22], body[22:54],
                   body[54:86], body[86:118], body[118:134], body[134:166], body[166:230])

@dataclass(frozen=True, repr=False)
class OpenAck(_Redacted):
    sender_role: int; receiver_role: int; service_context: int; sender_eid: bytes
    sender_public_key: bytes; sender_ephemeral: bytes; sender_nonce: bytes; signature: bytes
    def build(self, profile=0):
        _roles(self.sender_role, self.receiver_role)
        return encode(4, profile, bytes((self.sender_role, self.receiver_role)) + struct.pack("!I", self.service_context) +
                      self.sender_eid + self.sender_public_key + self.sender_ephemeral + self.sender_nonce + self.signature)
    @classmethod
    def parse(cls, payload):
        typ, _, _, body = decode(payload)
        if typ != 4: _decode_fail()
        _exact(body, 182); _roles(body[0], body[1])
        if eid(body[22:54]) != body[6:22]: _fail("EID_KEY_MISMATCH")
        return cls(body[0], body[1], struct.unpack("!I", body[2:6])[0], body[6:22], body[22:54],
                   body[54:86], body[86:118], body[118:182])

@dataclass(frozen=True, repr=False)
class ProtectedMessage(_Redacted):
    typ: int; profile: int; counter: int; ciphertext: bytes
    def build(self):
        if self.typ not in (5, 6, 7): _decode_fail()
        nonce(self.counter)
        return encode(self.typ, self.profile, struct.pack("!Q", self.counter) + self.ciphertext)
    @classmethod
    def parse(cls, payload):
        typ, _, profile, body = decode(payload)
        if typ not in (5, 6, 7): _decode_fail()
        counter = struct.unpack("!Q", body[:8])[0]; nonce(counter)
        return cls(typ, profile, counter, body[8:])

_HANDSHAKE_MATERIAL_AUTHORITY = object()
_CLIENT_SECRETS = weakref.WeakKeyDictionary()

class _ClientSecrets:
    __slots__ = ("ephemeral_secret", "transcript_hash", "prk", "c2s", "s2c")
    def __init__(self):
        self.ephemeral_secret = None
        self.transcript_hash = None
        self.prk = None
        self.c2s = None
        self.s2c = None

def _client_secrets(client):
    secrets = _CLIENT_SECRETS.get(client)
    if secrets is None:
        _fail("UNEXPECTED_MESSAGE")
    return secrets

class ClientMachine:
    IDLE, COOKIE_WAIT, AUTH_WAIT, ESTABLISHED, RELEASED = range(5)
    def __init__(self, identity, server_pin, service_context, profile, source, destination, clock,
                 binding_budget=1280):
        if not 0 <= profile <= 3 or not 48 <= binding_budget <= 1280:
            raise ValueError("client configuration")
        self.identity, self.server_pin, self.service_context, self.profile = identity, server_pin, service_context, profile
        self.source, self.destination, self.local_loc, self.peer_loc = source, destination, source, destination
        self.clock, self.binding_budget, self.state, self._lock, self._previews = clock, binding_budget, self.IDLE, threading.RLock(), set()
        _CLIENT_SECRETS[self] = _ClientSecrets()
    def start(
        self, scid, ephemeral_secret=None, nonce_value=None, *,
        _authority=None,
    ):
        if self.state != self.IDLE or not 0 < scid <= 0xffffffffffffffff:
            _fail("UNEXPECTED_MESSAGE")
        if _authority is _HANDSHAKE_MATERIAL_AUTHORITY:
            _exact(ephemeral_secret, 32)
            _exact(nonce_value, 32)
            ephemeral_secret, nonce_value = bytes(ephemeral_secret), bytes(nonce_value)
        elif ephemeral_secret is not None or nonce_value is not None:
            _fail("UNEXPECTED_MESSAGE")
        else:
            ephemeral_secret, nonce_value = _random(32), _random(32)
        self.scid = scid
        _client_secrets(self).ephemeral_secret = ephemeral_secret
        self.ephemeral = X25519PrivateKey.from_private_bytes(ephemeral_secret).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.nonce_value, self.deadline = nonce_value, self.clock() + 5
        self.opening = Open(1, self.server_pin.role, self.service_context, self.identity.eid, self.identity.public, self.ephemeral, nonce_value)
        self.open_packet = build_packet(Header(NH_SES, self.source, self.destination, profile=self.profile, scid=scid), self.opening.build(self.profile), self.binding_budget)
        self.state = self.COOKIE_WAIT
        return self.open_packet
    def receive_verify(self, packet):
        retry = self.state == self.AUTH_WAIT
        if self.state not in (self.COOKIE_WAIT, self.AUTH_WAIT) or self.clock() >= self.deadline:
            self._release()
        try:
            header, payload = parse_packet(packet, self.binding_budget)
            if (header.scid != self.scid or header.src != self.destination or header.dst != self.source
                    or header.profile != self.profile or header.flags != 0 or header.pslot != 0):
                _fail("AUTH_FAILED")
            verify = VerifyCookie.parse(payload)
            if (verify.receiver_role != self.opening.receiver_role or verify.sender_role != self.opening.sender_role
                    or verify.service_context != self.opening.service_context
                    or verify.client_public_key != self.opening.sender_public_key
                    or eid(verify.client_public_key) != self.opening.sender_eid
                    or verify.ephemeral_hash != hashlib.sha256(self.opening.sender_ephemeral).digest()):
                _fail("AUTH_FAILED")
            if retry:
                if (verify.boot_instance != self.boot_instance or payload != self.verify_payload):
                    _fail("AUTH_FAILED")
                return self.auth_packet
            t0 = placeholder_t0(self.scid, self.opening.sender_role, self.opening.receiver_role,
                                self.opening.service_context, self.opening.sender_eid,
                                self.opening.sender_public_key, self.server_pin.eid,
                                self.opening.sender_ephemeral, self.opening.sender_nonce,
                                verify.boot_instance)
            auth = OpenAuth(self.opening.sender_role, self.opening.receiver_role,
                            self.opening.service_context, self.opening.sender_eid,
                            self.opening.sender_public_key, self.opening.sender_ephemeral,
                            self.opening.sender_nonce, verify.boot_instance, verify.cookie_value,
                            sign_open_auth(self.identity, t0))
            self.verify_payload, self.boot_instance, self.auth_payload = payload, verify.boot_instance, auth.build(self.profile)
            self.auth_packet = build_packet(Header(NH_SES, self.source, self.destination,
                                                   profile=self.profile, scid=self.scid),
                                            self.auth_payload, self.binding_budget)
            self.state = self.AUTH_WAIT
            return self.auth_packet
        except SessionError:
            if retry:
                _fail("AUTH_FAILED")
            self._release()
    def receive_ack(self, packet):
        if self.state == self.ESTABLISHED:
            if packet == self.ack_packet:
                return self.accept_packet
            self._release()
        if self.state != self.AUTH_WAIT or self.clock() >= self.deadline:
            self._release()
        try:
            header, payload = parse_packet(packet)
            if (header.scid != self.scid or header.src != self.destination
                    or header.dst != self.source or header.profile != self.profile
                    or header.flags != 0 or header.pslot != 0):
                self._release()
            if hasattr(self, "ack_payload"):
                if payload == self.ack_payload:
                    return self.accept_packet
                self._release()
            ack = OpenAck.parse(payload)
            if ack.sender_role != 2 or ack.receiver_role != 1:
                self._release()
            if ack.service_context != self.service_context:
                self._release()
            if ack.sender_eid != self.server_pin.eid or ack.sender_public_key != self.server_pin.public_key:
                self._release()
            t0 = transcript(self.scid, 1, 2, self.service_context, self.identity.eid,
                            self.identity.public, ack.sender_eid, ack.sender_public_key,
                            self.ephemeral, ack.sender_ephemeral, self.nonce_value,
                            ack.sender_nonce, self.boot_instance)
            verify_signature(ack.sender_public_key, b"R8 OPEN_ACK v1", t0, ack.signature)
            secrets = _client_secrets(self)
            shared = x25519(secrets.ephemeral_secret, ack.sender_ephemeral)
            client_signature = OpenAuth.parse(self.auth_payload).signature
            secrets.transcript_hash = transcript_hash(
                t0, client_signature, ack.signature)
            if self.profile == 3:
                secrets.prk = key_prk(shared, secrets.transcript_hash)
            secrets.c2s = key_schedule(
                shared, secrets.transcript_hash, 1, 2, self.profile, 0)
            secrets.s2c = key_schedule(
                shared, secrets.transcript_hash, 2, 1, self.profile, 0)
            prefix = bytes((5, 1, self.profile, 0))
            accept_header = Header(NH_SES, self.source, self.destination, profile=self.profile,
                                   flags=1, pslot=0, scid=self.scid)
            aad_header = accept_header.pack(prefix + struct.pack("!Q", 1) + b"\0" * 60)[:48]
            ciphertext = seal(
                secrets.c2s, aad_header, prefix, 1,
                b"R8 ACCEPT v1" + secrets.transcript_hash)
            self.accept_payload = ProtectedMessage(5, self.profile, 1, ciphertext).build()
            self.accept_packet = build_packet(accept_header, self.accept_payload)
            self.ack_payload = payload
            self.ack_packet = bytes(packet)
            self.c2s_session, self.s2c_session = (
                Session(secrets.c2s, 2), Session(secrets.s2c))
            self.state = self.ESTABLISHED
            return self.accept_packet
        except SessionError:
            if self.state != self.ESTABLISHED:
                self._release()
            raise
    def take_profile3(self):
        with self._lock:
            if (self.profile != 3 or self.state != self.ESTABLISHED or self._previews
                    or self.c2s_session._previews or self.s2c_session._previews):
                _fail("UNEXPECTED_MESSAGE")
            secrets = _client_secrets(self)
            outbound, inbound = _move_session_pair(
                self.c2s_session, self.s2c_session)
            bootstrap = Profile3Bootstrap(
                self.scid, 1, self.local_loc, self.peer_loc,
                outbound, inbound, secrets.prk, secrets.transcript_hash,
                _authority=_PROFILE3_BOOTSTRAP_AUTHORITY)
            self._clear_state(release_sessions=False)
            return bootstrap
    def _protected_header(self, outbound, source=None, destination=None):
        return Header(NH_SES, self.local_loc if outbound and source is None else
                      self.peer_loc if not outbound and source is None else _loc(source),
                      self.peer_loc if outbound and destination is None else
                      self.local_loc if not outbound and destination is None else _loc(destination),
                      profile=self.profile, flags=1, pslot=0, scid=self.scid)
    def send_data(self, data):
        return self.send_data_with_locs(data, self.local_loc, self.peer_loc)
    def send_data_with_locs(self, data, source, destination):
        with self._lock:
            if self.state != self.ESTABLISHED: _fail("UNEXPECTED_MESSAGE")
            if self.profile == 3:
                _fail("UNEXPECTED_MESSAGE")
            plaintext = bytes(data)
            prefix = bytes((6, 1, self.profile, 0))
            header = self._protected_header(True, source, destination)
            try:
                counter, ciphertext = self.c2s_session.encrypt(
                    header.pack(prefix + struct.pack("!Q", 1) + b"\0" * (len(plaintext) + 16),
                                self.binding_budget)[:48], prefix, plaintext)
            except SessionError:
                self._release()
            return build_packet(header, ProtectedMessage(6, self.profile, counter, ciphertext).build(),
                                self.binding_budget)
    def preview_data(self, packet, allowed_sources=None, allowed_destinations=None):
        with self._lock:
            if self.state != self.ESTABLISHED or self.clock() > self.deadline + 120:
                self._release()
            header, payload = parse_packet(packet, self.binding_budget)
            if (header.src not in _allowed_locs(allowed_sources, self.peer_loc)
                    or header.dst not in _allowed_locs(allowed_destinations, self.local_loc)
                    or header.scid != self.scid or header.profile != self.profile
                    or header.flags != 1 or header.pslot != 0):
                _fail("AUTH_FAILED")
            message = ProtectedMessage.parse(payload)
            if message.typ not in (6, 7) or message.profile != self.profile: _fail("UNEXPECTED_MESSAGE")
            if self.profile == 3 and message.typ == 6:
                _fail("UNEXPECTED_MESSAGE")
            plaintext, session_preview = self.s2c_session.preview_decrypt(
                packet[:48], payload[:4], message.counter, message.ciphertext)
            if message.typ == 7:
                _exact(plaintext, 2)
            preview = _DataPreview(
                self, session_preview, self.s2c_session, message.typ == 7,
                _authority=_SESSION_PREVIEW_AUTHORITY)
            self._previews.add(preview)
            return plaintext, header, message, preview
    def commit_data(self, preview):
        with self._lock:
            now = self.clock()
            if not isinstance(preview, _DataPreview):
                _fail("REPLAY")
            record = _DATA_PREVIEWS.get(preview)
            if (record is None or record[0] is not self or preview not in self._previews
                    or record[2] is not self.s2c_session):
                self._previews.discard(preview)
                if record is not None:
                    preview._invalidate()
                _fail("REPLAY")
            session_preview, session, close = record[1:]
            try:
                session.commit_decrypt(session_preview)
            except SessionError:
                self._previews.discard(preview)
                preview._invalidate()
                raise
            for stale in tuple(self._previews):
                stale_record = _DATA_PREVIEWS.get(stale)
                if stale_record is not None and stale_record[2] is session:
                    self._previews.remove(stale)
                    stale._invalidate()
            if close:
                self._clear_state()
            else:
                self.deadline = now
    def abort_data_preview(self, preview):
        with self._lock:
            if not isinstance(preview, _DataPreview):
                _fail("REPLAY")
            record = _DATA_PREVIEWS.get(preview)
            valid = (record is not None and record[0] is self and preview in self._previews
                     and record[2] is self.s2c_session)
            if not valid:
                if record is not None and record[0] is self:
                    self._previews.discard(preview)
                    preview._invalidate()
                _fail("REPLAY")
            record[2].abort_decrypt(record[1])
            self._previews.discard(preview)
            preview._invalidate()
    def receive_protected(self, packet):
        plaintext, _, _, preview = self.preview_data(packet)
        self.commit_data(preview)
        return plaintext
    def promote_local_loc(self, loc):
        with self._lock:
            self.local_loc = _loc(loc)
    def promote_peer_loc(self, loc):
        with self._lock:
            self.peer_loc = _loc(loc)

    def close(self, code):
        if self.state != self.ESTABLISHED or not isinstance(code, int) or not 0 <= code <= 65535:
            _fail("UNEXPECTED_MESSAGE")
        prefix = bytes((7, 1, self.profile, 0))
        header = self._protected_header(True)
        try:
            counter, ciphertext = self.c2s_session.encrypt(
                header.pack(prefix + struct.pack("!Q", 1) + b"\0" * 18, self.binding_budget)[:48],
                prefix, struct.pack("!H", code))
        except SessionError:
            self._release()
        packet = build_packet(header, ProtectedMessage(7, self.profile, counter, ciphertext).build(),
                              self.binding_budget)
        self._clear_state()
        return packet

    def expire(self):
        if self.state in (self.COOKIE_WAIT, self.AUTH_WAIT) and self.clock() >= self.deadline:
            self._release()
        if self.state == self.ESTABLISHED and self.clock() > self.deadline + 120:
            self._release()
        return self.state
    def _clear_state(self, release_sessions=True):
        with self._lock:
            self.state = self.RELEASED
            secrets = _client_secrets(self)
            secrets.ephemeral_secret = None
            secrets.transcript_hash = None
            secrets.prk = None
            secrets.c2s = None
            secrets.s2c = None
            for preview in tuple(self._previews):
                preview._invalidate()
            self._previews.clear()
            for name in ("c2s_session", "s2c_session"):
                session = getattr(self, name, None)
                if session is not None:
                    if release_sessions:
                        session.release()
                    else:
                        session._discard_previews()
            for name in ("ephemeral_secret", "ephemeral", "nonce_value", "opening", "open_packet",
                         "verify_payload", "boot_instance", "auth_payload", "auth_packet",
                         "ack_payload", "ack_packet", "accept_payload", "accept_packet",
                         "transcript_hash", "c2s", "s2c", "_profile3_prk", "c2s_session", "s2c_session"):
                if hasattr(self, name):
                    setattr(self, name, None)
    def _release(self):
        self._clear_state()
        _fail("AUTH_FAILED")

def _endpoint(text, allow_isolated=False, allow_zero=False):
    host, separator, port_text = text.rpartition(":")
    if not separator:
        raise ValueError("invalid endpoint")
    address = ipaddress.ip_address(host)
    port = int(port_text)
    if not (0 <= port <= 65535) or (port == 0 and not allow_zero):
        raise ValueError("invalid endpoint")
    if address.is_unspecified or address.is_multicast or address.is_reserved or str(address) == "255.255.255.255":
        raise ValueError("unsafe endpoint")
    private = (address.version == 4 and address in ipaddress.ip_network("10.0.0.0/8")
               or address.version == 4 and address in ipaddress.ip_network("172.16.0.0/12")
               or address.version == 4 and address in ipaddress.ip_network("192.168.0.0/16")
               or address.is_link_local)
    if not address.is_loopback and not (allow_isolated and private):
        raise ValueError("underlay endpoint rejected")
    return str(address), port


def _socket():
    if not sys.platform.startswith("linux"):
        raise RuntimeError("PMTU/DF unavailable")
    result = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    result.setsockopt(socket.IPPROTO_IP, 10, 2)
    return result


def _drop(error, length):
    category = error.category if isinstance(error, SessionError) else "AUTH_FAILED"
    print(f"[drop] {category} length={min(length, 1253)}", flush=True)


def _runtime_binding(endpoint, selector):
    return UdpBinding.from_endpoint(endpoint[0], endpoint[1], 1, selector)
def _udp_send(sock, packet, endpoint):
    try:
        sent = sock.sendto(packet, endpoint)
    except OSError as error:
        if error.errno == errno.EMSGSIZE:
            _fail("BUDGET")
        raise
    if sent != len(packet):
        raise OSError(errno.EIO, "short datagram send")




def _arguments():
    parser = argparse.ArgumentParser(prog="r8session")
    subcommands = parser.add_subparsers(dest="command", required=True)
    for name in ("serve", "connect"):
        command = subcommands.add_parser(name)
        command.add_argument("--local-seed-hex", required=True)
        command.add_argument("--peer-public-key-hex", required=True)
        command.add_argument("--service-context", type=int, required=True)
        command.add_argument("--server-context-id", type=int, required=True)
        command.add_argument("--address", required=True)
        command.add_argument("--peer-address", required=True)
        command.add_argument("--binding-budget", type=int, default=1252)
        command.add_argument("--timeout", type=float, default=5)
        command.add_argument("--allow-isolated-underlay", action="store_true")
        command.add_argument("--bind", default="127.0.0.1:52808" if name == "serve" else "127.0.0.1:0")
        if name == "serve":
            command.add_argument("--max-sessions", type=int, default=1)
        else:
            command.add_argument("--peer", required=True)
            command.add_argument("--message-hex", required=True)
            command.add_argument("--scid", type=int)
    return parser, parser.parse_args()


def _validated(args):
    try:
        seed, peer = bytes.fromhex(args.local_seed_hex), bytes.fromhex(args.peer_public_key_hex)
        if len(seed) != 32 or len(peer) != 32 or not 0 < args.service_context <= 0xffffffff:
            _fail("CONFIG_ERROR")
        if not 0 < args.server_context_id <= 0xffffffff or not 48 <= args.binding_budget <= 1252 or args.timeout <= 0:
            _fail("CONFIG_ERROR")
        local, remote = ipaddress.IPv6Address(args.address), ipaddress.IPv6Address(args.peer_address)
        bind = _endpoint(args.bind, args.allow_isolated_underlay, args.command == "connect")
        target = _endpoint(args.peer, args.allow_isolated_underlay) if args.command == "connect" else None
        if args.command == "serve" and args.max_sessions <= 0:
            _fail("CONFIG_ERROR")
        identity = Identity.from_seed(seed)
        pin = PeerPin(2 if args.command == "connect" else 1, eid(peer), peer)
        return identity, pin, local, remote, bind, target
    except (TypeError, ValueError):
        _fail("CONFIG_ERROR")


def _connect(args, identity, pin, local, remote, bind, target):
    message = bytes.fromhex(args.message_hex)
    scid = args.scid if args.scid is not None else int.from_bytes(_random(8), "big")
    if not 0 < scid <= 0xffffffffffffffff:
        raise ValueError("invalid arguments")
    client = ClientMachine(identity, pin, args.service_context, 0, local, remote, time.monotonic,
                           args.binding_budget)
    opened = client.start(scid)
    sock = _socket()
    sock.bind(bind)
    deadline = time.monotonic() + args.timeout
    packet, phase, attempts = opened, "open", 0
    while time.monotonic() < deadline and attempts < 3:
        _udp_send(sock, packet, target)
        wait = min((.5, 1, 2)[attempts], max(0, deadline - time.monotonic()))
        sock.settimeout(wait)
        attempts += 1
        try:
            incoming, endpoint = sock.recvfrom(args.binding_budget + 1)
            if endpoint != target or len(incoming) > args.binding_budget:
                continue
            if phase == "open":
                packet = client.receive_verify(incoming); phase = "auth"; attempts = 0
            elif phase == "auth":
                packet = client.receive_ack(incoming); phase = "accept"; attempts = 0
            else:
                break
        except (socket.timeout, SessionError):
            continue
        if phase == "accept":
            _udp_send(sock, packet, target)
            packet = client.send_data(message)
            _udp_send(sock, packet, target)
            phase = "data"
            attempts = 3
            break
    if phase != "data":
        raise SessionError("TIMEOUT")
    end = time.monotonic() + args.timeout
    while time.monotonic() < end:
        sock.settimeout(end - time.monotonic())
        try:
            incoming, endpoint = sock.recvfrom(args.binding_budget + 1)
            if endpoint != target or len(incoming) > args.binding_budget:
                continue
            reply = client.receive_protected(incoming)
            if reply == message:
                _udp_send(sock, client.close(0), target)
                print(f"exchange ok length={len(message)}", flush=True)
                return
        except (socket.timeout, SessionError):
            continue
    raise SessionError("TIMEOUT")


def _serve(args, identity, pin, local, remote, bind, unused_target):
    config = ServerConfig(identity, pin, args.service_context, args.server_context_id, 0, local, remote,
                          args.binding_budget, 256, args.max_sessions)
    now = time.monotonic
    server = ServerMachine(config, _random(16), _random(32), None, 0, now,
                           PrevalidationLimiter(now, _random(32)))
    admitted = {}
    sock = _socket()
    sock.bind(bind)
    deadline, completed = now() + args.timeout, 0
    next_rotation = now() + 600
    selector = _random(16)
    while now() < deadline and completed < args.max_sessions:
        sock.settimeout(deadline - now())
        try:
            incoming, endpoint = sock.recvfrom(args.binding_budget + 1)
            if len(incoming) > args.binding_budget:
                _fail("BUDGET")
            binding = _runtime_binding(endpoint, selector)
            while now() >= next_rotation:
                server.rotate_cookie_key(_random(32), next_rotation)
                next_rotation += 600
            header, payload = parse_packet(incoming, args.binding_budget)
            completed_exchange = False
            typ = decode(payload)[0]
            if typ == 1:
                response = server.receive_open_packet(incoming, binding, int(now() // 10))
            elif typ == 3:
                response = server.receive_open_auth(incoming, binding, int(now() // 10))
                admitted[header.scid] = (endpoint, binding)
            else:
                expected = admitted.get(header.scid)
                if expected != (endpoint, binding):
                    _fail("AUTH_FAILED")
                delivered = server.receive_protected(incoming)
                if typ == 5:
                    response = None
                elif typ == 6:
                    response = server.send_data(header.scid, delivered)
                    completed_exchange = True
                    admitted.pop(header.scid, None)
                else:
                    response = None
                    admitted.pop(header.scid, None)
            if response is not None:
                _udp_send(sock, response, endpoint)
                if completed_exchange:
                    completed += 1
            server.expire()
        except socket.timeout:
            break
        except (SessionError, ValueError) as error:
            _drop(error, len(locals().get("incoming", b"")))
    if completed < args.max_sessions:
        raise SessionError("TIMEOUT")
    print("[r8session] established", flush=True)


def main():
    parser, args = _arguments()
    try:
        identity, pin, local, remote, bind, target = _validated(args)
        if args.command == "connect":
            _connect(args, identity, pin, local, remote, bind, target)
        else:
            _serve(args, identity, pin, local, remote, bind, target)
    except (ValueError, SessionError, OSError, RuntimeError):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
