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
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from r8ref import Header, NH_SES

ERRORS = frozenset((
    "ROLE_MISMATCH", "SERVICE_MISMATCH", "PIN_MISMATCH", "EID_KEY_MISMATCH",
    "COOKIE_INVALID", "AUTH_FAILED", "COUNTER_RANGE", "COUNTER_EXHAUSTED",
    "REPLAY", "TRUNCATED", "TRAILING_BYTES", "SCID_COLLISION", "CAPACITY",
    "RESTART_REQUIRED", "UNEXPECTED_MESSAGE", "TIMEOUT", "BUDGET",
    "BINDING_INVALID", "CONFIG_ERROR", "RNG_FAILURE",
))

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

@dataclass(frozen=True)
class Identity:
    private: Ed25519PrivateKey
    public: bytes
    eid: bytes
    @classmethod
    def from_seed(cls, seed):
        if len(seed) != 32: raise ValueError("seed must be 32 bytes")
        private = Ed25519PrivateKey.from_private_bytes(seed)
        public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return cls(private, public, eid(public))

@dataclass(frozen=True)
class PeerPin:
    role: int
    eid: bytes
    public_key: bytes
    def __post_init__(self):
        if self.role not in (1, 2) or len(self.eid) != 16 or len(self.public_key) != 32 or eid(self.public_key) != self.eid:
            raise ValueError("invalid complete peer pin")

@dataclass(frozen=True)
class UdpBinding:
    address: bytes
    port: int
    selector_kind: int
    selector: bytes

    def encode(self):
        if self.selector_kind not in (1, 2) or len(self.selector) != 16 or not 1 <= self.port <= 65535:
            _fail("BINDING_INVALID")
        try: ip = ipaddress.ip_address(self.address)
        except ValueError: _fail("BINDING_INVALID")
        family = b"\x01\x04" if ip.version == 4 else b"\x01\x06"
        return family + ip.packed + struct.pack("!H", self.port) + bytes((self.selector_kind,)) + self.selector

    @classmethod
    def from_endpoint(cls, host, port, selector_kind, selector):
        try:
            return cls(ipaddress.ip_address(host).packed, port, selector_kind, bytes(selector))
        except (ValueError, TypeError):
            _fail("BINDING_INVALID")

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
    except Exception as error:
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


@dataclass(frozen=True)
class Open:
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


@dataclass(frozen=True)
class VerifyCookie:
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
    return (b"R8 cookie v1" + binding.encode() + bytes((8, 1, client_role, server_role)) +
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
def key_schedule(shared, thash, sender_role, receiver_role, profile=0, slot=0):
    if sender_role not in (1, 2) or receiver_role not in (1, 2) or not 0 <= profile <= 3 or slot not in (0, 1):
        _fail("AUTH_FAILED")
    info = b"R8 key v1" + bytes((8, 1, profile)) + thash + bytes((sender_role, receiver_role, slot))
    return HKDFExpand(algorithm=SHA256(), length=32, info=info).derive(key_prk(shared, thash))
def nonce(counter):
    if not 1 <= counter <= 0xffffffffffffffff: _fail("COUNTER_RANGE")
    return b"\0\0\0\0" + struct.pack("!Q", counter)
def seal(key, header, prefix, counter, plaintext):
    return ChaCha20Poly1305(key).encrypt(nonce(counter), plaintext, header + prefix + struct.pack("!Q", counter))
def open_sealed(key, header, prefix, counter, ciphertext):
    try: return ChaCha20Poly1305(key).decrypt(nonce(counter), ciphertext, header + prefix + struct.pack("!Q", counter))
    except InvalidTag: _fail("AUTH_FAILED")

class ReplayWindow:
    def __init__(self):
        self.highest = 0
        self.bits = 0
        self.generation = 0
    def preview(self, counter):
        if counter == 0: _fail("COUNTER_RANGE")
        if self.highest and counter > self.highest + 1048576: _fail("REPLAY")
        if counter <= self.highest:
            distance = self.highest - counter
            if distance >= 1024 or self.bits & (1 << distance): _fail("REPLAY")
        return self.generation
    def check_and_mark(self, counter):
        self.preview(counter)
        if counter > self.highest:
            shift = counter - self.highest
            self.highest, self.bits = counter, (1 if shift >= 1024 else
                ((self.bits << shift) | 1) & ((1 << 1024) - 1))
        else:
            self.bits |= 1 << (self.highest - counter)
        self.generation += 1

class _DecryptPreview:
    __slots__ = ("_session", "_generation", "_counter", "_used")
    def __init__(self, session, generation, counter):
        self._session, self._generation, self._counter, self._used = session, generation, counter, False
    def __repr__(self):
        return "<DecryptPreview>"

class Session:
    def __init__(self, key, send_counter=1):
        self.key, self.send_counter, self.replay = key, send_counter, ReplayWindow()
        self._lock, self._previews = threading.RLock(), set()
    def encrypt(self, header, prefix, plaintext):
        with self._lock:
            if self.send_counter > 0xffffffffffffffff: _fail("COUNTER_EXHAUSTED")
            counter = self.send_counter; self.send_counter += 1
            return counter, seal(self.key, header, prefix, counter, plaintext)
    def preview_decrypt(self, header, prefix, counter, ciphertext):
        with self._lock:
            if len(self._previews) >= 64: _fail("CAPACITY")
            generation = self.replay.preview(counter)
            plaintext = open_sealed(self.key, header, prefix, counter, ciphertext)
            preview = _DecryptPreview(self, generation, counter)
            self._previews.add(preview)
            return plaintext, preview
    def commit_decrypt(self, preview):
        with self._lock:
            if (not isinstance(preview, _DecryptPreview) or preview._session is not self
                    or preview._used or preview not in self._previews
                    or preview._generation != self.replay.generation):
                self._previews.discard(preview)
                _fail("REPLAY")
            self.replay.check_and_mark(preview._counter)
            for stale in self._previews:
                stale._used = True
            self._previews.clear()
    def abort_decrypt(self, preview):
        with self._lock:
            valid = (isinstance(preview, _DecryptPreview) and preview._session is self
                     and not preview._used and preview in self._previews
                     and preview._generation == self.replay.generation)
            if not valid:
                if isinstance(preview, _DecryptPreview) and preview._session is self:
                    self._previews.discard(preview)
                    preview._used = True
                _fail("REPLAY")
            self._previews.remove(preview)
            preview._used = True
    def _discard_previews(self):
        with self._lock:
            for preview in self._previews:
                preview._used = True
            self._previews.clear()
    def decrypt(self, header, prefix, counter, ciphertext):
        with self._lock:
            plaintext, preview = self.preview_decrypt(header, prefix, counter, ciphertext)
            self.commit_decrypt(preview)
            return plaintext
class _DataPreview:
    __slots__ = ("_machine", "_session_preview", "_record", "_close", "_used")
    def __init__(self, machine, session_preview, record, close):
        self._machine, self._session_preview = machine, session_preview
        self._record, self._close, self._used = record, close, False
    def __repr__(self):
        return "<DataPreview>"

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
@dataclass
class Pending:
    scid: int
    binding: UdpBinding
    client: Open
    created: float
    cached_ack: bytes


@dataclass(frozen=True)
class ServerConfig:
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
                or not 48 <= self.binding_budget <= 1280 or self.pending_limit < 1
                or self.established_limit < 1 or not isinstance(self.local_loc, ipaddress.IPv6Address)
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
        record.cached_ack = b""
        for name in ("auth_packet", "hash", "c2s", "s2c", "accept_replay"):
            if hasattr(record, name):
                setattr(record, name, None)
    def _dispose_established(self, established):
        for preview in tuple(self._previews):
            if preview._record is established:
                self._previews.remove(preview)
                preview._used = True
        established["c2s"]._discard_previews()
        established["s2c"]._discard_previews()
        self._discard_record(established["record"])
    def _expire(self, now):
        with self._lock:
            expired_pending = [key for key, record in self.pending.items() if now >= record.created + 5]
            for key in expired_pending:
                self._discard_record(self.pending.pop(key))
            expired_established = [key for key, value in self.established.items() if now >= value["last"] + 120]
            for key in expired_established:
                self._dispose_established(self.established.pop(key))
    def expire(self):
        self._expire(self.clock())

    def receive_open_auth(self, packet, binding, current_bucket, server_ephemeral_secret, server_nonce):
        if len(packet) > self.config.binding_budget: _fail("BUDGET")
        header, payload = parse_packet(packet, self.config.binding_budget)
        self._header(header)
        auth = OpenAuth.parse(payload)
        self._expire(self.clock())
        existing = self.pending.get(header.scid)
        if existing is None:
            existing = self.established.get(header.scid, {}).get("record")
        if existing is not None:
            if existing.binding == binding and existing.auth_packet == bytes(packet):
                return existing.cached_ack
            _fail("SCID_COLLISION")
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
        record = Pending(header.scid, binding, Open(auth.sender_role, auth.receiver_role,
            auth.service_context, auth.sender_eid, auth.sender_public_key, auth.sender_ephemeral,
            auth.sender_nonce), self.clock(), ack_packet)
        record.auth_packet, record.hash, record.c2s, record.s2c = bytes(packet), thash, key_schedule(shared, thash, 1, 2), key_schedule(shared, thash, 2, 1)
        record.accept_replay = ReplayWindow()
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
        message = ProtectedMessage.parse(payload)
        if message.typ == 5:
            plaintext = open_sealed(record.c2s, packet[:48], payload[:4], message.counter, message.ciphertext)
            if message.counter != 1 or plaintext != b"R8 ACCEPT v1" + record.hash:
                _fail("AUTH_FAILED")
            if header.scid in self.pending:
                if len(self.established) >= self.established_limit:
                    _fail("CAPACITY")
                record.accept_replay.check_and_mark(message.counter)
                self.pending.pop(header.scid)
                self.established[header.scid] = {"record": record, "c2s": Session(record.c2s),
                                                 "s2c": Session(record.s2c), "last": self.clock()}
            else:
                try:
                    record.accept_replay.check_and_mark(message.counter)
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
            plaintext, session_preview = established["c2s"].preview_decrypt(
                packet[:48], payload[:4], message.counter, message.ciphertext)
            if message.typ == 7:
                _exact(plaintext, 2)
            preview = _DataPreview(self, session_preview, established, message.typ == 7)
            self._previews.add(preview)
            return plaintext, header, message, preview
    def commit_data(self, preview):
        with self._lock:
            self._expire(self.clock())
            if (not isinstance(preview, _DataPreview) or preview._machine is not self
                    or preview._used or preview not in self._previews
                    or self.established.get(preview._record["record"].scid) is not preview._record):
                self._previews.discard(preview)
                _fail("REPLAY")
            try:
                preview._record["c2s"].commit_decrypt(preview._session_preview)
            except SessionError:
                self._previews.discard(preview)
                preview._used = True
                raise
            for stale in self._previews:
                if stale._session_preview._session is preview._record["c2s"]:
                    stale._used = True
            self._previews = {stale for stale in self._previews
                              if stale._session_preview._session is not preview._record["c2s"]}
            if preview._close:
                self._dispose_established(self.established.pop(preview._record["record"].scid))
            else:
                preview._record["last"] = self.clock()
    def abort_data_preview(self, preview):
        with self._lock:
            valid = (isinstance(preview, _DataPreview) and preview._machine is self
                     and not preview._used and preview in self._previews
                     and self.established.get(preview._record["record"].scid) is preview._record)
            if not valid:
                if isinstance(preview, _DataPreview) and preview._machine is self:
                    self._previews.discard(preview)
                    preview._used = True
                _fail("REPLAY")
            preview._record["c2s"].abort_decrypt(preview._session_preview)
            self._previews.remove(preview)
            preview._used = True
    def promote_local_loc(self, loc):
        with self._lock:
            self.local_loc = _loc(loc)
    def promote_peer_loc(self, loc):
        with self._lock:
            self.peer_loc = _loc(loc)

    def send_data(self, scid, data, close=False):
        return self.send_data_with_locs(scid, data, self.local_loc, self.peer_loc, close)
    def send_data_with_locs(self, scid, data, source, destination, close=False):
        with self._lock:
            established = self.established.get(scid)
            if established is None: _fail("UNEXPECTED_MESSAGE")
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
        if len(hash_key) != 32: raise ValueError("limiter hash key")
        self.clock, self.hash_key, self.max_sources, self.window = clock, bytes(hash_key), max_sources, window
        self.burst, self.refill, self.tokens, self.updated, self.sources = burst, refill, burst, clock(), {}

    def _slot(self, source):
        encoded = source.encode() if isinstance(source, str) else source.encode()
        return hmac.new(self.hash_key, encoded, hashlib.sha256).digest()

    def admit(self, source, request_bytes, response_bytes):
        now = self.clock()
        self.tokens = min(self.burst, self.tokens + (now - self.updated) * self.refill)
        self.updated = now
        self.sources = {key: value for key, value in self.sources.items() if now - value[0] <= self.window}
        slot = self._slot(source)
        if slot not in self.sources and len(self.sources) >= self.max_sources:
            oldest = min(self.sources.items(), key=lambda item: (item[1][0], item[0]))[0]
            del self.sources[oldest]
        prior = self.sources.get(slot, (now, 0, 0))
        if response_bytes > request_bytes or prior[2] + response_bytes > prior[1] + request_bytes or self.tokens < 1:
            _fail("CAPACITY")
        self.tokens -= 1
        self.sources[slot] = (now, prior[1] + request_bytes, prior[2] + response_bytes)

@dataclass(frozen=True)
class OpenAuth:
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

@dataclass(frozen=True)
class OpenAck:
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

@dataclass(frozen=True)
class ProtectedMessage:
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

class ClientMachine:
    IDLE, COOKIE_WAIT, AUTH_WAIT, ESTABLISHED, RELEASED = range(5)
    def __init__(self, identity, server_pin, service_context, profile, source, destination, clock,
                 binding_budget=1280):
        if not 0 <= profile <= 3 or not 48 <= binding_budget <= 1280:
            raise ValueError("client configuration")
        self.identity, self.server_pin, self.service_context, self.profile = identity, server_pin, service_context, profile
        self.source, self.destination, self.local_loc, self.peer_loc = source, destination, source, destination
        self.clock, self.binding_budget, self.state, self._lock, self._previews = clock, binding_budget, self.IDLE, threading.RLock(), set()
    def start(self, scid, ephemeral_secret, nonce_value):
        if self.state != self.IDLE or not 0 < scid <= 0xffffffffffffffff or len(ephemeral_secret) != 32 or len(nonce_value) != 32: _fail("UNEXPECTED_MESSAGE")
        self.scid, self.ephemeral_secret = scid, ephemeral_secret
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
            shared = x25519(self.ephemeral_secret, ack.sender_ephemeral)
            client_signature = OpenAuth.parse(self.auth_payload).signature
            self.transcript_hash = transcript_hash(t0, client_signature, ack.signature)
            self.c2s = key_schedule(shared, self.transcript_hash, 1, 2, self.profile)
            self.s2c = key_schedule(shared, self.transcript_hash, 2, 1, self.profile)
            prefix = bytes((5, 1, self.profile, 0))
            accept_header = Header(NH_SES, self.source, self.destination, profile=self.profile,
                                   flags=1, pslot=0, scid=self.scid)
            aad_header = accept_header.pack(prefix + struct.pack("!Q", 1) + b"\0" * 60)[:48]
            ciphertext = seal(self.c2s, aad_header, prefix, 1,
                              b"R8 ACCEPT v1" + self.transcript_hash)
            self.accept_payload = ProtectedMessage(5, self.profile, 1, ciphertext).build()
            self.accept_packet = build_packet(accept_header, self.accept_payload)
            self.ack_payload = payload
            self.ack_packet = bytes(packet)
            self.c2s_session, self.s2c_session = Session(self.c2s, 2), Session(self.s2c)
            self.state = self.ESTABLISHED
            return self.accept_packet
        except SessionError:
            if self.state != self.ESTABLISHED:
                self._release()
            raise
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
            plaintext, session_preview = self.s2c_session.preview_decrypt(
                packet[:48], payload[:4], message.counter, message.ciphertext)
            if message.typ == 7:
                _exact(plaintext, 2)
            preview = _DataPreview(self, session_preview, self.s2c_session, message.typ == 7)
            self._previews.add(preview)
            return plaintext, header, message, preview
    def commit_data(self, preview):
        with self._lock:
            if (not isinstance(preview, _DataPreview) or preview._machine is not self
                    or preview._used or preview not in self._previews
                    or preview._record is not self.s2c_session):
                self._previews.discard(preview)
                _fail("REPLAY")
            try:
                self.s2c_session.commit_decrypt(preview._session_preview)
            except SessionError:
                self._previews.discard(preview)
                preview._used = True
                raise
            for stale in self._previews:
                if stale._session_preview._session is self.s2c_session:
                    stale._used = True
            self._previews = {stale for stale in self._previews
                              if stale._session_preview._session is not self.s2c_session}
            if preview._close:
                self._clear_state()
            else:
                self.deadline = self.clock()
    def abort_data_preview(self, preview):
        with self._lock:
            valid = (isinstance(preview, _DataPreview) and preview._machine is self
                     and not preview._used and preview in self._previews
                     and preview._record is self.s2c_session)
            if not valid:
                if isinstance(preview, _DataPreview) and preview._machine is self:
                    self._previews.discard(preview)
                    preview._used = True
                _fail("REPLAY")
            self.s2c_session.abort_decrypt(preview._session_preview)
            self._previews.remove(preview)
            preview._used = True
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
    def _clear_state(self):
        with self._lock:
            self.state = self.RELEASED
            for preview in self._previews:
                preview._used = True
            self._previews.clear()
            for name in ("c2s_session", "s2c_session"):
                session = getattr(self, name, None)
                if session is not None:
                    session._discard_previews()
            for name in ("ephemeral_secret", "ephemeral", "nonce_value", "opening", "open_packet",
                         "verify_payload", "boot_instance", "auth_payload", "auth_packet",
                         "ack_payload", "ack_packet", "accept_payload", "accept_packet",
                         "transcript_hash", "c2s", "s2c", "c2s_session", "s2c_session"):
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
    opened = client.start(scid, _random(32), _random(32))
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
                response = server.receive_open_auth(incoming, binding, int(now() // 10), _random(32), _random(32))
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
