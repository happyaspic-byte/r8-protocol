//! Strict R8 session-security v0.1 framing and cryptographic foundation.
//! No credential defaults, fallback modes, or custom cryptographic primitives.

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce, Tag,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use r8_proto::{Header, HEADER_LEN};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub const WIRE_VERSION: u8 = 8;
pub const SESSION_VERSION: u8 = 1;
pub const OPEN: u8 = 1;
pub const VERIFY_COOKIE: u8 = 2;
pub const OPEN_AUTH: u8 = 3;
pub const OPEN_ACK: u8 = 4;
pub const SESSION_ACCEPT: u8 = 5;
pub const SESSION_DATA: u8 = 6;
pub const CLOSE: u8 = 7;
pub const REPLAY_WINDOW: u64 = 1024;
pub const REPLAY_JUMP_MAX: u64 = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    Truncated,
    TrailingBytes,
    Type,
    Version,
    Profile,
    Flags,
    RoleMismatch,
    ServiceMismatch,
    PinMismatch,
    EidKeyMismatch,
    CookieInvalid,
    AuthFailed,
    CounterRange,
    CounterExhausted,
    Replay,
    ScidCollision,
    Capacity,
    RestartRequired,
    Timeout,
    UnexpectedMessage,
    Budget,
    Binding,
    RngFailure,
    ConfigError,
}

impl SessionError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Truncated => "TRUNCATED",
            Self::TrailingBytes => "TRAILING_BYTES",
            Self::Type => "TYPE",
            Self::Version => "VERSION",
            Self::Profile => "PROFILE",
            Self::Flags => "FLAGS",
            Self::RoleMismatch => "ROLE_MISMATCH",
            Self::ServiceMismatch => "SERVICE_MISMATCH",
            Self::PinMismatch => "PIN_MISMATCH",
            Self::EidKeyMismatch => "EID_KEY_MISMATCH",
            Self::CookieInvalid => "COOKIE_INVALID",
            Self::AuthFailed => "AUTH_FAILED",
            Self::CounterRange => "COUNTER_RANGE",
            Self::CounterExhausted => "COUNTER_EXHAUSTED",
            Self::Replay => "REPLAY",
            Self::ScidCollision => "SCID_COLLISION",
            Self::Capacity => "CAPACITY",
            Self::RestartRequired => "RESTART_REQUIRED",
            Self::Timeout => "TIMEOUT",
            Self::UnexpectedMessage => "UNEXPECTED_MESSAGE",
            Self::Budget => "BUDGET",
            Self::Binding => "BINDING_INVALID",
            Self::ConfigError => "CONFIG_ERROR",
            Self::RngFailure => "RNG_FAILURE",
        }
    }
}
impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::error::Error for SessionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub role: u8,
    pub service_context: u32,
    pub eid: [u8; 16],
    pub public_key: [u8; 32],
}
impl Identity {
    pub fn from_public_key(
        role: u8,
        service_context: u32,
        public_key: [u8; 32],
    ) -> Result<Self, SessionError> {
        if !matches!(role, 1 | 2) || service_context == 0 {
            return Err(SessionError::ConfigError);
        }
        Ok(Self {
            role,
            service_context,
            eid: eid(&public_key),
            public_key,
        })
    }
    pub fn validate(&self) -> Result<(), SessionError> {
        if !matches!(self.role, 1 | 2) {
            return Err(SessionError::RoleMismatch);
        }
        if self.service_context == 0 {
            return Err(SessionError::ServiceMismatch);
        }
        if !bool::from(eid(&self.public_key).ct_eq(&self.eid)) {
            return Err(SessionError::EidKeyMismatch);
        }
        Ok(())
    }
}

pub fn eid(public_key: &[u8; 32]) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"R8 EID v1");
    hash.update(public_key);
    hash.finalize()[..16]
        .try_into()
        .expect("SHA-256 has 32 bytes")
}

/// Canonical typed UDP binding from the mobility specification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpBinding(Vec<u8>);

impl UdpBinding {
    pub fn ipv4(
        address: [u8; 4],
        port: u16,
        selector_kind: u8,
        selector: [u8; 16],
    ) -> Result<Self, SessionError> {
        if port == 0 || !matches!(selector_kind, 1 | 2) {
            return Err(SessionError::Binding);
        }
        let mut bytes = vec![0; 25];
        bytes[0] = 1;
        bytes[1] = 4;
        bytes[2..6].copy_from_slice(&address);
        bytes[6..8].copy_from_slice(&port.to_be_bytes());
        bytes[8] = selector_kind;
        bytes[9..].copy_from_slice(&selector);
        Ok(Self(bytes))
    }

    pub fn ipv6(
        address: [u8; 16],
        port: u16,
        selector_kind: u8,
        selector: [u8; 16],
    ) -> Result<Self, SessionError> {
        if port == 0 || !matches!(selector_kind, 1 | 2) {
            return Err(SessionError::Binding);
        }
        let mut bytes = Vec::with_capacity(37);
        bytes.extend_from_slice(&[1, 6]);
        bytes.extend_from_slice(&address);
        bytes.extend_from_slice(&port.to_be_bytes());
        bytes.push(selector_kind);
        bytes.extend_from_slice(&selector);
        Ok(Self(bytes))
    }

    pub fn parse(bytes: Vec<u8>) -> Result<Self, SessionError> {
        let valid = match bytes.as_slice() {
            [1, 4, _, _, _, _, port_hi, port_lo, selector_kind, ..]
                if bytes.len() == 25
                    && u16::from_be_bytes([*port_hi, *port_lo]) != 0
                    && matches!(*selector_kind, 1 | 2) =>
            {
                true
            }
            [1, 6, ..]
                if bytes.len() == 37
                    && u16::from_be_bytes([bytes[18], bytes[19]]) != 0
                    && matches!(bytes[20], 1 | 2) =>
            {
                true
            }
            _ => false,
        };
        if !valid {
            return Err(SessionError::Binding);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionMessage {
    pub typ: u8,
    pub profile: u8,
    pub body: Vec<u8>,
}
impl SessionMessage {
    pub fn decode(payload: &[u8], header_profile: u8, budget: usize) -> Result<Self, SessionError> {
        if payload.len() > budget {
            return Err(SessionError::Budget);
        }
        if payload.len() < 4 {
            return Err(SessionError::Truncated);
        }
        let typ = payload[0];
        if !matches!(typ, OPEN..=CLOSE) {
            return Err(SessionError::Type);
        }
        if payload[1] != SESSION_VERSION {
            return Err(SessionError::Version);
        }
        if payload[2] != header_profile {
            return Err(SessionError::Profile);
        }
        if payload[3] != 0 {
            return Err(SessionError::Flags);
        }
        let body = &payload[4..];
        validate_body(typ, body)?;
        Ok(Self {
            typ,
            profile: payload[2],
            body: body.to_vec(),
        })
    }
    pub fn encode(&self, budget: usize) -> Result<Vec<u8>, SessionError> {
        validate_body(self.typ, &self.body)?;
        let len = 4usize
            .checked_add(self.body.len())
            .ok_or(SessionError::Budget)?;
        if len > budget {
            return Err(SessionError::Budget);
        }
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(&[self.typ, SESSION_VERSION, self.profile, 0]);
        out.extend_from_slice(&self.body);
        Ok(out)
    }
}

fn validate_role_pair(body: &[u8]) -> Result<(), SessionError> {
    if !matches!(body[0], 1 | 2) || !matches!(body[1], 1 | 2) || body[0] == body[1] {
        Err(SessionError::RoleMismatch)
    } else {
        Ok(())
    }
}
fn validate_body(typ: u8, body: &[u8]) -> Result<(), SessionError> {
    let exact = match typ {
        OPEN => 118,
        VERIFY_COOKIE => 118,
        OPEN_AUTH => 230,
        OPEN_ACK => 182,
        SESSION_ACCEPT => 68,
        CLOSE => 26,
        SESSION_DATA => 24,
        _ => return Err(SessionError::Type),
    };
    if body.len() < exact {
        return Err(SessionError::Truncated);
    }
    if typ != SESSION_DATA && body.len() != exact {
        return Err(SessionError::TrailingBytes);
    }
    if matches!(typ, OPEN | VERIFY_COOKIE | OPEN_AUTH | OPEN_ACK) {
        validate_role_pair(body)?;
    }
    if matches!(typ, SESSION_ACCEPT | SESSION_DATA | CLOSE)
        && u64::from_be_bytes(body[..8].try_into().expect("checked")) == 0
    {
        return Err(SessionError::CounterRange);
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub struct CookieContext<'a> {
    pub binding: &'a UdpBinding,
    pub client: &'a Identity,
    pub server: &'a Identity,
    pub scid: u64,
    pub client_ephemeral: [u8; 32],
    pub boot: [u8; 16],
    pub bucket: u64,
    pub server_context_id: u32,
}

pub fn cookie_input(context: &CookieContext<'_>) -> Result<Vec<u8>, SessionError> {
    context.client.validate()?;
    context.server.validate()?;
    if context.server_context_id == 0 {
        return Err(SessionError::ConfigError);
    }
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(b"R8 cookie v1");
    out.extend_from_slice(context.binding.as_bytes());
    out.extend_from_slice(&[
        WIRE_VERSION,
        SESSION_VERSION,
        context.client.role,
        context.server.role,
    ]);
    out.extend_from_slice(&context.client.service_context.to_be_bytes());
    out.extend_from_slice(&context.scid.to_be_bytes());
    out.extend_from_slice(&context.client.eid);
    out.extend_from_slice(&Sha256::digest(context.client.public_key));
    out.extend_from_slice(&Sha256::digest(context.client_ephemeral));
    out.extend_from_slice(&context.boot);
    out.extend_from_slice(&context.bucket.to_be_bytes());
    out.extend_from_slice(&context.server_context_id.to_be_bytes());
    Ok(out)
}
pub fn cookie(key: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("fixed HMAC key");
    mac.update(input);
    mac.finalize().into_bytes().into()
}
pub fn cookie_matches(
    current: &[u8; 32],
    previous: &[u8; 32],
    supplied: &[u8; 32],
    input: &[u8],
) -> bool {
    bool::from(cookie(current, input).ct_eq(supplied) | cookie(previous, input).ct_eq(supplied))
}
pub fn cookie_matches_buckets(
    current_key: &[u8; 32],
    previous_key: &[u8; 32],
    previous_key_rotated_ms: u64,
    supplied: &[u8; 32],
    context: CookieContext<'_>,
    now_ms: u64,
) -> Result<bool, SessionError> {
    let current_bucket = now_ms / 10_000;
    let current_input = cookie_input(&CookieContext {
        bucket: current_bucket,
        ..context
    })?;
    let current_match = cookie(current_key, &current_input).ct_eq(supplied);
    let prior_match = if let Some(bucket) = current_bucket.checked_sub(1) {
        let input = cookie_input(&CookieContext { bucket, ..context })?;
        cookie(current_key, &input).ct_eq(supplied)
    } else {
        0u8.ct_eq(&1)
    };
    let prior_key_match = if now_ms.saturating_sub(previous_key_rotated_ms) <= 20_000 {
        let current = cookie(previous_key, &current_input).ct_eq(supplied);
        let prior = if let Some(bucket) = current_bucket.checked_sub(1) {
            let input = cookie_input(&CookieContext { bucket, ..context })?;
            cookie(previous_key, &input).ct_eq(supplied)
        } else {
            0u8.ct_eq(&1)
        };
        current | prior
    } else {
        0u8.ct_eq(&1)
    };
    Ok(bool::from(current_match | prior_match | prior_key_match))
}

pub struct TranscriptContext<'a> {
    pub profile: u8,
    pub scid: u64,
    pub client: &'a Identity,
    pub server: &'a Identity,
    pub client_ephemeral: [u8; 32],
    pub server_ephemeral: [u8; 32],
    pub client_nonce: [u8; 32],
    pub server_nonce: [u8; 32],
    pub boot: [u8; 16],
}

pub fn transcript_t0(context: &TranscriptContext<'_>) -> Result<Vec<u8>, SessionError> {
    context.client.validate()?;
    if !matches!(context.server.role, 1 | 2) || context.server.service_context == 0 {
        return Err(SessionError::RoleMismatch);
    }
    if context.server.public_key != [0; 32]
        && !bool::from(eid(&context.server.public_key).ct_eq(&context.server.eid))
    {
        return Err(SessionError::EidKeyMismatch);
    }
    if context.client.service_context != context.server.service_context {
        return Err(SessionError::ServiceMismatch);
    }
    let mut out = Vec::with_capacity(245);
    out.extend_from_slice(b"R8 session transcript v1");
    out.extend_from_slice(&[WIRE_VERSION, context.profile]);
    out.extend_from_slice(&context.scid.to_be_bytes());
    out.extend_from_slice(&[context.client.role, context.server.role]);
    out.extend_from_slice(&context.client.service_context.to_be_bytes());
    out.extend_from_slice(&context.client.eid);
    out.extend_from_slice(&context.client.public_key);
    out.extend_from_slice(&context.server.eid);
    out.extend_from_slice(&context.server.public_key);
    out.extend_from_slice(&context.client_ephemeral);
    out.extend_from_slice(&context.server_ephemeral);
    out.extend_from_slice(&context.client_nonce);
    out.extend_from_slice(&context.server_nonce);
    out.extend_from_slice(&context.boot);
    Ok(out)
}
pub fn sign_open_auth(key: &SigningKey, t0: &[u8]) -> [u8; 64] {
    sign(key, b"R8 OPEN_AUTH v1", t0)
}
pub fn sign_open_ack(key: &SigningKey, t0: &[u8]) -> [u8; 64] {
    sign(key, b"R8 OPEN_ACK v1", t0)
}
fn sign(key: &SigningKey, domain: &[u8], t0: &[u8]) -> [u8; 64] {
    let mut message = domain.to_vec();
    message.extend_from_slice(t0);
    key.sign(&message).to_bytes()
}
pub fn verify_signature(
    public_key: &[u8; 32],
    domain: &[u8],
    t0: &[u8],
    signature: &[u8; 64],
) -> Result<(), SessionError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| SessionError::PinMismatch)?;
    let mut message = domain.to_vec();
    message.extend_from_slice(t0);
    key.verify(&message, &Signature::from_bytes(signature))
        .map_err(|_| SessionError::AuthFailed)
}
pub fn transcript_hash(
    t0: &[u8],
    client_signature: &[u8; 64],
    server_signature: &[u8; 64],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(t0);
    hash.update(client_signature);
    hash.update(server_signature);
    hash.finalize().into()
}

pub fn x25519(secret: [u8; 32], peer: [u8; 32]) -> Result<[u8; 32], SessionError> {
    let shared = StaticSecret::from(secret)
        .diffie_hellman(&PublicKey::from(peer))
        .to_bytes();
    if bool::from(shared.ct_eq(&[0; 32])) {
        Err(SessionError::AuthFailed)
    } else {
        Ok(shared)
    }
}
pub fn hkdf_prk(shared: [u8; 32], transcript_hash: [u8; 32]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(&transcript_hash), &shared);
    prk.into()
}
pub fn derive_key(
    shared: [u8; 32],
    transcript_hash: [u8; 32],
    profile: u8,
    sender_role: u8,
    receiver_role: u8,
    slot: u8,
) -> Result<[u8; 32], SessionError> {
    if !matches!(sender_role, 1 | 2)
        || !matches!(receiver_role, 1 | 2)
        || sender_role == receiver_role
        || slot > 1
    {
        return Err(SessionError::ConfigError);
    };
    let hk = Hkdf::<Sha256>::new(Some(&transcript_hash), &shared);
    let mut info = b"R8 key v1".to_vec();
    info.extend_from_slice(&[WIRE_VERSION, SESSION_VERSION, profile]);
    info.extend_from_slice(&transcript_hash);
    info.extend_from_slice(&[sender_role, receiver_role, slot]);
    let mut key = [0; 32];
    hk.expand(&info, &mut key)
        .map_err(|_| SessionError::ConfigError)?;
    Ok(key)
}

pub fn nonce(counter: u64) -> Result<[u8; 12], SessionError> {
    if counter == 0 {
        return Err(SessionError::CounterRange);
    };
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    Ok(nonce)
}
pub fn protected_aad(packet: &[u8], counter: u64) -> Result<Vec<u8>, SessionError> {
    if packet.len() < HEADER_LEN + 12 {
        return Err(SessionError::Truncated);
    }
    Header::unpack(packet).map_err(|_| SessionError::AuthFailed)?;
    let mut aad = Vec::with_capacity(HEADER_LEN + 12);
    aad.extend_from_slice(&packet[..HEADER_LEN + 4]);
    aad.extend_from_slice(&counter.to_be_bytes());
    Ok(aad)
}
pub fn seal(
    key: [u8; 32],
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SessionError> {
    let nonce = nonce(counter)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut data = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, &mut data)
        .map_err(|_| SessionError::AuthFailed)?;
    data.extend_from_slice(&tag);
    Ok(data)
}
pub fn open(
    key: [u8; 32],
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, SessionError> {
    if ciphertext.len() < 16 {
        return Err(SessionError::Truncated);
    };
    let nonce = nonce(counter)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let split = ciphertext.len() - 16;
    let mut data = ciphertext[..split].to_vec();
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            aad,
            &mut data,
            Tag::from_slice(&ciphertext[split..]),
        )
        .map_err(|_| SessionError::AuthFailed)?;
    Ok(data)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayWindow {
    largest: u64,
    bits: [u64; 16],
    generation: u64,
}

#[derive(Debug)]
pub struct ReplayCommit {
    counter: u64,
    generation: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            largest: 0,
            bits: [0; 16],
            generation: 0,
        }
    }
    pub fn check(&self, counter: u64) -> Result<(), SessionError> {
        if counter == 0 {
            return Err(SessionError::CounterRange);
        };
        if self.largest > 0 && counter > self.largest.saturating_add(REPLAY_JUMP_MAX) {
            return Err(SessionError::Replay);
        };
        if self.largest > 0 && counter.saturating_add(REPLAY_WINDOW) <= self.largest {
            return Err(SessionError::Replay);
        };
        if counter <= self.largest {
            let delta = self.largest - counter;
            if delta < REPLAY_WINDOW
                && (self.bits[(delta / 64) as usize] & (1 << (delta % 64))) != 0
            {
                return Err(SessionError::Replay);
            }
        }
        Ok(())
    }
    pub fn preview(&self, counter: u64) -> Result<ReplayCommit, SessionError> {
        self.check(counter)?;
        Ok(ReplayCommit {
            counter,
            generation: self.generation,
        })
    }
    pub fn commit(&mut self, token: ReplayCommit) -> Result<(), SessionError> {
        if token.generation != self.generation {
            return Err(SessionError::Replay);
        }
        self.check(token.counter)?;
        let generation = self.generation.checked_add(1).ok_or(SessionError::Replay)?;
        self.mark(token.counter);
        self.generation = generation;
        Ok(())
    }
    pub fn mark_after_auth(&mut self, counter: u64) -> Result<(), SessionError> {
        self.commit(self.preview(counter)?)
    }
    fn mark(&mut self, counter: u64) {
        if counter > self.largest {
            let shift = counter - self.largest;
            if shift >= REPLAY_WINDOW {
                self.bits = [0; 16]
            } else {
                for _ in 0..shift {
                    for i in (0..16).rev() {
                        self.bits[i] =
                            (self.bits[i] << 1) | if i > 0 { self.bits[i - 1] >> 63 } else { 0 }
                    }
                }
            }
            self.largest = counter;
        }
        let delta = self.largest - counter;
        self.bits[(delta / 64) as usize] |= 1 << (delta % 64);
    }
}
impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct Counters {
    next: u64,
}
impl Counters {
    pub fn new() -> Self {
        Self { next: 1 }
    }
    pub fn reserve(&mut self) -> Result<u64, SessionError> {
        if self.next == 0 {
            return Err(SessionError::CounterExhausted);
        };
        let counter = self.next;
        self.next = self.next.checked_add(1).unwrap_or(0);
        Ok(counter)
    }
    pub fn restart(&mut self) {
        self.next = 1
    }
}
impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Zeroize)]
pub struct SecretMaterial {
    #[zeroize(skip)]
    pub key_id: u64,
    pub bytes: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct HandshakeConfig {
    pub local: Identity,
    pub peer: Identity,
    pub profile: u8,
    pub source: [u8; 16],
    pub destination: [u8; 16],
    pub budget: usize,
    pub pending_limit: usize,
    pub established_limit: usize,
    pub server_context_id: u32,
}

impl HandshakeConfig {
    pub fn validate(&self) -> Result<(), SessionError> {
        self.local.validate()?;
        self.peer.validate()?;
        if self.local.role == self.peer.role {
            return Err(SessionError::RoleMismatch);
        }
        if self.local.service_context != self.peer.service_context {
            return Err(SessionError::ServiceMismatch);
        }
        if self.profile > 3 || self.budget < 48 || self.server_context_id == 0 {
            return Err(SessionError::ConfigError);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ClientMaterial {
    pub ephemeral_secret: [u8; 32],
    pub nonce: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub struct ServerMaterial {
    pub boot_instance: [u8; 16],
    pub current_cookie_key: [u8; 32],
    pub previous_cookie_key: [u8; 32],
    pub previous_key_rotated_ms: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct ServerHandshakeMaterial {
    pub ephemeral_secret: [u8; 32],
    pub nonce: [u8; 32],
}

impl ServerMaterial {
    pub fn handshake_material(
        ephemeral_secret: [u8; 32],
        nonce: [u8; 32],
    ) -> ServerHandshakeMaterial {
        ServerHandshakeMaterial {
            ephemeral_secret,
            nonce,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DirectionalSession {
    pub send_key: [u8; 32],
    pub receive_key: [u8; 32],
    pub send_counters: Counters,
    pub replay: ReplayWindow,
    pub transcript_hash: [u8; 32],
}

#[derive(Debug)]
pub struct ProtectedPreview {
    plaintext: Vec<u8>,
    commit: ReplayCommit,
}

impl ProtectedPreview {
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

impl DirectionalSession {
    pub fn encrypt(
        &mut self,
        header: &Header,
        typ: u8,
        plaintext: &[u8],
        budget: usize,
    ) -> Result<Vec<u8>, SessionError> {
        if !matches!(typ, SESSION_ACCEPT | SESSION_DATA | CLOSE) {
            return Err(SessionError::Type);
        }
        if typ == SESSION_ACCEPT && plaintext.len() != 44 {
            return Err(SessionError::AuthFailed);
        }
        if typ == CLOSE && plaintext.len() != 2 {
            return Err(SessionError::AuthFailed);
        }
        let payload_len = 12usize
            .checked_add(plaintext.len())
            .and_then(|len| len.checked_add(16))
            .ok_or(SessionError::Budget)?;
        if payload_len.checked_add(48).ok_or(SessionError::Budget)? > budget {
            return Err(SessionError::Budget);
        }
        let counter = self.send_counters.reserve()?;
        let mut payload = vec![typ, SESSION_VERSION, header.profile, 0];
        payload.extend_from_slice(&counter.to_be_bytes());
        payload.resize(payload_len, 0);
        let packet = header
            .pack_with_budget(&payload, budget)
            .map_err(|_| SessionError::Budget)?;
        let aad = protected_aad(&packet, counter)?;
        let ciphertext = seal(self.send_key, counter, &aad, plaintext)?;
        payload[12..].copy_from_slice(&ciphertext);
        header
            .pack_with_budget(&payload, budget)
            .map_err(|_| SessionError::Budget)
    }

    pub fn preview(&self, packet: &[u8]) -> Result<ProtectedPreview, SessionError> {
        let (header, payload) = Header::unpack(packet).map_err(|_| SessionError::AuthFailed)?;
        let message = SessionMessage::decode(payload, header.profile, packet.len())
            .map_err(|_| SessionError::AuthFailed)?;
        if !matches!(message.typ, SESSION_ACCEPT | SESSION_DATA | CLOSE) {
            return Err(SessionError::UnexpectedMessage);
        }
        let counter =
            u64::from_be_bytes(message.body[..8].try_into().expect("checked session body"));
        let commit = self.replay.preview(counter)?;
        let aad = protected_aad(packet, counter)?;
        let plaintext = open(self.receive_key, counter, &aad, &message.body[8..])?;
        Ok(ProtectedPreview { plaintext, commit })
    }

    pub fn commit(&mut self, preview: ProtectedPreview) -> Result<Vec<u8>, SessionError> {
        self.replay.commit(preview.commit)?;
        Ok(preview.plaintext)
    }

    pub fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.commit(self.preview(packet)?)
    }
}
fn validate_protected_header(
    header: &Header,
    profile: u8,
    scid: u64,
    source: &[u8; 16],
    destination: &[u8; 16],
) -> Result<(), SessionError> {
    if header.next_header != r8_proto::NH_SES
        || header.profile != profile
        || header.scid != scid
        || header.flags != 1
        || header.path_slot != 0
        || &header.src != source
        || &header.dst != destination
    {
        return Err(SessionError::AuthFailed);
    }
    Ok(())
}
#[derive(Debug)]
pub struct DataPreview {
    scid: u64,
    header: Header,
    commit: ProtectedPreview,
}

impl DataPreview {
    pub fn plaintext(&self) -> &[u8] {
        self.commit.plaintext()
    }
}

#[derive(Clone, Debug)]
enum ClientState {
    Idle,
    CookieWait {
        scid: u64,
        material: ClientMaterial,
        open: Vec<u8>,
        deadline_ms: u64,
    },
    AuthWait {
        scid: u64,
        material: ClientMaterial,
        boot: [u8; 16],
        open_auth: Vec<u8>,
        deadline_ms: u64,
    },
    Established {
        scid: u64,
        session: DirectionalSession,
        cached_accept: Vec<u8>,
    },
    Released,
}

pub struct ClientMachine {
    config: HandshakeConfig,
    signing_key: SigningKey,
    state: ClientState,
    effective_local_loc: [u8; 16],
    effective_peer_loc: [u8; 16],
}

impl ClientMachine {
    pub fn new(config: HandshakeConfig, signing_key: SigningKey) -> Result<Self, SessionError> {
        config.validate()?;
        if signing_key.verifying_key().to_bytes() != config.local.public_key {
            return Err(SessionError::PinMismatch);
        }
        Ok(Self {
            effective_local_loc: config.source,
            effective_peer_loc: config.destination,
            config,
            signing_key,
            state: ClientState::Idle,
        })
    }

    pub fn start(
        &mut self,
        scid: u64,
        material: ClientMaterial,
        now_ms: u64,
    ) -> Result<Vec<u8>, SessionError> {
        if scid == 0 || !matches!(self.state, ClientState::Idle) {
            return Err(SessionError::UnexpectedMessage);
        }
        let ephemeral = PublicKey::from(&StaticSecret::from(material.ephemeral_secret)).to_bytes();
        let mut body = Vec::with_capacity(118);
        body.extend_from_slice(&[self.config.local.role, self.config.peer.role]);
        body.extend_from_slice(&self.config.local.service_context.to_be_bytes());
        body.extend_from_slice(&self.config.local.eid);
        body.extend_from_slice(&self.config.local.public_key);
        body.extend_from_slice(&ephemeral);
        body.extend_from_slice(&material.nonce);
        let packet = self.packet(scid, OPEN, 0, 0, &body)?;
        self.state = ClientState::CookieWait {
            scid,
            material,
            open: packet.clone(),
            deadline_ms: now_ms.saturating_add(5_000),
        };
        Ok(packet)
    }

    pub fn retry(&self, now_ms: u64) -> Result<Vec<u8>, SessionError> {
        match &self.state {
            ClientState::CookieWait {
                open, deadline_ms, ..
            } if now_ms < *deadline_ms => Ok(open.clone()),
            ClientState::AuthWait {
                open_auth,
                deadline_ms,
                ..
            } if now_ms < *deadline_ms => Ok(open_auth.clone()),
            ClientState::Established { cached_accept, .. } => Ok(cached_accept.clone()),
            _ => Err(SessionError::UnexpectedMessage),
        }
    }
    pub fn expire(&mut self, now_ms: u64) {
        let expired = match &self.state {
            ClientState::CookieWait { deadline_ms, .. }
            | ClientState::AuthWait { deadline_ms, .. } => now_ms >= *deadline_ms,
            _ => false,
        };
        if expired {
            self.state = ClientState::Released;
        }
    }

    pub fn receive_verify(&mut self, packet: &[u8], now_ms: u64) -> Result<Vec<u8>, SessionError> {
        let (scid, material, deadline_ms) = match &self.state {
            ClientState::CookieWait {
                scid,
                material,
                deadline_ms,
                ..
            } if now_ms < *deadline_ms => (*scid, *material, *deadline_ms),
            _ => return Err(SessionError::UnexpectedMessage),
        };
        let (_, payload) = Header::unpack(packet).map_err(|_| SessionError::AuthFailed)?;
        let verify = SessionMessage::decode(payload, self.config.profile, self.config.budget)?;
        if verify.typ != VERIFY_COOKIE {
            return Err(SessionError::UnexpectedMessage);
        }
        let body = &verify.body;
        if body[0] != self.config.peer.role || body[1] != self.config.local.role {
            return Err(SessionError::RoleMismatch);
        }
        if u32::from_be_bytes(body[2..6].try_into().expect("checked"))
            != self.config.local.service_context
        {
            return Err(SessionError::ServiceMismatch);
        }
        if body[6..38] != self.config.local.public_key {
            return Err(SessionError::PinMismatch);
        }
        let expected_ephemeral =
            PublicKey::from(&StaticSecret::from(material.ephemeral_secret)).to_bytes();
        let ephemeral_digest = Sha256::digest(expected_ephemeral);
        if ephemeral_digest[..] != body[38..70] {
            return Err(SessionError::AuthFailed);
        }
        let boot: [u8; 16] = body[70..86].try_into().expect("checked");
        let cookie: [u8; 32] = body[86..118].try_into().expect("checked");
        let placeholder_server = Identity {
            role: self.config.peer.role,
            service_context: self.config.peer.service_context,
            eid: self.config.peer.eid,
            public_key: [0; 32],
        };
        let t0 = transcript_t0(&TranscriptContext {
            profile: self.config.profile,
            scid,
            client: &self.config.local,
            server: &placeholder_server,
            client_ephemeral: expected_ephemeral,
            server_ephemeral: [0; 32],
            client_nonce: material.nonce,
            server_nonce: [0; 32],
            boot,
        })?;
        let signature = sign_open_auth(&self.signing_key, &t0);
        let mut body = Vec::with_capacity(230);
        body.extend_from_slice(&[self.config.local.role, self.config.peer.role]);
        body.extend_from_slice(&self.config.local.service_context.to_be_bytes());
        body.extend_from_slice(&self.config.local.eid);
        body.extend_from_slice(&self.config.local.public_key);
        body.extend_from_slice(&expected_ephemeral);
        body.extend_from_slice(&material.nonce);
        body.extend_from_slice(&boot);
        body.extend_from_slice(&cookie);
        body.extend_from_slice(&signature);
        let open_auth = self.packet(scid, OPEN_AUTH, 0, 0, &body)?;
        self.state = ClientState::AuthWait {
            scid,
            material,
            boot,
            open_auth: open_auth.clone(),
            deadline_ms,
        };
        Ok(open_auth)
    }
    pub fn receive_ack(&mut self, packet: &[u8], now_ms: u64) -> Result<Vec<u8>, SessionError> {
        let (scid, material, boot) = match &self.state {
            ClientState::AuthWait {
                scid,
                material,
                boot,
                deadline_ms,
                ..
            } if now_ms < *deadline_ms => (*scid, *material, *boot),
            ClientState::Established { cached_accept, .. } => return Ok(cached_accept.clone()),
            _ => return Err(SessionError::UnexpectedMessage),
        };
        let (header, payload) = Header::unpack_with_budget(packet, self.config.budget)
            .map_err(|_| SessionError::AuthFailed)?;
        if header.next_header != r8_proto::NH_SES
            || header.profile != self.config.profile
            || header.scid != scid
            || header.flags != 0
            || header.path_slot != 0
            || header.src != self.config.destination
            || header.dst != self.config.source
        {
            return Err(SessionError::AuthFailed);
        }
        let ack = SessionMessage::decode(payload, self.config.profile, self.config.budget)?;
        if ack.typ != OPEN_ACK {
            return Err(SessionError::UnexpectedMessage);
        }
        let body = &ack.body;
        if body[0] != self.config.peer.role || body[1] != self.config.local.role {
            return Err(SessionError::RoleMismatch);
        }
        if u32::from_be_bytes(body[2..6].try_into().expect("checked"))
            != self.config.peer.service_context
        {
            return Err(SessionError::ServiceMismatch);
        }
        if body[6..22] != self.config.peer.eid || body[22..54] != self.config.peer.public_key {
            return Err(SessionError::PinMismatch);
        }
        let server_ephemeral: [u8; 32] = body[54..86].try_into().expect("ack body length");
        let server_nonce: [u8; 32] = body[86..118].try_into().expect("ack body length");
        let signature: [u8; 64] = body[118..182].try_into().expect("ack body length");
        let client_ephemeral =
            PublicKey::from(&StaticSecret::from(material.ephemeral_secret)).to_bytes();
        let t0 = transcript_t0(&TranscriptContext {
            profile: self.config.profile,
            scid,
            client: &self.config.local,
            server: &self.config.peer,
            client_ephemeral,
            server_ephemeral,
            client_nonce: material.nonce,
            server_nonce,
            boot,
        })?;
        verify_signature(
            &self.config.peer.public_key,
            b"R8 OPEN_ACK v1",
            &t0,
            &signature,
        )?;
        let shared = x25519(material.ephemeral_secret, server_ephemeral)?;
        let client_signature = match &self.state {
            ClientState::AuthWait { open_auth, .. } => {
                let body = &Header::unpack(open_auth)
                    .map_err(|_| SessionError::AuthFailed)?
                    .1[4..];
                body[166..230].try_into().expect("open auth signature")
            }
            _ => unreachable!(),
        };
        let hash = transcript_hash(&t0, &client_signature, &signature);
        let send_key = derive_key(
            shared,
            hash,
            self.config.profile,
            self.config.local.role,
            self.config.peer.role,
            0,
        )?;
        let receive_key = derive_key(
            shared,
            hash,
            self.config.profile,
            self.config.peer.role,
            self.config.local.role,
            0,
        )?;
        let mut session = DirectionalSession {
            send_key,
            receive_key,
            send_counters: Counters::new(),
            replay: ReplayWindow::new(),
            transcript_hash: hash,
        };
        let header = Header {
            profile: self.config.profile,
            tc: 0,
            next_header: r8_proto::NH_SES,
            hop_limit: 64,
            flags: 1,
            path_slot: 0,
            scid,
            src: self.config.source,
            dst: self.config.destination,
        };
        let mut plaintext = b"R8 ACCEPT v1".to_vec();
        plaintext.extend_from_slice(&hash);
        let accept = session.encrypt(&header, SESSION_ACCEPT, &plaintext, self.config.budget)?;
        self.state = ClientState::Established {
            scid,
            session,
            cached_accept: accept.clone(),
        };
        Ok(accept)
    }

    pub fn send_data(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.send_data_with_locs(plaintext, self.effective_local_loc, self.effective_peer_loc)
    }

    pub fn send_data_with_locs(
        &mut self,
        plaintext: &[u8],
        source: [u8; 16],
        destination: [u8; 16],
    ) -> Result<Vec<u8>, SessionError> {
        let (scid, session) = match &mut self.state {
            ClientState::Established { scid, session, .. } => (*scid, session),
            _ => return Err(SessionError::UnexpectedMessage),
        };
        let header = Header {
            profile: self.config.profile,
            tc: 0,
            next_header: r8_proto::NH_SES,
            hop_limit: 64,
            flags: 1,
            path_slot: 0,
            scid,
            src: source,
            dst: destination,
        };
        let result = session.encrypt(&header, SESSION_DATA, plaintext, self.config.budget);
        if result == Err(SessionError::CounterExhausted) {
            self.state = ClientState::Released;
        }
        result
    }
    pub fn close(&mut self, code: u16) -> Result<Vec<u8>, SessionError> {
        let (scid, session) = match &mut self.state {
            ClientState::Established { scid, session, .. } => (*scid, session),
            _ => return Err(SessionError::UnexpectedMessage),
        };
        let header = Header {
            profile: self.config.profile,
            tc: 0,
            next_header: r8_proto::NH_SES,
            hop_limit: 64,
            flags: 1,
            path_slot: 0,
            scid,
            src: self.effective_local_loc,
            dst: self.effective_peer_loc,
        };
        let result = session.encrypt(&header, CLOSE, &code.to_be_bytes(), self.config.budget);
        match result {
            Ok(packet) => {
                self.state = ClientState::Released;
                Ok(packet)
            }
            Err(SessionError::CounterExhausted) => {
                self.state = ClientState::Released;
                Err(SessionError::CounterExhausted)
            }
            Err(error) => Err(error),
        }
    }

    pub fn receive_data(&mut self, packet: &[u8]) -> Result<Vec<u8>, SessionError> {
        let preview = self.preview_data_with_locs(packet, &[], &[])?;
        self.commit_data(preview)
    }

    pub fn preview_data_with_locs(
        &self,
        packet: &[u8],
        allowed_sources: &[[u8; 16]],
        allowed_destinations: &[[u8; 16]],
    ) -> Result<DataPreview, SessionError> {
        let (header, payload) = Header::unpack_with_budget(packet, self.config.budget)
            .map_err(|_| SessionError::AuthFailed)?;
        let session = match &self.state {
            ClientState::Established { scid, session, .. } if *scid == header.scid => session,
            _ => return Err(SessionError::UnexpectedMessage),
        };
        if header.next_header != r8_proto::NH_SES
            || header.profile != self.config.profile
            || header.flags != 1
            || header.path_slot != 0
            || (header.src != self.effective_peer_loc && !allowed_sources.contains(&header.src))
            || (header.dst != self.effective_local_loc
                && !allowed_destinations.contains(&header.dst))
        {
            return Err(SessionError::AuthFailed);
        }
        let message = SessionMessage::decode(payload, header.profile, self.config.budget)?;
        if message.typ != SESSION_DATA {
            return Err(SessionError::UnexpectedMessage);
        }
        let commit = session.preview(packet)?;
        Ok(DataPreview {
            scid: header.scid,
            header,
            commit,
        })
    }

    pub fn commit_data(&mut self, preview: DataPreview) -> Result<Vec<u8>, SessionError> {
        if preview.header.scid != preview.scid {
            return Err(SessionError::Replay);
        }
        let session = match &mut self.state {
            ClientState::Established { scid, session, .. } if *scid == preview.scid => session,
            _ => return Err(SessionError::Replay),
        };
        session.commit(preview.commit)
    }

    pub fn promote_local_loc(&mut self, new_loc: [u8; 16]) {
        self.effective_local_loc = new_loc;
    }

    pub fn promote_peer_loc(&mut self, new_loc: [u8; 16]) {
        self.effective_peer_loc = new_loc;
    }

    pub fn effective_local_loc(&self) -> [u8; 16] {
        self.effective_local_loc
    }

    pub fn effective_peer_loc(&self) -> [u8; 16] {
        self.effective_peer_loc
    }
    pub fn receive_close(&mut self, packet: &[u8]) -> Result<u16, SessionError> {
        let (scid, session) = match &mut self.state {
            ClientState::Established { scid, session, .. } => (*scid, session),
            _ => return Err(SessionError::UnexpectedMessage),
        };
        let (header, payload) = Header::unpack_with_budget(packet, self.config.budget)
            .map_err(|_| SessionError::AuthFailed)?;
        validate_protected_header(
            &header,
            self.config.profile,
            scid,
            &self.effective_peer_loc,
            &self.effective_local_loc,
        )?;
        let message = SessionMessage::decode(payload, header.profile, self.config.budget)?;
        if message.typ != CLOSE {
            return Err(SessionError::UnexpectedMessage);
        }
        let plaintext = session.decrypt(packet)?;
        let code: [u8; 2] = plaintext.try_into().map_err(|_| SessionError::AuthFailed)?;
        self.state = ClientState::Released;
        Ok(u16::from_be_bytes(code))
    }
    fn packet(
        &self,
        scid: u64,
        typ: u8,
        flags: u8,
        slot: u8,
        body: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let header = Header {
            profile: self.config.profile,
            tc: 0,
            next_header: r8_proto::NH_SES,
            hop_limit: 64,
            flags,
            path_slot: slot,
            scid,
            src: self.config.source,
            dst: self.config.destination,
        };
        let payload = SessionMessage {
            typ,
            profile: self.config.profile,
            body: body.to_vec(),
        }
        .encode(self.config.budget)?;
        header
            .pack_with_budget(&payload, self.config.budget)
            .map_err(|_| SessionError::Budget)
    }
}
#[derive(Clone, Debug)]
struct PendingSession {
    scid: u64,
    opening: Vec<u8>,
    cached_ack: Vec<u8>,
    binding: UdpBinding,
    deadline_ms: u64,
    session: DirectionalSession,
}
#[derive(Clone, Debug)]
struct EstablishedSession {
    scid: u64,
    session: DirectionalSession,
    last_active_ms: u64,
}

pub struct ServerMachine {
    config: HandshakeConfig,
    signing_key: SigningKey,
    material: ServerMaterial,
    pending: Vec<PendingSession>,
    established: Vec<EstablishedSession>,
    effective_local_loc: [u8; 16],
    effective_peer_loc: [u8; 16],
}

impl ServerMachine {
    pub fn new(
        config: HandshakeConfig,
        signing_key: SigningKey,
        material: ServerMaterial,
    ) -> Result<Self, SessionError> {
        config.validate()?;
        if signing_key.verifying_key().to_bytes() != config.local.public_key {
            return Err(SessionError::PinMismatch);
        }
        Ok(Self {
            effective_local_loc: config.destination,
            effective_peer_loc: config.source,
            config,
            signing_key,
            material,
            pending: Vec::new(),
            established: Vec::new(),
        })
    }

    pub fn receive_open(
        &self,
        packet: &[u8],
        binding: &UdpBinding,
        bucket: u64,
    ) -> Result<Vec<u8>, SessionError> {
        let (header, payload) = Header::unpack_with_budget(packet, self.config.budget)
            .map_err(|_| SessionError::AuthFailed)?;
        let open = SessionMessage::decode(payload, self.config.profile, self.config.budget)?;
        if open.typ != OPEN {
            return Err(SessionError::UnexpectedMessage);
        }
        let body = &open.body;
        let client = self.client_identity(body)?;
        let ephemeral: [u8; 32] = body[54..86].try_into().expect("open body length");
        let input = cookie_input(&CookieContext {
            binding,
            client: &client,
            server: &self.config.local,
            scid: header.scid,
            client_ephemeral: ephemeral,
            boot: self.material.boot_instance,
            bucket,
            server_context_id: self.config.server_context_id,
        })?;
        let cookie = cookie(&self.material.current_cookie_key, &input);
        let mut body = Vec::with_capacity(118);
        body.extend_from_slice(&[self.config.local.role, client.role]);
        body.extend_from_slice(&self.config.local.service_context.to_be_bytes());
        body.extend_from_slice(&client.public_key);
        body.extend_from_slice(&Sha256::digest(ephemeral));
        body.extend_from_slice(&self.material.boot_instance);
        body.extend_from_slice(&cookie);
        self.packet(header.scid, VERIFY_COOKIE, 0, 0, &body)
    }
    pub fn receive_open_limited(
        &self,
        packet: &[u8],
        binding: &UdpBinding,
        opaque_source: [u8; 32],
        now_ms: u64,
        bucket: u64,
        limiter: &mut PrevalidationLimiter,
    ) -> Result<Vec<u8>, SessionError> {
        limiter.admit(opaque_source, packet.len(), 170, now_ms)?;
        self.receive_open(packet, binding, bucket)
    }

    pub fn receive_open_auth(
        &mut self,
        packet: &[u8],
        binding: &UdpBinding,
        now_ms: u64,
        bucket: u64,
        handshake_material: Option<ServerHandshakeMaterial>,
    ) -> Result<Vec<u8>, SessionError> {
        let (header, payload) = Header::unpack_with_budget(packet, self.config.budget)
            .map_err(|_| SessionError::AuthFailed)?;
        let auth = SessionMessage::decode(payload, self.config.profile, self.config.budget)?;
        if auth.typ != OPEN_AUTH {
            return Err(SessionError::UnexpectedMessage);
        }
        let body = &auth.body;
        let client = self.client_identity(body)?;
        let client_ephemeral: [u8; 32] = body[54..86].try_into().expect("auth body length");
        let client_nonce: [u8; 32] = body[86..118].try_into().expect("auth body length");
        let boot: [u8; 16] = body[118..134].try_into().expect("auth body length");
        let supplied_cookie: [u8; 32] = body[134..166].try_into().expect("auth body length");
        if boot != self.material.boot_instance {
            return Err(SessionError::CookieInvalid);
        }
        let cookie_context = CookieContext {
            binding,
            client: &client,
            server: &self.config.local,
            scid: header.scid,
            client_ephemeral,
            boot,
            bucket,
            server_context_id: self.config.server_context_id,
        };
        if !cookie_matches_buckets(
            &self.material.current_cookie_key,
            &self.material.previous_cookie_key,
            self.material.previous_key_rotated_ms,
            &supplied_cookie,
            cookie_context,
            bucket.saturating_mul(10_000),
        )? {
            return Err(SessionError::CookieInvalid);
        }
        if let Some(pending) = self.pending.iter().find(|entry| entry.scid == header.scid) {
            if pending.opening == packet && pending.binding == *binding {
                return Ok(pending.cached_ack.clone());
            }
            return Err(SessionError::ScidCollision);
        }
        if self.pending.len() >= self.config.pending_limit {
            return Err(SessionError::Capacity);
        }
        let handshake_material = handshake_material.ok_or(SessionError::UnexpectedMessage)?;
        let signature: [u8; 64] = body[166..230].try_into().expect("auth body length");
        let placeholder_server = Identity {
            role: self.config.local.role,
            service_context: self.config.local.service_context,
            eid: self.config.local.eid,
            public_key: [0; 32],
        };
        let placeholder = transcript_t0(&TranscriptContext {
            profile: self.config.profile,
            scid: header.scid,
            client: &client,
            server: &placeholder_server,
            client_ephemeral,
            server_ephemeral: [0; 32],
            client_nonce,
            server_nonce: [0; 32],
            boot,
        })?;
        verify_signature(
            &client.public_key,
            b"R8 OPEN_AUTH v1",
            &placeholder,
            &signature,
        )?;
        let server_ephemeral =
            PublicKey::from(&StaticSecret::from(handshake_material.ephemeral_secret)).to_bytes();
        let shared = x25519(handshake_material.ephemeral_secret, client_ephemeral)?;
        let actual = transcript_t0(&TranscriptContext {
            profile: self.config.profile,
            scid: header.scid,
            client: &client,
            server: &self.config.local,
            client_ephemeral,
            server_ephemeral,
            client_nonce,
            server_nonce: handshake_material.nonce,
            boot,
        })?;
        let server_signature = sign_open_ack(&self.signing_key, &actual);
        let hash = transcript_hash(&actual, &signature, &server_signature);
        let send_key = derive_key(
            shared,
            hash,
            self.config.profile,
            self.config.local.role,
            client.role,
            0,
        )?;
        let receive_key = derive_key(
            shared,
            hash,
            self.config.profile,
            client.role,
            self.config.local.role,
            0,
        )?;
        let mut ack_body = Vec::with_capacity(182);
        ack_body.extend_from_slice(&[self.config.local.role, client.role]);
        ack_body.extend_from_slice(&self.config.local.service_context.to_be_bytes());
        ack_body.extend_from_slice(&self.config.local.eid);
        ack_body.extend_from_slice(&self.config.local.public_key);
        ack_body.extend_from_slice(&server_ephemeral);
        ack_body.extend_from_slice(&handshake_material.nonce);
        ack_body.extend_from_slice(&server_signature);
        let ack = self.packet(header.scid, OPEN_ACK, 0, 0, &ack_body)?;
        self.pending.push(PendingSession {
            scid: header.scid,
            opening: packet.to_vec(),
            cached_ack: ack.clone(),
            binding: binding.clone(),
            deadline_ms: now_ms.saturating_add(5_000),
            session: DirectionalSession {
                send_key,
                receive_key,
                send_counters: Counters::new(),
                replay: ReplayWindow::new(),
                transcript_hash: hash,
            },
        });
        Ok(ack)
    }

    pub fn receive_accept(&mut self, packet: &[u8], now_ms: u64) -> Result<(), SessionError> {
        let (header, _) = Header::unpack_with_budget(packet, self.config.budget)
            .map_err(|_| SessionError::AuthFailed)?;
        validate_protected_header(
            &header,
            self.config.profile,
            header.scid,
            &self.config.source,
            &self.config.destination,
        )?;
        if self
            .established
            .iter()
            .any(|entry| entry.scid == header.scid)
        {
            return Ok(());
        }
        let index = self
            .pending
            .iter()
            .position(|entry| entry.scid == header.scid)
            .ok_or(SessionError::UnexpectedMessage)?;
        let plaintext = self.pending[index].session.decrypt(packet)?;
        if plaintext.len() != 44
            || &plaintext[..12] != b"R8 ACCEPT v1"
            || plaintext[12..] != self.pending[index].session.transcript_hash
        {
            return Err(SessionError::AuthFailed);
        }
        if self.established.len() >= self.config.established_limit {
            return Err(SessionError::Capacity);
        }
        let pending = self.pending.remove(index);
        self.established.push(EstablishedSession {
            scid: pending.scid,
            session: pending.session,
            last_active_ms: now_ms,
        });
        Ok(())
    }

    pub fn receive_data(&mut self, packet: &[u8], now_ms: u64) -> Result<Vec<u8>, SessionError> {
        let preview = self.preview_data_with_locs(packet, &[], &[])?;
        self.commit_data(preview, now_ms)
    }

    pub fn preview_data_with_locs(
        &self,
        packet: &[u8],
        allowed_sources: &[[u8; 16]],
        allowed_destinations: &[[u8; 16]],
    ) -> Result<DataPreview, SessionError> {
        let (header, payload) = Header::unpack_with_budget(packet, self.config.budget)
            .map_err(|_| SessionError::AuthFailed)?;
        let session = self
            .established
            .iter()
            .find(|entry| entry.scid == header.scid)
            .map(|entry| &entry.session)
            .ok_or(SessionError::UnexpectedMessage)?;
        if header.next_header != r8_proto::NH_SES
            || header.profile != self.config.profile
            || header.flags != 1
            || header.path_slot != 0
            || (header.src != self.effective_peer_loc && !allowed_sources.contains(&header.src))
            || (header.dst != self.effective_local_loc
                && !allowed_destinations.contains(&header.dst))
        {
            return Err(SessionError::AuthFailed);
        }
        let message = SessionMessage::decode(payload, header.profile, self.config.budget)?;
        if message.typ != SESSION_DATA {
            return Err(SessionError::UnexpectedMessage);
        }
        let commit = session.preview(packet)?;
        Ok(DataPreview {
            scid: header.scid,
            header,
            commit,
        })
    }

    pub fn commit_data(
        &mut self,
        preview: DataPreview,
        now_ms: u64,
    ) -> Result<Vec<u8>, SessionError> {
        if preview.header.scid != preview.scid {
            return Err(SessionError::Replay);
        }
        let entry = self
            .established
            .iter_mut()
            .find(|entry| entry.scid == preview.scid)
            .ok_or(SessionError::Replay)?;
        let plaintext = entry.session.commit(preview.commit)?;
        entry.last_active_ms = now_ms;
        Ok(plaintext)
    }

    pub fn promote_local_loc(&mut self, new_loc: [u8; 16]) {
        self.effective_local_loc = new_loc;
    }

    pub fn promote_peer_loc(&mut self, new_loc: [u8; 16]) {
        self.effective_peer_loc = new_loc;
    }

    pub fn effective_local_loc(&self) -> [u8; 16] {
        self.effective_local_loc
    }

    pub fn effective_peer_loc(&self) -> [u8; 16] {
        self.effective_peer_loc
    }

    pub fn send_data(&mut self, scid: u64, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.send_data_with_locs(
            scid,
            plaintext,
            self.effective_local_loc,
            self.effective_peer_loc,
        )
    }

    pub fn send_data_with_locs(
        &mut self,
        scid: u64,
        plaintext: &[u8],
        source: [u8; 16],
        destination: [u8; 16],
    ) -> Result<Vec<u8>, SessionError> {
        let index = self
            .established
            .iter()
            .position(|entry| entry.scid == scid)
            .ok_or(SessionError::UnexpectedMessage)?;
        let header = Header {
            profile: self.config.profile,
            tc: 0,
            next_header: r8_proto::NH_SES,
            hop_limit: 64,
            flags: 1,
            path_slot: 0,
            scid,
            src: source,
            dst: destination,
        };
        let result = self.established[index].session.encrypt(
            &header,
            SESSION_DATA,
            plaintext,
            self.config.budget,
        );
        if result == Err(SessionError::CounterExhausted) {
            self.established.remove(index);
        }
        result
    }
    pub fn close(&mut self, scid: u64, code: u16) -> Result<Vec<u8>, SessionError> {
        let index = self
            .established
            .iter()
            .position(|entry| entry.scid == scid)
            .ok_or(SessionError::UnexpectedMessage)?;
        let header = Header {
            profile: self.config.profile,
            tc: 0,
            next_header: r8_proto::NH_SES,
            hop_limit: 64,
            flags: 1,
            path_slot: 0,
            scid,
            src: self.effective_local_loc,
            dst: self.effective_peer_loc,
        };
        let result = self.established[index].session.encrypt(
            &header,
            CLOSE,
            &code.to_be_bytes(),
            self.config.budget,
        );
        match result {
            Ok(packet) => {
                self.established.remove(index);
                Ok(packet)
            }
            Err(SessionError::CounterExhausted) => {
                self.established.remove(index);
                Err(SessionError::CounterExhausted)
            }
            Err(error) => Err(error),
        }
    }
    pub fn receive_close(&mut self, packet: &[u8], now_ms: u64) -> Result<u16, SessionError> {
        let (header, payload) = Header::unpack_with_budget(packet, self.config.budget)
            .map_err(|_| SessionError::AuthFailed)?;
        validate_protected_header(
            &header,
            self.config.profile,
            header.scid,
            &self.effective_peer_loc,
            &self.effective_local_loc,
        )?;
        let index = self
            .established
            .iter()
            .position(|entry| entry.scid == header.scid)
            .ok_or(SessionError::UnexpectedMessage)?;
        let message = SessionMessage::decode(payload, header.profile, self.config.budget)?;
        if message.typ != CLOSE {
            return Err(SessionError::UnexpectedMessage);
        }
        let plaintext = self.established[index].session.decrypt(packet)?;
        let code: [u8; 2] = plaintext.try_into().map_err(|_| SessionError::AuthFailed)?;
        self.established.remove(index);
        let _ = now_ms;
        Ok(u16::from_be_bytes(code))
    }

    pub fn expire(&mut self, now_ms: u64) {
        self.pending.retain(|entry| now_ms < entry.deadline_ms);
        self.established
            .retain(|entry| now_ms.saturating_sub(entry.last_active_ms) < 120_000);
    }
    pub fn is_live(&self, scid: u64) -> bool {
        self.pending.iter().any(|entry| entry.scid == scid)
            || self.established.iter().any(|entry| entry.scid == scid)
    }

    pub fn rotate_cookie_key(&mut self, new_key: [u8; 32], now_ms: u64) {
        self.material.previous_cookie_key = self.material.current_cookie_key;
        self.material.current_cookie_key = new_key;
        self.material.previous_key_rotated_ms = now_ms;
    }
    pub fn restart(&mut self, material: ServerMaterial) {
        self.pending.clear();
        self.established.clear();
        self.material = material;
    }

    fn client_identity(&self, body: &[u8]) -> Result<Identity, SessionError> {
        if body[0] != self.config.peer.role || body[1] != self.config.local.role {
            return Err(SessionError::RoleMismatch);
        }
        if u32::from_be_bytes(body[2..6].try_into().expect("checked"))
            != self.config.peer.service_context
        {
            return Err(SessionError::ServiceMismatch);
        }
        let eid: [u8; 16] = body[6..22].try_into().expect("checked");
        let public_key: [u8; 32] = body[22..54].try_into().expect("checked");
        if public_key != self.config.peer.public_key {
            return Err(SessionError::PinMismatch);
        }
        let identity = Identity {
            role: body[0],
            service_context: self.config.peer.service_context,
            eid,
            public_key,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn packet(
        &self,
        scid: u64,
        typ: u8,
        flags: u8,
        slot: u8,
        body: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let header = Header {
            profile: self.config.profile,
            tc: 0,
            next_header: r8_proto::NH_SES,
            hop_limit: 64,
            flags,
            path_slot: slot,
            scid,
            src: self.config.destination,
            dst: self.config.source,
        };
        let payload = SessionMessage {
            typ,
            profile: self.config.profile,
            body: body.to_vec(),
        }
        .encode(self.config.budget)?;
        header
            .pack_with_budget(&payload, self.config.budget)
            .map_err(|_| SessionError::Budget)
    }
}
#[derive(Clone, Debug)]
struct SourceAllowance {
    source: [u8; 32],
    window_started_ms: u64,
    last_seen_ms: u64,
    request_bytes: usize,
    response_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct PrevalidationLimiter {
    sources: Vec<SourceAllowance>,
    tokens: u32,
    token_second: u64,
}

impl Default for PrevalidationLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl PrevalidationLimiter {
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            tokens: 2000,
            token_second: 0,
        }
    }

    pub fn admit(
        &mut self,
        source: [u8; 32],
        request_bytes: usize,
        response_bytes: usize,
        now_ms: u64,
    ) -> Result<(), SessionError> {
        let second = now_ms / 1000;
        if second > self.token_second {
            let elapsed = second - self.token_second;
            self.tokens = self
                .tokens
                .saturating_add((elapsed.saturating_mul(1000)) as u32)
                .min(2000);
            self.token_second = second;
        }
        if self.tokens == 0 || response_bytes > request_bytes {
            return Err(SessionError::Capacity);
        }
        let index = match self.sources.iter().position(|entry| entry.source == source) {
            Some(index) => index,
            None if self.sources.len() < 4096 => {
                self.sources.push(SourceAllowance {
                    source,
                    window_started_ms: now_ms,
                    last_seen_ms: now_ms,
                    request_bytes: 0,
                    response_bytes: 0,
                });
                self.sources.len() - 1
            }
            None => {
                let index = self
                    .sources
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| (entry.last_seen_ms, entry.source))
                    .map(|(index, _)| index)
                    .expect("full source registry is non-empty");
                self.sources[index] = SourceAllowance {
                    source,
                    window_started_ms: now_ms,
                    last_seen_ms: now_ms,
                    request_bytes: 0,
                    response_bytes: 0,
                };
                index
            }
        };
        let entry = &mut self.sources[index];
        if now_ms.saturating_sub(entry.window_started_ms) >= 20_000 {
            entry.window_started_ms = now_ms;
            entry.request_bytes = 0;
            entry.response_bytes = 0;
        }
        let requests = entry
            .request_bytes
            .checked_add(request_bytes)
            .ok_or(SessionError::Capacity)?;
        let responses = entry
            .response_bytes
            .checked_add(response_bytes)
            .ok_or(SessionError::Capacity)?;
        if responses > requests {
            return Err(SessionError::Capacity);
        }
        entry.request_bytes = requests;
        entry.response_bytes = responses;
        entry.last_seen_ms = now_ms;
        self.tokens -= 1;
        Ok(())
    }
}
#[cfg(test)]
mod limiter_tests {
    use super::{PrevalidationLimiter, SourceAllowance};

    #[test]
    fn full_source_registry_replaces_oldest_then_lexicographic_source() {
        let mut limiter = PrevalidationLimiter::new();
        limiter.sources = (0u16..4096)
            .map(|index| {
                let mut source = [0u8; 32];
                source[..2].copy_from_slice(&index.to_be_bytes());
                SourceAllowance {
                    source,
                    window_started_ms: 0,
                    last_seen_ms: 10,
                    request_bytes: 0,
                    response_bytes: 0,
                }
            })
            .collect();

        assert!(limiter.admit([9; 32], 1, 1, 11).is_ok());
        assert!(!limiter.sources.iter().any(|entry| entry.source == [0; 32]));
        assert!(limiter.sources.iter().any(|entry| entry.source == [9; 32]));
    }
}
