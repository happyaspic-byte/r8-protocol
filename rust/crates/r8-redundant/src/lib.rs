//! Carrier-neutral, two-slot Profile-3 delivery state.

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroU64;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use r8_mobility::{
    CandidateManager, Control, Profile3Admission, Profile3AdmissionIssuer, Profile3AdmissionOwner,
    Transition,
};
use r8_proto::Header;
use r8_session::{
    DirectionalSession, ObservedBinding, Profile3Bootstrap, Profile3DataPreview, SessionError,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const OVERHEAD: usize = 84;
const QUEUE_PACKETS: usize = 256;
const QUEUE_BYTES: usize = 256 * 1024;
const DEDUP_IDS: usize = 4096;
const DELIVERED_WINDOW_IDS: usize = 4096;
const DELIVERED_WINDOW_WORDS: usize = DELIVERED_WINDOW_IDS / u64::BITS as usize;
const DEDUP_LIFETIME_MS: u64 = 30_000;
const DELIVERY_GAP: u64 = 65_536;
const EVENTS: usize = 64;

static NEXT_RECEIVE_OWNER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathState {
    Absent,
    Candidate,
    Validated,
    Active,
    Degraded,
    Removed,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    Active,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedundantError {
    ProfileInvalid,
    AdmissionInvalid,
    PathUnavailable,
    BindingMismatch,
    MtuExceeded,
    QueueOverflow,
    CounterExhausted,
    DeliveryExhausted,
    AuthFailed,
    Replay,
    DeliveryGap,
    DedupCapacity,
    DivergentDelivery,
    PathFailure,
    Released,
}

impl RedundantError {
    pub const fn category(self) -> &'static str {
        match self {
            Self::MtuExceeded => "E-BUDGET",
            Self::DedupCapacity => "E-CAPACITY",
            Self::CounterExhausted | Self::DeliveryExhausted => "E-COUNTER",
            Self::Replay | Self::DeliveryGap => "E-REPLAY",
            Self::DivergentDelivery => "E-PATH",
            Self::AdmissionInvalid => "E-CANDIDATE",
            Self::PathUnavailable | Self::BindingMismatch | Self::PathFailure => "E-PATH",
            Self::Released => "E-TIMEOUT",
            Self::ProfileInvalid | Self::QueueOverflow | Self::AuthFailed => "E-PATH",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedundantEvent {
    InitialDegraded,
    Recovered,
    QueueOverflow,
    Divergence,
    Degraded,
    Released,
}

pub enum SendOutcome {
    Enqueued {
        delivery_id: NonZeroU64,
        packets: Vec<OutboundPacket>,
    },
    DroppedNewest,
}

impl core::fmt::Debug for SendOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Enqueued { packets, .. } => f
                .debug_struct("SendOutcome::Enqueued")
                .field("packets", &packets.len())
                .finish(),
            Self::DroppedNewest => f.write_str("SendOutcome::DroppedNewest"),
        }
    }
}

pub enum ReceiveOutcome {
    Delivered(Vec<u8>),
    Suppressed,
    Closed,
}

impl core::fmt::Debug for ReceiveOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Delivered(bytes) => f
                .debug_tuple("ReceiveOutcome::Delivered")
                .field(&format_args!("[REDACTED; {} bytes]", bytes.len()))
                .finish(),
            Self::Suppressed => f.write_str("ReceiveOutcome::Suppressed"),
            Self::Closed => f.write_str("ReceiveOutcome::Closed"),
        }
    }
}
#[derive(Clone, Copy)]
enum ReceiveDecision {
    New,
    Equal,
    Divergent,
}

struct InboundLease {
    active: AtomicBool,
}

#[must_use]
pub struct InboundPreview {
    owner: u64,
    generation: u64,
    slot: u8,
    session_preview: Option<Profile3DataPreview>,
    decision: ReceiveDecision,
    now_ms: u64,
    lease: Option<Arc<InboundLease>>,
}

impl InboundPreview {
    pub fn plaintext(&self) -> Result<&[u8], RedundantError> {
        self.lease
            .as_ref()
            .is_some_and(|lease| lease.active.load(Ordering::Acquire))
            .then(|| {
                self.session_preview
                    .as_ref()
                    .map(Profile3DataPreview::plaintext)
            })
            .flatten()
            .ok_or(RedundantError::Released)
    }
    fn into_mobility_commit(
        mut self,
        transition: Transition,
    ) -> Result<MobilityInboundCommit, RedundantError> {
        if matches!(self.decision, ReceiveDecision::Divergent) {
            return Err(RedundantError::DivergentDelivery);
        }
        let lease = self.lease.take().expect("inbound preview has a lease");
        Ok(MobilityInboundCommit {
            lease: InboundReplayLease {
                owner: self.owner,
                generation: self.generation,
                slot: self.slot,
                lease,
            },
            transition,
        })
    }
}
impl Drop for InboundPreview {
    fn drop(&mut self) {
        if let Some(lease) = &self.lease {
            lease.active.store(false, Ordering::Release);
        }
    }
}

#[must_use]
pub struct MobilityInboundCommit {
    lease: InboundReplayLease,
    transition: Transition,
}

#[must_use]
struct InboundReplayLease {
    owner: u64,
    generation: u64,
    slot: u8,
    lease: Arc<InboundLease>,
}

impl core::fmt::Debug for InboundReplayLease {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("InboundReplayLease(<redacted>)")
    }
}
impl Drop for InboundReplayLease {
    fn drop(&mut self) {
        self.lease.active.store(false, Ordering::Release);
    }
}

impl core::fmt::Debug for MobilityInboundCommit {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("MobilityInboundCommit(<redacted>)")
    }
}

impl core::fmt::Debug for InboundPreview {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("InboundPreview(<redacted>)")
    }
}

/// A wire packet paired only with its opaque carrier binding and path slot.
pub struct OutboundPacket {
    slot: u8,
    binding: ObservedBinding,
    packet: Vec<u8>,
}

impl OutboundPacket {
    pub fn slot(&self) -> u8 {
        self.slot
    }

    pub fn binding(&self) -> &ObservedBinding {
        &self.binding
    }

    pub fn packet(&self) -> &[u8] {
        &self.packet
    }
}

impl Drop for OutboundPacket {
    fn drop(&mut self) {
        self.packet.fill(0);
    }
}

impl core::fmt::Debug for OutboundPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OutboundPacket")
            .field("slot", &self.slot)
            .field("binding", &"[REDACTED]")
            .field("packet", &"[REDACTED]")
            .finish()
    }
}

struct Path {
    state: PathState,
    binding: Option<ObservedBinding>,
    local_loc: Option<[u8; 16]>,
    peer_loc: Option<[u8; 16]>,
    budget: usize,
    session: Option<DirectionalSession>,
    queue: VecDeque<OutboundPacket>,
    queued_bytes: usize,
}

impl core::fmt::Debug for Path {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Path")
            .field("state", &self.state)
            .field("binding", &"[REDACTED]")
            .field("local_loc", &"[REDACTED]")
            .field("peer_loc", &"[REDACTED]")
            .field("budget", &self.budget)
            .field("session", &"[REDACTED]")
            .field("queue_len", &self.queue.len())
            .finish()
    }
}

impl Path {
    fn clear(&mut self) {
        self.queue.clear();
        self.queued_bytes = 0;
        self.binding.take();
        self.local_loc.take();
        self.peer_loc.take();
        self.session.take();
    }

    fn can_enqueue(&self, len: usize) -> bool {
        self.queue.len() < QUEUE_PACKETS
            && self
                .queued_bytes
                .checked_add(len)
                .is_some_and(|value| value <= QUEUE_BYTES)
    }
}

struct Dedup {
    bytes: Vec<u8>,
    expiry_ms: u64,
}

impl Drop for Dedup {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

impl core::fmt::Debug for Dedup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dedup")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct DeliveredFingerprint {
    digest: [u8; 32],
    length: usize,
}

struct DeliveredWindow {
    high_water: Option<NonZeroU64>,
    bits: [u64; DELIVERED_WINDOW_WORDS],
    fingerprints: Zeroizing<Box<[Option<DeliveredFingerprint>]>>,
}

impl core::fmt::Debug for DeliveredWindow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeliveredWindow")
            .field("high_water", &"[REDACTED]")
            .finish()
    }
}

impl DeliveredWindow {
    fn seen(&self, id: NonZeroU64) -> bool {
        let Some(high) = self.high_water else {
            return false;
        };
        if id.get() > high.get() || high.get() - id.get() >= DELIVERED_WINDOW_IDS as u64 {
            return false;
        }
        self.bit(id)
    }

    fn too_old(&self, id: NonZeroU64) -> bool {
        self.high_water.is_some_and(|high| {
            id.get() <= high.get() && high.get() - id.get() >= DELIVERED_WINDOW_IDS as u64
        })
    }

    fn high_water(&self) -> Option<NonZeroU64> {
        self.high_water
    }

    fn insert(&mut self, id: NonZeroU64, bytes: &[u8]) {
        if let Some(high) = self.high_water {
            if id.get() > high.get() {
                let advance = id.get() - high.get();
                if advance >= DELIVERED_WINDOW_IDS as u64 {
                    self.clear_all();
                } else {
                    for value in high.get() + 1..=id.get() {
                        self.clear(value);
                    }
                }
                self.high_water = Some(id);
            }
        } else {
            self.high_water = Some(id);
        }
        self.clear(id.get());
        self.set(id);
        self.fingerprints[Self::index(id.get())] = Some(DeliveredFingerprint {
            digest: Sha256::digest(bytes).into(),
            length: bytes.len(),
        });
    }

    fn matches(&self, id: NonZeroU64, bytes: &[u8]) -> bool {
        self.fingerprints[Self::index(id.get())]
            .as_ref()
            .is_some_and(|fingerprint| {
                fingerprint.length == bytes.len()
                    && fingerprint.digest == <[u8; 32]>::from(Sha256::digest(bytes))
            })
    }

    fn bit(&self, id: NonZeroU64) -> bool {
        let (word, bit) = Self::position(id.get());
        self.bits[word] & bit != 0
    }

    fn set(&mut self, id: NonZeroU64) {
        let (word, bit) = Self::position(id.get());
        self.bits[word] |= bit;
    }

    fn clear(&mut self, id: u64) {
        let (word, bit) = Self::position(id);
        self.bits[word] &= !bit;
        if let Some(mut fingerprint) = self.fingerprints[Self::index(id)].take() {
            fingerprint.zeroize();
        }
    }

    fn clear_all(&mut self) {
        for index in 0..DELIVERED_WINDOW_IDS {
            if let Some(mut fingerprint) = self.fingerprints[index].take() {
                fingerprint.zeroize();
            }
        }
        self.bits.fill(0);
    }

    fn index(id: u64) -> usize {
        (id % DELIVERED_WINDOW_IDS as u64) as usize
    }

    fn position(id: u64) -> (usize, u64) {
        let index = Self::index(id);
        (
            index / u64::BITS as usize,
            1_u64 << (index % u64::BITS as usize),
        )
    }
}
impl Drop for DeliveredWindow {
    fn drop(&mut self) {
        self.clear_all();
        self.high_water = None;
        self.bits.zeroize();
        self.fingerprints.zeroize();
    }
}

/// The only owner of Profile-3 delivery state. It accepts no key material and cannot
/// construct slot one: mobility must mint, and this type must consume, an admission.
pub struct RedundantSession {
    bootstrap: Option<Profile3Bootstrap>,
    paths: [Path; 2],
    state: SessionState,
    next_delivery: NonZeroU64,
    delivered: DeliveredWindow,
    dedup: HashMap<NonZeroU64, Dedup>,
    events: VecDeque<RedundantEvent>,
    admission_issuer: Option<Profile3AdmissionIssuer>,
    receive_owner: u64,
    receive_generation: u64,
    receive_preview: Option<Arc<InboundLease>>,
}

impl core::fmt::Debug for RedundantSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RedundantSession")
            .field("state", &self.state)
            .field("paths", &self.paths)
            .field("next_delivery", &"[REDACTED]")
            .field("delivered", &self.delivered)
            .field("dedup_len", &self.dedup.len())
            .field("events", &self.events.len())
            .finish()
    }
}

impl RedundantSession {
    pub fn new(
        mut bootstrap: Profile3Bootstrap,
        slot0_binding: ObservedBinding,
        delivery_seed: NonZeroU64,
    ) -> Result<Self, RedundantError> {
        slot0_binding
            .validate()
            .map_err(|_| RedundantError::BindingMismatch)?;
        let budget = bootstrap.budget();
        if !(OVERHEAD..=1280).contains(&budget) {
            return Err(RedundantError::ProfileInvalid);
        }
        let slot0 = bootstrap.take_slot0().map_err(map_session)?;
        if !slot0.can_reserve() {
            return Err(RedundantError::CounterExhausted);
        }
        let local_loc = *bootstrap.local_loc();
        let peer_loc = *bootstrap.peer_loc();
        let mut session = Self {
            bootstrap: Some(bootstrap),
            state: SessionState::Active,
            next_delivery: delivery_seed,
            delivered: DeliveredWindow {
                high_water: None,
                bits: [0; DELIVERED_WINDOW_WORDS],
                fingerprints: Zeroizing::new(vec![None; DELIVERED_WINDOW_IDS].into_boxed_slice()),
            },
            dedup: HashMap::new(),
            events: VecDeque::new(),
            admission_issuer: None,
            receive_owner: NEXT_RECEIVE_OWNER.fetch_add(1, Ordering::Relaxed),
            receive_generation: 0,
            receive_preview: None,
            paths: [
                Path {
                    state: PathState::Active,
                    binding: Some(slot0_binding),
                    local_loc: Some(local_loc),
                    peer_loc: Some(peer_loc),
                    budget,
                    session: Some(slot0),
                    queue: VecDeque::new(),
                    queued_bytes: 0,
                },
                Path {
                    state: PathState::Absent,
                    binding: None,
                    local_loc: None,
                    peer_loc: None,
                    budget,
                    session: None,
                    queue: VecDeque::new(),
                    queued_bytes: 0,
                },
            ],
        };
        session.event(RedundantEvent::InitialDegraded);
        Ok(session)
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn path_state(&self, slot: u8) -> Option<PathState> {
        self.paths.get(usize::from(slot)).map(|path| path.state)
    }

    pub fn drain_events(&mut self) -> Vec<RedundantEvent> {
        self.events.drain(..).collect()
    }

    pub fn issue_profile3_admission_owner(
        &mut self,
        policy_id: u32,
    ) -> Result<Profile3AdmissionOwner, RedundantError> {
        self.live()?;
        if self.paths[1].state != PathState::Absent
            || self
                .admission_issuer
                .as_ref()
                .is_some_and(Profile3AdmissionIssuer::owner_is_live)
        {
            return Err(RedundantError::AdmissionInvalid);
        }
        self.admission_issuer = None;
        let bootstrap = self.bootstrap.as_ref().ok_or(RedundantError::Released)?;
        let binding = self.paths[0]
            .session
            .as_ref()
            .ok_or(RedundantError::Released)?
            .profile3_replay_binding();
        let (owner, issuer) = Profile3AdmissionOwner::issue(bootstrap.scid(), policy_id, binding)
            .map_err(|_| RedundantError::AdmissionInvalid)?;
        self.admission_issuer = Some(issuer);
        Ok(owner)
    }
    /// Consumes typed mobility authority exactly once.
    pub fn activate(
        &mut self,
        admission: Profile3Admission,
        budget: usize,
    ) -> Result<(), RedundantError> {
        admission
            .binding()
            .validate()
            .map_err(|_| RedundantError::AdmissionInvalid)?;
        self.live()?;
        self.reap_preview();
        if self.paths[1].state != PathState::Absent
            || !(OVERHEAD..=1280).contains(&budget)
            || self.receive_preview.is_some()
        {
            return Err(RedundantError::AdmissionInvalid);
        }
        let next_receive_generation = self
            .receive_generation
            .checked_add(1)
            .ok_or(RedundantError::Released)?;
        self.paths[1].state = PathState::Candidate;
        let result = (|| {
            let bootstrap = self.bootstrap.as_mut().ok_or(RedundantError::Released)?;
            let slot0_binding = self.paths[0]
                .session
                .as_ref()
                .ok_or(RedundantError::Released)?
                .profile3_replay_binding();
            if admission.scid() != bootstrap.scid()
                || !self
                    .admission_issuer
                    .as_ref()
                    .is_some_and(|issuer| issuer.admits(&admission))
                || !admission.matches_replay_binding(&slot0_binding)
            {
                return Err(RedundantError::AdmissionInvalid);
            }
            let session = bootstrap.take_slot1().map_err(map_session)?;
            if !session.can_reserve() {
                return Err(RedundantError::CounterExhausted);
            }
            Ok(session)
        })();
        let session = match result {
            Ok(session) => session,
            Err(error) => {
                self.paths[1].state = PathState::Absent;
                return Err(error);
            }
        };
        self.admission_issuer = None;
        let path = &mut self.paths[1];
        path.state = PathState::Validated;
        path.binding = Some(admission.binding().clone());
        path.local_loc = Some(admission.local_loc());
        path.peer_loc = Some(admission.peer_loc());
        path.budget = budget;
        path.session = Some(session);
        path.state = PathState::Active;
        self.event(RedundantEvent::Recovered);
        self.receive_generation = next_receive_generation;
        Ok(())
    }

    /// Encrypts identical logical data for every active path. Overflow never reserves
    /// a delivery ID or a path counter.
    pub fn outbound(&mut self, plaintext: &[u8]) -> Result<SendOutcome, RedundantError> {
        self.live()?;
        let length = plaintext
            .len()
            .checked_add(OVERHEAD)
            .ok_or(RedundantError::MtuExceeded)?;
        let active: Vec<usize> = self
            .paths
            .iter()
            .enumerate()
            .filter_map(|(index, path)| (path.state == PathState::Active).then_some(index))
            .collect();
        if active.is_empty() {
            return Err(RedundantError::PathUnavailable);
        }
        for &index in &active {
            let path = &self.paths[index];
            if length > path.budget {
                return Err(RedundantError::MtuExceeded);
            }
            if !path.can_enqueue(length) {
                self.event(RedundantEvent::QueueOverflow);
                return Ok(SendOutcome::DroppedNewest);
            }
            if !path
                .session
                .as_ref()
                .is_some_and(DirectionalSession::can_reserve)
            {
                self.close();
                return Err(RedundantError::CounterExhausted);
            }
        }
        let delivery = self.next_delivery;
        if delivery.get() == u64::MAX {
            self.close();
            return Err(RedundantError::DeliveryExhausted);
        }
        let next = NonZeroU64::new(delivery.get() + 1).expect("maximum checked");
        let mut packets = Vec::with_capacity(active.len());
        for index in active {
            let header = self.header(index as u8)?;
            let path = &mut self.paths[index];
            let binding = path
                .binding
                .clone()
                .ok_or(RedundantError::PathUnavailable)?;
            let packet = path
                .session
                .as_mut()
                .ok_or(RedundantError::PathUnavailable)?
                .encrypt_profile3_data(&header, delivery, plaintext, path.budget)
                .map_err(map_session)?;
            path.queued_bytes += packet.len();
            path.queue.push_back(OutboundPacket {
                slot: index as u8,
                binding: binding.clone(),
                packet: packet.clone(),
            });
            packets.push(OutboundPacket {
                slot: index as u8,
                binding,
                packet,
            });
        }
        self.next_delivery = next;
        Ok(SendOutcome::Enqueued {
            delivery_id: delivery,
            packets,
        })
    }

    /// Returns the encrypted FIFO packet without removing it.
    pub fn front(&self, slot: u8) -> Option<&OutboundPacket> {
        self.paths.get(usize::from(slot))?.queue.front()
    }

    /// Removes only the exact packet that was successfully sent.
    pub fn confirm_sent(&mut self, slot: u8, packet: &[u8]) -> Result<(), RedundantError> {
        let path = self
            .paths
            .get_mut(usize::from(slot))
            .ok_or(RedundantError::PathUnavailable)?;
        let cached = path.queue.front().ok_or(RedundantError::PathUnavailable)?;
        if cached.packet() != packet {
            return Err(RedundantError::PathFailure);
        }
        let sent = path.queue.pop_front().expect("front checked");
        path.queued_bytes -= sent.packet.len();
        Ok(())
    }

    fn preview_inbound_inner(
        &mut self,
        slot: u8,
        binding: &ObservedBinding,
        packet: &[u8],
        now_ms: u64,
        require_active_binding: bool,
    ) -> Result<InboundPreview, RedundantError> {
        binding
            .validate()
            .map_err(|_| RedundantError::BindingMismatch)?;
        self.live()?;
        self.reap_preview();
        if self.receive_preview.is_some() {
            return Err(RedundantError::DedupCapacity);
        }
        let index = usize::from(slot);
        let path = self
            .paths
            .get(index)
            .ok_or(RedundantError::PathUnavailable)?;
        if path.state != PathState::Active
            || (require_active_binding && path.binding.as_ref() != Some(binding))
        {
            return Err(RedundantError::BindingMismatch);
        }
        let (header, _) = Header::unpack_with_budget(packet, path.budget)
            .map_err(|_| RedundantError::AuthFailed)?;
        let bootstrap = self.bootstrap.as_ref().ok_or(RedundantError::Released)?;
        if header.scid != bootstrap.scid()
            || header.path_slot != slot
            || path.peer_loc != Some(header.src)
            || path.local_loc != Some(header.dst)
        {
            return Err(RedundantError::AuthFailed);
        }
        let session_preview = path
            .session
            .as_ref()
            .ok_or(RedundantError::PathUnavailable)?
            .preview_profile3_data(packet)
            .map_err(map_session)?;
        let id = session_preview.delivery_id();
        if self.delivered.too_old(id) {
            return Err(RedundantError::Replay);
        }
        let decision = if self.delivered.seen(id) {
            if self.delivered.matches(id, session_preview.plaintext()) {
                ReceiveDecision::Equal
            } else {
                ReceiveDecision::Divergent
            }
        } else {
            if let Some(high) = self.delivered.high_water() {
                if id.get() > high.get() && id.get() - high.get() > DELIVERY_GAP {
                    return Err(RedundantError::DeliveryGap);
                }
            }
            ReceiveDecision::New
        };
        let lease = Arc::new(InboundLease {
            active: AtomicBool::new(true),
        });
        self.receive_preview = Some(lease.clone());
        Ok(InboundPreview {
            owner: self.receive_owner,
            generation: self.receive_generation,
            slot,
            session_preview: Some(session_preview),
            decision,
            now_ms,
            lease: Some(lease),
        })
    }

    pub fn preview_inbound(
        &mut self,
        slot: u8,
        binding: &ObservedBinding,
        packet: &[u8],
        now_ms: u64,
    ) -> Result<InboundPreview, RedundantError> {
        self.preview_inbound_inner(slot, binding, packet, now_ms, true)
    }

    /// Authenticates a protected mobility control arriving on a candidate carrier.
    /// The caller prepares it with `CandidateManager::prepare_mobility_commit` and
    /// finalizes it through `RedundantSession::commit_mobility`.
    pub fn preview_mobility_inbound(
        &mut self,
        slot: u8,
        observed_binding: &ObservedBinding,
        packet: &[u8],
        now_ms: u64,
    ) -> Result<InboundPreview, RedundantError> {
        self.preview_inbound_inner(slot, observed_binding, packet, now_ms, false)
    }

    pub fn commit_inbound(
        &mut self,
        mut preview: InboundPreview,
    ) -> Result<ReceiveOutcome, RedundantError> {
        self.live()?;
        if !self.accepts_preview(&preview) {
            return Err(RedundantError::Replay);
        }
        let next_generation = self
            .receive_generation
            .checked_add(1)
            .ok_or(RedundantError::Released)?;
        let slot = preview.slot;
        let decision = preview.decision;
        let now_ms = preview.now_ms;
        let session_preview = preview
            .session_preview
            .take()
            .ok_or(RedundantError::Replay)?;
        self.receive_preview.take();
        let (id, mut bytes) = self.commit(slot, session_preview)?;
        self.receive_generation = next_generation;
        self.expire(now_ms);
        match decision {
            ReceiveDecision::Equal => {
                bytes.zeroize();
                Ok(ReceiveOutcome::Suppressed)
            }
            ReceiveDecision::Divergent => {
                bytes.zeroize();
                self.event(RedundantEvent::Divergence);
                self.close();
                Ok(ReceiveOutcome::Closed)
            }
            ReceiveDecision::New => {
                let evict = (self.dedup.len() >= DEDUP_IDS).then(|| {
                    self.dedup
                        .iter()
                        .min_by_key(|(old_id, entry)| (entry.expiry_ms, old_id.get()))
                        .map(|(old_id, _)| *old_id)
                        .expect("full dedup cache is non-empty")
                });
                if let Some(old_id) = evict {
                    self.dedup.remove(&old_id);
                }
                self.delivered.insert(id, &bytes);
                self.dedup.insert(
                    id,
                    Dedup {
                        bytes: bytes.clone(),
                        expiry_ms: now_ms.saturating_add(DEDUP_LIFETIME_MS),
                    },
                );
                Ok(ReceiveOutcome::Delivered(bytes))
            }
        }
    }

    pub fn abort_inbound(&mut self, preview: InboundPreview) -> Result<(), RedundantError> {
        self.live()?;
        if !self.accepts_preview(&preview) {
            return Err(RedundantError::Replay);
        }
        self.receive_preview.take();
        drop(preview);
        Ok(())
    }

    pub fn prepare_mobility_commit(
        &mut self,
        manager: &CandidateManager,
        observed_binding: &ObservedBinding,
        mut preview: InboundPreview,
        now_ms: u64,
    ) -> Result<MobilityInboundCommit, RedundantError> {
        self.live()?;
        if !self.accepts_preview(&preview) {
            return Err(RedundantError::Replay);
        }
        let mut plaintext = preview.plaintext()?.to_vec();
        let proof = preview
            .session_preview
            .take()
            .ok_or(RedundantError::Replay)?
            .into_replay_proof();
        let transition = manager
            .preview_profile3(&plaintext, observed_binding, proof, now_ms)
            .map_err(|_| RedundantError::Replay);
        plaintext.zeroize();
        preview.into_mobility_commit(transition?)
    }

    pub fn mobility_response(
        &self,
        manager: &CandidateManager,
        commit: &MobilityInboundCommit,
    ) -> Result<Option<Control>, RedundantError> {
        manager
            .response_for(&commit.transition)
            .map_err(|_| RedundantError::Replay)
    }

    pub fn commit_mobility(
        &mut self,
        manager: &CandidateManager,
        commit: MobilityInboundCommit,
    ) -> Result<(), RedundantError> {
        self.live()?;
        if !self.accepts_replay_lease(&commit.lease) {
            return Err(RedundantError::Replay);
        }
        let next_generation = self
            .receive_generation
            .checked_add(1)
            .ok_or(RedundantError::Released)?;
        let slot = commit.lease.slot;
        let session = self
            .paths
            .get_mut(usize::from(slot))
            .ok_or(RedundantError::PathUnavailable)?
            .session
            .as_mut()
            .ok_or(RedundantError::PathUnavailable)?;
        manager
            .commit_profile3(commit.transition, session)
            .map_err(|_| RedundantError::Replay)?;
        self.receive_preview.take();
        self.receive_generation = next_generation;
        Ok(())
    }
    pub fn inbound(
        &mut self,
        slot: u8,
        binding: &ObservedBinding,
        packet: &[u8],
        now_ms: u64,
    ) -> Result<ReceiveOutcome, RedundantError> {
        let preview = self.preview_inbound(slot, binding, packet, now_ms)?;
        self.commit_inbound(preview)
    }

    pub fn remove_path(&mut self, slot: u8) -> Result<(), RedundantError> {
        self.live()?;
        self.reap_preview();
        if let Some(lease) = self.receive_preview.take() {
            lease.active.store(false, Ordering::Release);
        }
        let next_receive_generation = self
            .receive_generation
            .checked_add(1)
            .ok_or(RedundantError::Released)?;
        {
            let path = self
                .paths
                .get_mut(usize::from(slot))
                .ok_or(RedundantError::PathUnavailable)?;
            if matches!(path.state, PathState::Removed | PathState::Degraded) {
                return Ok(());
            }
            if path.state != PathState::Active {
                return Err(RedundantError::PathUnavailable);
            }
            path.state = PathState::Degraded;
            path.clear();
            path.state = PathState::Removed;
        }
        self.receive_generation = next_receive_generation;
        self.event(RedundantEvent::Degraded);
        if !self
            .paths
            .iter()
            .any(|candidate| candidate.state == PathState::Active)
        {
            self.close();
        }
        Ok(())
    }

    pub fn close(&mut self) {
        if self.state == SessionState::Released {
            return;
        }
        for path in &mut self.paths {
            path.clear();
            path.state = PathState::Released;
        }
        self.dedup.clear();
        self.delivered.high_water = None;
        self.delivered.clear_all();
        self.admission_issuer = None;
        self.next_delivery = NonZeroU64::MIN;
        self.bootstrap.take();
        if let Some(lease) = self.receive_preview.take() {
            lease.active.store(false, Ordering::Release);
        }
        self.receive_generation = u64::MAX;
        self.state = SessionState::Released;
        self.event(RedundantEvent::Released);
    }

    fn reap_preview(&mut self) {
        if self
            .receive_preview
            .as_ref()
            .is_some_and(|lease| !lease.active.load(Ordering::Acquire))
        {
            self.receive_preview.take();
        }
    }

    fn accepts_preview(&self, preview: &InboundPreview) -> bool {
        preview.owner == self.receive_owner
            && preview.generation == self.receive_generation
            && preview
                .lease
                .as_ref()
                .is_some_and(|lease| lease.active.load(Ordering::Acquire))
            && self.receive_preview.as_ref().is_some_and(|lease| {
                preview
                    .lease
                    .as_ref()
                    .is_some_and(|preview_lease| Arc::ptr_eq(lease, preview_lease))
            })
    }
    fn accepts_replay_lease(&self, lease: &InboundReplayLease) -> bool {
        lease.owner == self.receive_owner
            && lease.generation == self.receive_generation
            && lease.lease.active.load(Ordering::Acquire)
            && self
                .receive_preview
                .as_ref()
                .is_some_and(|pending| Arc::ptr_eq(pending, &lease.lease))
    }
    fn live(&self) -> Result<(), RedundantError> {
        (self.state == SessionState::Active)
            .then_some(())
            .ok_or(RedundantError::Released)
    }

    fn header(&self, slot: u8) -> Result<Header, RedundantError> {
        let bootstrap = self.bootstrap.as_ref().ok_or(RedundantError::Released)?;
        let path = self
            .paths
            .get(usize::from(slot))
            .ok_or(RedundantError::PathUnavailable)?;
        Ok(Header {
            profile: 3,
            tc: 0,
            next_header: r8_proto::NH_SES,
            hop_limit: 64,
            flags: if slot == 0 { 1 } else { 3 },
            path_slot: slot,
            scid: bootstrap.scid(),
            src: path.local_loc.ok_or(RedundantError::PathUnavailable)?,
            dst: path.peer_loc.ok_or(RedundantError::PathUnavailable)?,
        })
    }

    fn event(&mut self, event: RedundantEvent) {
        if self.events.len() == EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    fn expire(&mut self, now_ms: u64) {
        self.dedup.retain(|_, entry| entry.expiry_ms > now_ms);
    }

    fn commit(
        &mut self,
        slot: u8,
        preview: r8_session::Profile3DataPreview,
    ) -> Result<(NonZeroU64, Vec<u8>), RedundantError> {
        self.paths
            .get_mut(usize::from(slot))
            .ok_or(RedundantError::PathUnavailable)?
            .session
            .as_mut()
            .ok_or(RedundantError::PathUnavailable)?
            .commit_profile3_data(preview)
            .map_err(map_session)
    }
}

impl Drop for RedundantSession {
    fn drop(&mut self) {
        self.close();
    }
}

fn map_session(error: SessionError) -> RedundantError {
    match error {
        SessionError::Budget => RedundantError::MtuExceeded,
        SessionError::CounterExhausted => RedundantError::CounterExhausted,
        SessionError::CounterRange | SessionError::Replay => RedundantError::Replay,
        _ => RedundantError::AuthFailed,
    }
}

#[cfg(test)]
mod delivered_window_tests {
    use super::*;

    fn window() -> DeliveredWindow {
        DeliveredWindow {
            high_water: None,
            bits: [0; DELIVERED_WINDOW_WORDS],
            fingerprints: Zeroizing::new(vec![None; DELIVERED_WINDOW_IDS].into_boxed_slice()),
        }
    }

    #[test]
    fn retains_digest_and_length_for_a_seen_delivery() {
        let mut window = window();
        let id = NonZeroU64::new(7).expect("nonzero");
        window.insert(id, b"same");
        assert!(window.seen(id));
        assert!(window.matches(id, b"same"));
        assert!(!window.matches(id, b"different"));
    }

    #[test]
    fn evicts_fingerprint_when_window_advances() {
        let mut window = window();
        let first = NonZeroU64::new(1).expect("nonzero");
        window.insert(first, b"first");
        let next = NonZeroU64::new(1 + DELIVERED_WINDOW_IDS as u64).expect("nonzero");
        window.insert(next, b"next");
        assert!(window.too_old(first));
        assert!(!window.seen(first));
        assert!(window.matches(next, b"next"));
    }
}
