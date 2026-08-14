//! Strict R8M1 candidate binding controls.

use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use r8_session::{Identity, UdpBinding};
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub const SESSION_VERSION: u8 = 1;
pub const LOC_UPDATE: u8 = 1;
pub const BIND_PROBE: u8 = 2;
pub const BIND_CHALLENGE: u8 = 3;
pub const BIND_RESPONSE: u8 = 4;
pub const CANDIDATE_RESULT: u8 = 5;
pub const LIVE_CANDIDATES_MAX: usize = 2;
pub const PROPOSAL_SLOTS: usize = 2;
pub const RESULT_CACHE_SLOTS: usize = 2;
pub const CHALLENGE_EXPIRY_MS: u64 = 3_000;
pub const OLD_BINDING_GRACE_MS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MobilityError {
    Candidate,
    Capacity,
    Timeout,
    Replay,
}
impl MobilityError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "E-CANDIDATE",
            Self::Capacity => "E-CAPACITY",
            Self::Timeout => "E-TIMEOUT",
            Self::Replay => "E-REPLAY",
        }
    }
}
impl core::fmt::Display for MobilityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::error::Error for MobilityError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservedBinding {
    Udp(UdpBinding),
    Native {
        ingress_descriptor_id: u32,
        next_hop_mac: [u8; 6],
    },
}
impl ObservedBinding {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Udp(binding) => binding.as_bytes().to_vec(),
            Self::Native {
                ingress_descriptor_id,
                next_hop_mac,
            } => {
                let mut out = vec![2];
                out.extend_from_slice(&ingress_descriptor_id.to_be_bytes());
                out.extend_from_slice(next_hop_mac);
                out
            }
        }
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, MobilityError> {
        match bytes.first() {
            Some(1) => UdpBinding::parse(bytes.to_vec())
                .map(Self::Udp)
                .map_err(|_| MobilityError::Candidate),
            Some(2) if bytes.len() == 11 => {
                let descriptor = u32::from_be_bytes(
                    bytes[1..5]
                        .try_into()
                        .map_err(|_| MobilityError::Candidate)?,
                );
                if descriptor == 0 {
                    return Err(MobilityError::Candidate);
                }
                Ok(Self::Native {
                    ingress_descriptor_id: descriptor,
                    next_hop_mac: bytes[5..]
                        .try_into()
                        .map_err(|_| MobilityError::Candidate)?,
                })
            }
            _ => Err(MobilityError::Candidate),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Control {
    LocUpdate {
        candidate_id: [u8; 16],
        old_loc: [u8; 16],
        new_loc: [u8; 16],
        epoch: u64,
        not_before_ms: u64,
        valid_for_ms: u64,
        path_slot: u8,
        signature: [u8; 64],
    },
    BindProbe {
        candidate_id: [u8; 16],
        loc: [u8; 16],
        epoch: u64,
        path_slot: u8,
        probe_nonce: [u8; 16],
    },
    BindChallenge {
        candidate_id: [u8; 16],
        loc: [u8; 16],
        epoch: u64,
        path_slot: u8,
        expiry_ms: u64,
        token: [u8; 32],
    },
    BindResponse {
        candidate_id: [u8; 16],
        loc: [u8; 16],
        epoch: u64,
        path_slot: u8,
        expiry_ms: u64,
        token: [u8; 32],
    },
    CandidateResult {
        candidate_id: [u8; 16],
        epoch: u64,
        path_slot: u8,
        result: u8,
    },
}
impl Control {
    pub fn typ(&self) -> u8 {
        match self {
            Self::LocUpdate { .. } => LOC_UPDATE,
            Self::BindProbe { .. } => BIND_PROBE,
            Self::BindChallenge { .. } => BIND_CHALLENGE,
            Self::BindResponse { .. } => BIND_RESPONSE,
            Self::CandidateResult { .. } => CANDIDATE_RESULT,
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, MobilityError> {
        let mut out = b"R8M1".to_vec();
        out.extend_from_slice(&[self.typ(), 1, 0, 0]);
        match self {
            Self::LocUpdate {
                candidate_id,
                old_loc,
                new_loc,
                epoch,
                not_before_ms,
                valid_for_ms,
                path_slot,
                signature,
            } => {
                out.extend_from_slice(candidate_id);
                out.extend_from_slice(old_loc);
                out.extend_from_slice(new_loc);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(&not_before_ms.to_be_bytes());
                out.extend_from_slice(&valid_for_ms.to_be_bytes());
                out.push(*path_slot);
                out.extend_from_slice(signature);
            }
            Self::BindProbe {
                candidate_id,
                loc,
                epoch,
                path_slot,
                probe_nonce,
            } => {
                out.extend_from_slice(candidate_id);
                out.extend_from_slice(loc);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.push(*path_slot);
                out.extend_from_slice(probe_nonce);
            }
            Self::BindChallenge {
                candidate_id,
                loc,
                epoch,
                path_slot,
                expiry_ms,
                token,
            }
            | Self::BindResponse {
                candidate_id,
                loc,
                epoch,
                path_slot,
                expiry_ms,
                token,
            } => {
                out.extend_from_slice(candidate_id);
                out.extend_from_slice(loc);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.push(*path_slot);
                out.extend_from_slice(&expiry_ms.to_be_bytes());
                out.extend_from_slice(token);
            }
            Self::CandidateResult {
                candidate_id,
                epoch,
                path_slot,
                result,
            } => {
                out.extend_from_slice(candidate_id);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.push(*path_slot);
                out.push(*result);
            }
        }
        Ok(out)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, MobilityError> {
        if bytes.len() < 8 || &bytes[..4] != b"R8M1" || bytes[5] != 1 || bytes[6..8] != [0, 0] {
            return Err(MobilityError::Candidate);
        }
        let a16 = |offset| -> Result<[u8; 16], MobilityError> {
            bytes
                .get(offset..offset + 16)
                .ok_or(MobilityError::Candidate)?
                .try_into()
                .map_err(|_| MobilityError::Candidate)
        };
        let u64at = |offset| -> Result<u64, MobilityError> {
            Ok(u64::from_be_bytes(
                bytes
                    .get(offset..offset + 8)
                    .ok_or(MobilityError::Candidate)?
                    .try_into()
                    .map_err(|_| MobilityError::Candidate)?,
            ))
        };
        let control = match (bytes[4], bytes.len()) {
            (LOC_UPDATE, 145) => Ok(Self::LocUpdate {
                candidate_id: a16(8)?,
                old_loc: a16(24)?,
                new_loc: a16(40)?,
                epoch: u64at(56)?,
                not_before_ms: u64at(64)?,
                valid_for_ms: u64at(72)?,
                path_slot: bytes[80],
                signature: bytes[81..145]
                    .try_into()
                    .map_err(|_| MobilityError::Candidate)?,
            }),
            (BIND_PROBE, 65) => Ok(Self::BindProbe {
                candidate_id: a16(8)?,
                loc: a16(24)?,
                epoch: u64at(40)?,
                path_slot: bytes[48],
                probe_nonce: a16(49)?,
            }),
            (BIND_CHALLENGE, 89) | (BIND_RESPONSE, 89) => {
                let id = a16(8)?;
                let loc = a16(24)?;
                let epoch = u64at(40)?;
                let slot = bytes[48];
                let expiry = u64at(49)?;
                let token = bytes[57..89]
                    .try_into()
                    .map_err(|_| MobilityError::Candidate)?;
                if bytes[4] == BIND_CHALLENGE {
                    Ok(Self::BindChallenge {
                        candidate_id: id,
                        loc,
                        epoch,
                        path_slot: slot,
                        expiry_ms: expiry,
                        token,
                    })
                } else {
                    Ok(Self::BindResponse {
                        candidate_id: id,
                        loc,
                        epoch,
                        path_slot: slot,
                        expiry_ms: expiry,
                        token,
                    })
                }
            }
            (CANDIDATE_RESULT, 34) => Ok(Self::CandidateResult {
                candidate_id: a16(8)?,
                epoch: u64at(24)?,
                path_slot: bytes[32],
                result: bytes[33],
            }),
            _ => Err(MobilityError::Candidate),
        }?;
        let (candidate_id, path_slot, result) = match &control {
            Self::LocUpdate {
                candidate_id,
                path_slot,
                ..
            }
            | Self::BindProbe {
                candidate_id,
                path_slot,
                ..
            }
            | Self::BindChallenge {
                candidate_id,
                path_slot,
                ..
            }
            | Self::BindResponse {
                candidate_id,
                path_slot,
                ..
            } => (*candidate_id, *path_slot, None),
            Self::CandidateResult {
                candidate_id,
                path_slot,
                result,
                ..
            } => (*candidate_id, *path_slot, Some(*result)),
        };
        if candidate_id == [0; 16]
            || path_slot > 1
            || result.is_some_and(|value| !(1..=3).contains(&value))
        {
            return Err(MobilityError::Candidate);
        }
        Ok(control)
    }
}

#[derive(Clone, Copy)]
pub struct MobilityContext<'a> {
    pub profile: u8,
    pub scid: u64,
    pub sender: &'a Identity,
    pub receiver: &'a Identity,
    pub policy_id: u32,
}

#[derive(Clone, Copy)]
pub struct LocUpdateFields {
    pub candidate_id: [u8; 16],
    pub old_loc: [u8; 16],
    pub new_loc: [u8; 16],
    pub epoch: u64,
    pub path_slot: u8,
}

#[derive(Clone, Copy)]
pub struct TokenFields<'a> {
    pub candidate_id: [u8; 16],
    pub loc: [u8; 16],
    pub binding: &'a ObservedBinding,
    pub epoch: u64,
    pub path_slot: u8,
    pub expiry_ms: u64,
}
fn profile_allows_slot(profile: u8, path_slot: u8) -> bool {
    matches!((profile, path_slot), (0..=2, 0) | (3, 1))
}

pub fn loc_update_signature_input(
    context: MobilityContext<'_>,
    fields: LocUpdateFields,
) -> Result<Vec<u8>, MobilityError> {
    if context.profile > 3
        || context.sender.role == context.receiver.role
        || !(1..=2).contains(&context.sender.role)
        || !(1..=2).contains(&context.receiver.role)
        || !profile_allows_slot(context.profile, fields.path_slot)
    {
        return Err(MobilityError::Candidate);
    }
    let mut out = b"R8 LOC_UPDATE v1".to_vec();
    out.extend_from_slice(&[SESSION_VERSION, context.profile]);
    out.extend_from_slice(&context.scid.to_be_bytes());
    out.extend_from_slice(&context.sender.eid);
    out.extend_from_slice(&context.receiver.eid);
    out.extend_from_slice(&fields.old_loc);
    out.extend_from_slice(&fields.new_loc);
    out.extend_from_slice(&fields.epoch.to_be_bytes());
    out.extend_from_slice(&0_u64.to_be_bytes());
    out.extend_from_slice(&5_000_u64.to_be_bytes());
    out.extend_from_slice(&fields.candidate_id);
    out.push(fields.path_slot);
    Ok(out)
}

pub fn sign_loc_update(
    signing: &SigningKey,
    context: MobilityContext<'_>,
    fields: LocUpdateFields,
) -> Result<Control, MobilityError> {
    let input = loc_update_signature_input(context, fields)?;
    Ok(Control::LocUpdate {
        candidate_id: fields.candidate_id,
        old_loc: fields.old_loc,
        new_loc: fields.new_loc,
        epoch: fields.epoch,
        not_before_ms: 0,
        valid_for_ms: 5_000,
        path_slot: fields.path_slot,
        signature: signing.sign(&input).to_bytes(),
    })
}

pub fn verify_loc_update(
    control: &Control,
    context: MobilityContext<'_>,
) -> Result<(), MobilityError> {
    if let Control::LocUpdate {
        candidate_id,
        old_loc,
        new_loc,
        epoch,
        not_before_ms,
        valid_for_ms,
        path_slot,
        signature,
    } = control
    {
        if *not_before_ms != 0 || *valid_for_ms != 5_000 {
            return Err(MobilityError::Candidate);
        }
        let input = loc_update_signature_input(
            context,
            LocUpdateFields {
                candidate_id: *candidate_id,
                old_loc: *old_loc,
                new_loc: *new_loc,
                epoch: *epoch,
                path_slot: *path_slot,
            },
        )?;
        VerifyingKey::from_bytes(&context.sender.public_key)
            .map_err(|_| MobilityError::Candidate)?
            .verify(&input, &Signature::from_bytes(signature))
            .map_err(|_| MobilityError::Candidate)
    } else {
        Err(MobilityError::Candidate)
    }
}

pub fn token_input(
    context: MobilityContext<'_>,
    fields: TokenFields<'_>,
) -> Result<Vec<u8>, MobilityError> {
    if context.profile > 3
        || !profile_allows_slot(context.profile, fields.path_slot)
        || context.sender.role == context.receiver.role
        || !(1..=2).contains(&context.sender.role)
        || !(1..=2).contains(&context.receiver.role)
    {
        return Err(MobilityError::Candidate);
    }
    let direction = if context.sender.role == 1 { 1 } else { 2 };
    let mut out = b"R8 bind v1".to_vec();
    out.extend_from_slice(&[SESSION_VERSION, context.profile]);
    out.extend_from_slice(&context.scid.to_be_bytes());
    out.extend_from_slice(&context.sender.eid);
    out.extend_from_slice(&context.receiver.eid);
    out.extend_from_slice(&fields.candidate_id);
    out.extend_from_slice(&fields.loc);
    out.extend_from_slice(&fields.binding.encode());
    out.push(direction);
    out.extend_from_slice(&fields.epoch.to_be_bytes());
    out.push(fields.path_slot);
    out.extend_from_slice(&context.policy_id.to_be_bytes());
    out.extend_from_slice(&fields.expiry_ms.to_be_bytes());
    Ok(out)
}

pub fn token(
    secret: &[u8; 32],
    context: MobilityContext<'_>,
    fields: TokenFields<'_>,
) -> Result<[u8; 32], MobilityError> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| MobilityError::Candidate)?;
    mac.update(&token_input(context, fields)?);
    Ok(mac.finalize().into_bytes().into())
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub policy_id: u32,
}
#[derive(Clone, Debug)]
struct Proposal {
    bytes: Vec<u8>,
    candidate_id: [u8; 16],
    loc: [u8; 16],
    epoch: u64,
    slot: u8,
    expiry_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateState {
    Challenged,
    Proven,
    Failed,
    Promoted,
    Released,
}

#[derive(Clone, Debug)]
struct Candidate {
    candidate_id: [u8; 16],
    loc: [u8; 16],
    epoch: u64,
    slot: u8,
    binding: ObservedBinding,
    expiry_ms: u64,
    state: CandidateState,
}

#[derive(Clone, Debug)]
struct ResultEntry {
    candidate_id: [u8; 16],
    epoch: u64,
    slot: u8,
    bytes: Vec<u8>,
    expiry_ms: u64,
}

#[derive(Clone, Debug)]
struct OutboundCandidate {
    candidate_id: [u8; 16],
    loc: [u8; 16],
    epoch: u64,
    slot: u8,
    binding: Option<ObservedBinding>,
    expiry_ms: u64,
}

struct State {
    generation: u64,
    closed: bool,
    local_epoch: u64,
    peer_epoch: u64,
    local_loc: [u8; 16],
    peer_loc: [u8; 16],
    current_binding: ObservedBinding,
    old_binding: Option<(ObservedBinding, u64)>,
    proposals: Vec<Proposal>,
    candidates: Vec<Candidate>,
    results: Vec<ResultEntry>,
    proposal_tokens: u8,
    proposal_refill_ms: u64,
    candidate_secret: Option<Zeroizing<[u8; 32]>>,
    frozen_cohort: Option<(u64, Vec<[u8; 16]>)>,
    outbound: Vec<OutboundCandidate>,
    emitted_results: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
enum Action {
    CacheProposal {
        proposal: Proposal,
        tokens: u8,
        refill_ms: u64,
    },
    Challenge(Candidate),
    ExistingChallenge(Candidate),
    Respond(Control),
    CommitLocal {
        candidate_id: [u8; 16],
        epoch: u64,
        result: ResultEntry,
    },
    Prove {
        candidate_id: [u8; 16],
        epoch: u64,
        slot: u8,
        outcomes: Vec<ResultEntry>,
        promoted: Option<[u8; 16]>,
        grace_until_ms: u64,
    },
    None,
}

pub struct Transition {
    generation: u64,
    action: Action,
}

pub struct CandidateManagerConfig {
    pub signing: SigningKey,
    pub local: Identity,
    pub peer: Identity,
    pub profile: u8,
    pub scid: u64,
    pub policy: Policy,
    pub local_loc: [u8; 16],
    pub peer_loc: [u8; 16],
    pub initial_peer_binding: ObservedBinding,
    pub candidate_secret: [u8; 32],
}

#[derive(Clone)]
pub struct CandidateManager {
    signing: SigningKey,
    local: Identity,
    peer: Identity,
    profile: u8,
    scid: u64,
    policy: Policy,
    state: Arc<Mutex<State>>,
}
impl core::fmt::Debug for CandidateManager {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CandidateManager")
            .field("profile", &self.profile)
            .field("policy_id", &self.policy.policy_id)
            .finish_non_exhaustive()
    }
}
impl CandidateManager {
    pub fn new(config: CandidateManagerConfig) -> Result<Self, MobilityError> {
        let CandidateManagerConfig {
            signing,
            local,
            peer,
            profile,
            scid,
            policy,
            local_loc,
            peer_loc,
            initial_peer_binding,
            candidate_secret,
        } = config;
        if profile > 3
            || scid == 0
            || local.validate().is_err()
            || peer.validate().is_err()
            || ObservedBinding::parse(&initial_peer_binding.encode()).is_err()
            || local.role == peer.role
            || signing.verifying_key().to_bytes() != local.public_key
        {
            return Err(MobilityError::Candidate);
        }
        Ok(Self {
            signing,
            local,
            peer,
            profile,
            scid,
            policy,
            state: Arc::new(Mutex::new(State {
                generation: 0,
                closed: false,
                local_epoch: 0,
                peer_epoch: 0,
                local_loc,
                peer_loc,
                current_binding: initial_peer_binding,
                old_binding: None,
                proposals: Vec::new(),
                candidates: Vec::new(),
                results: Vec::new(),
                proposal_tokens: 2,
                proposal_refill_ms: 0,
                candidate_secret: Some(Zeroizing::new(candidate_secret)),
                frozen_cohort: None,
                outbound: Vec::new(),
                emitted_results: Vec::new(),
            })),
        })
    }
    pub fn propose_local(
        &self,
        candidate_id: [u8; 16],
        new_loc: [u8; 16],
        epoch: u64,
        path_slot: u8,
        now_ms: u64,
    ) -> Result<Control, MobilityError> {
        let mut state = self.state.lock().map_err(|_| MobilityError::Candidate)?;
        if state.closed
            || candidate_id == [0; 16]
            || epoch <= state.local_epoch
            || !profile_allows_slot(self.profile, path_slot)
        {
            return Err(MobilityError::Candidate);
        }
        if let Some(existing) = state
            .outbound
            .iter()
            .find(|candidate| candidate.candidate_id == candidate_id)
        {
            if existing.loc == new_loc && existing.epoch == epoch && existing.slot == path_slot {
                return sign_loc_update(
                    &self.signing,
                    MobilityContext {
                        profile: self.profile,
                        scid: self.scid,
                        sender: &self.local,
                        receiver: &self.peer,
                        policy_id: self.policy.policy_id,
                    },
                    LocUpdateFields {
                        candidate_id,
                        old_loc: state.local_loc,
                        new_loc,
                        epoch,
                        path_slot,
                    },
                );
            }
            return Err(MobilityError::Candidate);
        }
        if state.outbound.len() == PROPOSAL_SLOTS {
            return Err(MobilityError::Capacity);
        }
        let update = sign_loc_update(
            &self.signing,
            MobilityContext {
                profile: self.profile,
                scid: self.scid,
                sender: &self.local,
                receiver: &self.peer,
                policy_id: self.policy.policy_id,
            },
            LocUpdateFields {
                candidate_id,
                old_loc: state.local_loc,
                new_loc,
                epoch,
                path_slot,
            },
        )?;
        state.outbound.push(OutboundCandidate {
            candidate_id,
            loc: new_loc,
            epoch,
            slot: path_slot,
            binding: None,
            expiry_ms: now_ms.saturating_add(5_000),
        });
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(MobilityError::Replay)?;
        Ok(update)
    }

    pub fn make_probe(
        &self,
        candidate_id: [u8; 16],
        carrier: ObservedBinding,
        probe_nonce: [u8; 16],
        now_ms: u64,
    ) -> Result<Control, MobilityError> {
        let mut state = self.state.lock().map_err(|_| MobilityError::Candidate)?;
        if state.closed {
            return Err(MobilityError::Candidate);
        }
        let candidate = state
            .outbound
            .iter_mut()
            .find(|candidate| candidate.candidate_id == candidate_id)
            .ok_or(MobilityError::Candidate)?;
        if now_ms >= candidate.expiry_ms {
            return Err(MobilityError::Candidate);
        }
        if let Some(binding) = &candidate.binding {
            if binding != &carrier {
                return Err(MobilityError::Candidate);
            }
        } else {
            candidate.binding = Some(carrier);
        }
        Ok(Control::BindProbe {
            candidate_id: candidate.candidate_id,
            loc: candidate.loc,
            epoch: candidate.epoch,
            path_slot: candidate.slot,
            probe_nonce,
        })
    }
    pub fn preview(
        &self,
        plaintext: &[u8],
        binding: &ObservedBinding,
        replay_token: u64,
        now_ms: u64,
    ) -> Result<Transition, MobilityError> {
        if replay_token == 0 {
            return Err(MobilityError::Replay);
        }
        let control = Control::parse(plaintext)?;
        let path_slot = match &control {
            Control::LocUpdate { path_slot, .. }
            | Control::BindProbe { path_slot, .. }
            | Control::BindChallenge { path_slot, .. }
            | Control::BindResponse { path_slot, .. }
            | Control::CandidateResult { path_slot, .. } => *path_slot,
        };
        if !profile_allows_slot(self.profile, path_slot) {
            return Err(MobilityError::Candidate);
        }
        let state = self.state.lock().map_err(|_| MobilityError::Candidate)?;
        if state.closed {
            return Err(MobilityError::Candidate);
        }
        let action = match &control {
            Control::LocUpdate {
                candidate_id,
                old_loc,
                new_loc,
                epoch,
                path_slot,
                ..
            } => {
                verify_loc_update(
                    &control,
                    MobilityContext {
                        profile: self.profile,
                        scid: self.scid,
                        sender: &self.peer,
                        receiver: &self.local,
                        policy_id: self.policy.policy_id,
                    },
                )?;
                if *old_loc != state.peer_loc || *epoch <= state.peer_epoch {
                    return Err(MobilityError::Candidate);
                }
                let bytes = control.encode()?;
                if let Some(proposal) = state
                    .proposals
                    .iter()
                    .find(|proposal| proposal.candidate_id == *candidate_id)
                {
                    if proposal.bytes == bytes {
                        Action::None
                    } else {
                        return Err(MobilityError::Candidate);
                    }
                } else if state
                    .candidates
                    .iter()
                    .any(|candidate| candidate.candidate_id == *candidate_id)
                    || state
                        .outbound
                        .iter()
                        .any(|candidate| candidate.candidate_id == *candidate_id)
                    || state
                        .results
                        .iter()
                        .any(|entry| entry.candidate_id == *candidate_id)
                {
                    return Err(MobilityError::Candidate);
                } else {
                    if state.proposals.len() == PROPOSAL_SLOTS {
                        return Err(MobilityError::Capacity);
                    }
                    let elapsed = now_ms.saturating_sub(state.proposal_refill_ms) / 1_000;
                    let tokens = (u64::from(state.proposal_tokens) + elapsed).min(2) as u8;
                    if tokens == 0 {
                        return Err(MobilityError::Candidate);
                    }
                    Action::CacheProposal {
                        proposal: Proposal {
                            bytes,
                            candidate_id: *candidate_id,
                            loc: *new_loc,
                            epoch: *epoch,
                            slot: *path_slot,
                            expiry_ms: now_ms.saturating_add(5_000),
                        },
                        tokens: tokens - 1,
                        refill_ms: state.proposal_refill_ms.saturating_add(elapsed * 1_000),
                    }
                }
            }
            Control::BindProbe {
                candidate_id,
                loc,
                epoch,
                path_slot,
                ..
            } => {
                let proposal = state
                    .proposals
                    .iter()
                    .find(|proposal| {
                        proposal.candidate_id == *candidate_id
                            && proposal.loc == *loc
                            && proposal.epoch == *epoch
                            && proposal.slot == *path_slot
                            && now_ms < proposal.expiry_ms
                    })
                    .ok_or(MobilityError::Candidate)?;
                if let Some(candidate) = state.candidates.iter().find(|candidate| {
                    candidate.candidate_id == *candidate_id
                        && candidate.loc == *loc
                        && candidate.epoch == *epoch
                        && candidate.slot == *path_slot
                        && candidate.binding == *binding
                }) {
                    if candidate.state == CandidateState::Challenged {
                        Action::ExistingChallenge(candidate.clone())
                    } else {
                        return Err(MobilityError::Candidate);
                    }
                } else {
                    let bindings = 1 + usize::from(state.old_binding.is_some());
                    if state.candidates.len() == LIVE_CANDIDATES_MAX
                        || bindings == LIVE_CANDIDATES_MAX
                    {
                        return Err(MobilityError::Capacity);
                    }
                    Action::Challenge(Candidate {
                        candidate_id: proposal.candidate_id,
                        loc: proposal.loc,
                        epoch: proposal.epoch,
                        slot: proposal.slot,
                        binding: binding.clone(),
                        expiry_ms: now_ms.saturating_add(CHALLENGE_EXPIRY_MS),
                        state: CandidateState::Challenged,
                    })
                }
            }
            Control::BindResponse {
                candidate_id,
                loc,
                epoch,
                path_slot,
                expiry_ms,
                token: supplied,
            } => {
                if let Some(result) = state.results.iter().find(|entry| {
                    entry.candidate_id == *candidate_id
                        && entry.epoch == *epoch
                        && entry.slot == *path_slot
                        && now_ms < entry.expiry_ms
                }) {
                    let candidate = state
                        .candidates
                        .iter()
                        .find(|candidate| {
                            candidate.candidate_id == *candidate_id && candidate.binding == *binding
                        })
                        .ok_or(MobilityError::Candidate)?;
                    let control = Control::parse(&result.bytes)?;
                    if candidate.state == CandidateState::Promoted
                        || candidate.state == CandidateState::Failed
                    {
                        Action::Respond(control)
                    } else {
                        return Err(MobilityError::Candidate);
                    }
                } else {
                    let candidate = state
                        .candidates
                        .iter()
                        .find(|candidate| {
                            candidate.candidate_id == *candidate_id
                                && candidate.loc == *loc
                                && candidate.epoch == *epoch
                                && candidate.slot == *path_slot
                                && candidate.binding == *binding
                        })
                        .ok_or(MobilityError::Candidate)?;
                    if candidate.state != CandidateState::Challenged {
                        return Err(MobilityError::Candidate);
                    }
                    if now_ms >= candidate.expiry_ms || *expiry_ms != candidate.expiry_ms {
                        return Err(MobilityError::Timeout);
                    }
                    let secret = state
                        .candidate_secret
                        .as_ref()
                        .ok_or(MobilityError::Candidate)?;
                    let expected = token(
                        secret,
                        MobilityContext {
                            profile: self.profile,
                            scid: self.scid,
                            sender: &self.peer,
                            receiver: &self.local,
                            policy_id: self.policy.policy_id,
                        },
                        TokenFields {
                            candidate_id: *candidate_id,
                            loc: *loc,
                            binding,
                            epoch: *epoch,
                            path_slot: *path_slot,
                            expiry_ms: *expiry_ms,
                        },
                    )?;
                    if expected != *supplied {
                        return Err(MobilityError::Candidate);
                    }
                    let greatest = state
                        .proposals
                        .iter()
                        .map(|proposal| proposal.epoch)
                        .max()
                        .ok_or(MobilityError::Candidate)?;
                    let members = state
                        .frozen_cohort
                        .as_ref()
                        .filter(|(cohort_epoch, _)| *cohort_epoch == greatest)
                        .map(|(_, members)| members.clone())
                        .unwrap_or_else(|| {
                            state
                                .proposals
                                .iter()
                                .filter(|proposal| proposal.epoch == greatest)
                                .map(|proposal| proposal.candidate_id)
                                .collect()
                        });
                    let terminal = members.iter().all(|member| {
                        if *member == *candidate_id {
                            true
                        } else {
                            state.candidates.iter().any(|candidate| {
                                candidate.candidate_id == *member
                                    && matches!(
                                        candidate.state,
                                        CandidateState::Proven | CandidateState::Failed
                                    )
                            })
                        }
                    });
                    let mut outcomes = Vec::new();
                    let mut promoted = None;
                    if terminal {
                        let mut proven: Vec<[u8; 16]> = members
                            .iter()
                            .copied()
                            .filter(|member| {
                                *member == *candidate_id
                                    || state.candidates.iter().any(|candidate| {
                                        candidate.candidate_id == *member
                                            && candidate.state == CandidateState::Proven
                                    })
                            })
                            .collect();
                        proven.sort_unstable();
                        promoted = proven.first().copied();
                        for member in &members {
                            let candidate = if *member == *candidate_id {
                                Some((*loc, *epoch, *path_slot))
                            } else {
                                state
                                    .candidates
                                    .iter()
                                    .find(|candidate| candidate.candidate_id == *member)
                                    .map(|candidate| {
                                        (candidate.loc, candidate.epoch, candidate.slot)
                                    })
                            };
                            if let Some((_, result_epoch, result_slot)) = candidate {
                                let result = if Some(*member) == promoted { 1 } else { 2 };
                                let bytes = Control::CandidateResult {
                                    candidate_id: *member,
                                    epoch: result_epoch,
                                    path_slot: result_slot,
                                    result,
                                }
                                .encode()?;
                                outcomes.push(ResultEntry {
                                    candidate_id: *member,
                                    epoch: result_epoch,
                                    slot: result_slot,
                                    bytes,
                                    expiry_ms: now_ms.saturating_add(10_000),
                                });
                            }
                        }
                        if state.results.len().saturating_add(outcomes.len()) > RESULT_CACHE_SLOTS {
                            return Err(MobilityError::Capacity);
                        }
                    }
                    Action::Prove {
                        candidate_id: *candidate_id,
                        epoch: *epoch,
                        slot: *path_slot,
                        outcomes,
                        promoted,
                        grace_until_ms: now_ms.saturating_add(OLD_BINDING_GRACE_MS),
                    }
                }
            }
            Control::BindChallenge {
                candidate_id,
                loc,
                epoch,
                path_slot,
                expiry_ms,
                token,
            } => {
                let candidate = state
                    .outbound
                    .iter()
                    .find(|candidate| {
                        candidate.candidate_id == *candidate_id
                            && candidate.loc == *loc
                            && candidate.epoch == *epoch
                            && candidate.slot == *path_slot
                            && candidate.binding.as_ref() == Some(binding)
                            && now_ms < candidate.expiry_ms
                    })
                    .ok_or(MobilityError::Candidate)?;
                Action::Respond(Control::BindResponse {
                    candidate_id: candidate.candidate_id,
                    loc: candidate.loc,
                    epoch: candidate.epoch,
                    path_slot: candidate.slot,
                    expiry_ms: *expiry_ms,
                    token: *token,
                })
            }
            Control::CandidateResult {
                candidate_id,
                epoch,
                path_slot,
                result,
            } => {
                let candidate = state
                    .outbound
                    .iter()
                    .find(|candidate| {
                        candidate.candidate_id == *candidate_id
                            && candidate.epoch == *epoch
                            && candidate.slot == *path_slot
                            && candidate.binding.as_ref() == Some(binding)
                    })
                    .ok_or(MobilityError::Candidate)?;
                if state.results.iter().any(|entry| {
                    entry.candidate_id == *candidate_id
                        && entry.epoch == *epoch
                        && entry.slot == *path_slot
                }) {
                    Action::None
                } else if state.results.len() >= RESULT_CACHE_SLOTS {
                    return Err(MobilityError::Capacity);
                } else if *result == 1 {
                    Action::CommitLocal {
                        candidate_id: candidate.candidate_id,
                        epoch: candidate.epoch,
                        result: ResultEntry {
                            candidate_id: *candidate_id,
                            epoch: *epoch,
                            slot: *path_slot,
                            bytes: control.encode()?,
                            expiry_ms: now_ms.saturating_add(10_000),
                        },
                    }
                } else {
                    Action::None
                }
            }
        };
        Ok(Transition {
            generation: state.generation,
            action,
        })
    }

    pub fn response_for(&self, transition: &Transition) -> Result<Option<Control>, MobilityError> {
        let state = self.state.lock().map_err(|_| MobilityError::Candidate)?;
        if state.closed || state.generation != transition.generation {
            return Err(MobilityError::Replay);
        }
        let candidate = match &transition.action {
            Action::Challenge(candidate) | Action::ExistingChallenge(candidate) => candidate,
            Action::Respond(control) => return Ok(Some(control.clone())),
            _ => return Ok(None),
        };
        let secret = state
            .candidate_secret
            .as_ref()
            .ok_or(MobilityError::Candidate)?;
        let token = token(
            secret,
            MobilityContext {
                profile: self.profile,
                scid: self.scid,
                sender: &self.peer,
                receiver: &self.local,
                policy_id: self.policy.policy_id,
            },
            TokenFields {
                candidate_id: candidate.candidate_id,
                loc: candidate.loc,
                binding: &candidate.binding,
                epoch: candidate.epoch,
                path_slot: candidate.slot,
                expiry_ms: candidate.expiry_ms,
            },
        )?;
        Ok(Some(Control::BindChallenge {
            candidate_id: candidate.candidate_id,
            loc: candidate.loc,
            epoch: candidate.epoch,
            path_slot: candidate.slot,
            expiry_ms: candidate.expiry_ms,
            token,
        }))
    }

    pub fn commit(
        &self,
        transition: Transition,
        replay_commit: impl FnOnce() -> Result<(), MobilityError>,
        idle_commit: impl FnOnce(),
    ) -> Result<(), MobilityError> {
        let mut state = self.state.lock().map_err(|_| MobilityError::Candidate)?;
        if state.closed || state.generation != transition.generation {
            return Err(MobilityError::Replay);
        }
        replay_commit()?;
        match transition.action {
            Action::CacheProposal {
                proposal,
                tokens,
                refill_ms,
            } => {
                state.proposal_tokens = tokens;
                state.proposal_refill_ms = refill_ms;
                state.proposals.push(proposal);
            }
            Action::Challenge(candidate) => state.candidates.push(candidate),
            Action::ExistingChallenge(_) => {}
            Action::Respond(_) => {}
            Action::CommitLocal {
                candidate_id,
                epoch,
                result,
            } => {
                let (loc, binding, expiry_ms) = state
                    .outbound
                    .iter()
                    .find(|candidate| {
                        candidate.candidate_id == candidate_id && candidate.epoch == epoch
                    })
                    .map(|candidate| {
                        (
                            candidate.loc,
                            candidate.binding.clone(),
                            candidate.expiry_ms,
                        )
                    })
                    .ok_or(MobilityError::Candidate)?;
                let binding = binding.ok_or(MobilityError::Candidate)?;
                state.results.push(result);
                state.local_epoch = epoch;
                state.local_loc = loc;
                state.old_binding = Some((
                    state.current_binding.clone(),
                    expiry_ms.saturating_add(OLD_BINDING_GRACE_MS),
                ));
                state.current_binding = binding;
                state.outbound.retain(|candidate| candidate.epoch > epoch);
            }
            Action::Prove {
                candidate_id,
                epoch,
                slot,
                outcomes,
                promoted,
                grace_until_ms,
            } => {
                let candidate = state
                    .candidates
                    .iter_mut()
                    .find(|candidate| {
                        candidate.candidate_id == candidate_id
                            && candidate.epoch == epoch
                            && candidate.slot == slot
                    })
                    .expect("transition generation protects candidate");
                candidate.state = CandidateState::Proven;
                if state.frozen_cohort.is_none() {
                    let members = state
                        .proposals
                        .iter()
                        .filter(|proposal| proposal.epoch == epoch)
                        .map(|proposal| proposal.candidate_id)
                        .collect();
                    state.frozen_cohort = Some((epoch, members));
                }
                if let Some(winner) = promoted {
                    let winner_candidate = state
                        .candidates
                        .iter()
                        .find(|candidate| candidate.candidate_id == winner)
                        .expect("terminal cohort members have candidates");
                    let loc = winner_candidate.loc;
                    let binding = winner_candidate.binding.clone();
                    state.peer_epoch = epoch;
                    state.peer_loc = loc;
                    state.old_binding = Some((state.current_binding.clone(), grace_until_ms));
                    state.current_binding = binding;
                    for candidate in &mut state.candidates {
                        if candidate.epoch == epoch {
                            candidate.state = if candidate.candidate_id == winner {
                                CandidateState::Promoted
                            } else {
                                CandidateState::Failed
                            };
                        }
                    }
                    state
                        .emitted_results
                        .extend(outcomes.iter().map(|entry| entry.bytes.clone()));
                    state.results.extend(outcomes);
                    state.proposals.retain(|proposal| proposal.epoch >= epoch);
                    state
                        .candidates
                        .retain(|candidate| candidate.epoch >= epoch);
                    state.frozen_cohort = Some((
                        epoch,
                        state
                            .proposals
                            .iter()
                            .filter(|proposal| proposal.epoch == epoch)
                            .map(|proposal| proposal.candidate_id)
                            .collect(),
                    ));
                }
            }
            Action::None => {}
        }
        idle_commit();
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(MobilityError::Replay)?;
        Ok(())
    }

    pub fn expire(&self, now_ms: u64) {
        if let Ok(mut state) = self.state.lock() {
            for candidate in &mut state.candidates {
                if now_ms >= candidate.expiry_ms && candidate.state == CandidateState::Challenged {
                    candidate.state = CandidateState::Failed;
                }
            }
            state
                .proposals
                .retain(|proposal| now_ms < proposal.expiry_ms);
            state
                .candidates
                .retain(|candidate| candidate.state != CandidateState::Released);
            state.results.retain(|result| now_ms < result.expiry_ms);
            state
                .outbound
                .retain(|candidate| now_ms < candidate.expiry_ms);
            if state
                .old_binding
                .as_ref()
                .is_some_and(|(_, expiry)| now_ms >= *expiry)
            {
                state.old_binding = None;
            }
        }
    }

    pub fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            state.proposals.clear();
            state.candidates.clear();
            state.results.clear();
            state.outbound.clear();
            state.emitted_results.clear();
            state.old_binding = None;
            state.frozen_cohort = None;
            state.candidate_secret = None;
            state.generation = state.generation.wrapping_add(1);
        }
    }

    pub fn restart(&self) {
        self.close();
    }

    pub fn policy_id(&self) -> u32 {
        self.policy.policy_id
    }

    pub fn peer_loc(&self) -> [u8; 16] {
        self.state
            .lock()
            .map(|state| state.peer_loc)
            .unwrap_or([0; 16])
    }
    pub fn local_loc(&self) -> [u8; 16] {
        self.state
            .lock()
            .map(|state| state.local_loc)
            .unwrap_or([0; 16])
    }

    pub fn current_binding(&self) -> Option<ObservedBinding> {
        self.state
            .lock()
            .ok()
            .map(|state| state.current_binding.clone())
    }

    pub fn binding_allowed_inbound(&self, binding: &ObservedBinding, now_ms: u64) -> bool {
        self.state.lock().is_ok_and(|state| {
            binding == &state.current_binding
                || state
                    .old_binding
                    .as_ref()
                    .is_some_and(|(old, expiry)| binding == old && now_ms < *expiry)
        })
    }

    pub fn take_results(&self) -> Vec<Control> {
        let Ok(mut state) = self.state.lock() else {
            return Vec::new();
        };
        std::mem::take(&mut state.emitted_results)
            .into_iter()
            .filter_map(|bytes| Control::parse(&bytes).ok())
            .collect()
    }
}
#[cfg(test)]
mod corpus_negative_state_machine {
    use super::*;
    use serde_json::Value;
    use sha2::Digest;
    use std::collections::BTreeSet;

    const VECTORS: &str = include_str!("../../../../tests/vectors/mobility-v0.1.json");

    fn hex(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("fixture hex"))
            .collect()
    }
    fn bytes<const N: usize>(value: &str) -> [u8; N] {
        hex(value).try_into().expect("fixture byte width")
    }
    fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
        value
            .get(key)
            .unwrap_or_else(|| panic!("missing fixture field {key}"))
    }
    fn binding(value: &str) -> ObservedBinding {
        ObservedBinding::parse(&hex(value)).expect("typed fixture binding")
    }
    fn snapshot(manager: &CandidateManager, callbacks: usize) -> [u8; 32] {
        let state = manager.state.lock().expect("state lock");
        let redacted = format!(
            "{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}{callbacks}",
            state.generation,
            state.closed,
            state.local_epoch,
            state.peer_epoch,
            state.local_loc,
            state.peer_loc,
            state.current_binding,
            state.old_binding,
            state.proposals,
            state.candidates,
            state.results,
            state.proposal_tokens,
            state.proposal_refill_ms,
            state.frozen_cohort,
            state.outbound,
            state.emitted_results,
            state.candidate_secret.is_some(),
        );
        Sha256::digest(redacted.as_bytes()).into()
    }
    fn manager(setup: &Value, context: &Value) -> (CandidateManager, bool) {
        let session = field(setup, "session");
        let roles = setup.get("roles");
        let receiver = roles
            .and_then(|r| r.get("receiver"))
            .and_then(Value::as_u64)
            .unwrap_or(2) as u8;
        let sender = roles
            .and_then(|r| r.get("sender"))
            .and_then(Value::as_u64)
            .unwrap_or(1) as u8;
        let invalid_roles =
            !matches!(receiver, 1 | 2) || !matches!(sender, 1 | 2) || receiver == sender;
        let client = bytes(
            field(context, "client_public_key_hex")
                .as_str()
                .expect("client key"),
        );
        let server = bytes(
            field(context, "server_public_key_hex")
                .as_str()
                .expect("server key"),
        );
        let now = field(setup, "clock_ms").as_u64().expect("clock");
        let loc = bytes(field(setup, "current_loc_hex").as_str().expect("location"));
        let current = binding(
            field(setup, "current_binding_hex")
                .as_str()
                .expect("binding"),
        );
        let mut state = State {
            generation: 0,
            closed: false,
            local_epoch: 0,
            peer_epoch: setup
                .get("committed_epoch")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            local_loc: loc,
            peer_loc: loc,
            current_binding: current.clone(),
            old_binding: None,
            proposals: Vec::new(),
            candidates: Vec::new(),
            results: Vec::new(),
            proposal_tokens: 2,
            proposal_refill_ms: 0,
            candidate_secret: Some(Zeroizing::new([0x31; 32])),
            frozen_cohort: None,
            outbound: Vec::new(),
            emitted_results: Vec::new(),
        };
        if let Some(bucket) = setup.get("proposal_bucket") {
            state.proposal_tokens = field(bucket, "tokens").as_u64().expect("tokens") as u8;
            state.proposal_refill_ms = field(bucket, "last_refill_ms").as_u64().expect("refill");
        }
        for entry in field(setup, "proposal_cache")
            .as_array()
            .expect("proposals")
        {
            let id = bytes(field(entry, "candidate_id_hex").as_str().expect("id"));
            let candidate_loc = entry
                .get("loc_hex")
                .map(|v| bytes(v.as_str().expect("loc")))
                .unwrap_or(loc);
            let epoch = entry.get("epoch").and_then(Value::as_u64).unwrap_or(2);
            let slot = entry.get("slot").and_then(Value::as_u64).unwrap_or(0) as u8;
            let encoded = entry
                .get("canonical_input_hex")
                .map(|v| hex(v.as_str().expect("input")))
                .unwrap_or_else(|| {
                    Control::LocUpdate {
                        candidate_id: id,
                        old_loc: loc,
                        new_loc: candidate_loc,
                        epoch,
                        not_before_ms: 0,
                        valid_for_ms: 5000,
                        path_slot: slot,
                        signature: [0; 64],
                    }
                    .encode()
                    .expect("update")
                });
            state.proposals.push(Proposal {
                bytes: encoded,
                candidate_id: id,
                loc: candidate_loc,
                epoch,
                slot,
                expiry_ms: entry
                    .get("receipt_expiry_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(now + 5000),
            });
        }
        for entry in field(setup, "result_cache").as_array().expect("results") {
            let id = bytes(field(entry, "candidate_id_hex").as_str().expect("id"));
            let epoch = entry.get("epoch").and_then(Value::as_u64).unwrap_or(2);
            let slot = entry.get("slot").and_then(Value::as_u64).unwrap_or(0) as u8;
            state.results.push(ResultEntry {
                candidate_id: id,
                epoch,
                slot,
                bytes: Control::CandidateResult {
                    candidate_id: id,
                    epoch,
                    path_slot: slot,
                    result: 2,
                }
                .encode()
                .expect("result"),
                expiry_ms: entry
                    .get("expiry_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(now + 10000),
            });
        }
        for entry in field(setup, "live_candidates")
            .as_array()
            .expect("candidates")
        {
            let id = bytes(field(entry, "candidate_id_hex").as_str().expect("id"));
            let candidate_loc = entry
                .get("loc_hex")
                .map(|v| bytes(v.as_str().expect("loc")))
                .unwrap_or(loc);
            let epoch = entry.get("epoch").and_then(Value::as_u64).unwrap_or(2);
            let slot = entry.get("slot").and_then(Value::as_u64).unwrap_or(0) as u8;
            let observed = binding(field(entry, "binding_hex").as_str().expect("binding"));
            state.candidates.push(Candidate {
                candidate_id: id,
                loc: candidate_loc,
                epoch,
                slot,
                binding: observed.clone(),
                expiry_ms: setup
                    .get("challenge_expiry_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(now + 3000),
                state: match field(entry, "state").as_str().expect("state") {
                    "CHALLENGED" => CandidateState::Challenged,
                    "PROVEN" => CandidateState::Proven,
                    "FAILED" => CandidateState::Failed,
                    "PROMOTED" => CandidateState::Promoted,
                    _ => panic!("unknown state"),
                },
            });
            if entry.get("local_mover").and_then(Value::as_bool) == Some(true) {
                state.outbound.push(OutboundCandidate {
                    candidate_id: id,
                    loc: candidate_loc,
                    epoch,
                    slot,
                    binding: Some(observed),
                    expiry_ms: now + 5000,
                });
            }
        }
        if setup.get("validated_bindings").and_then(Value::as_u64) == Some(2) {
            state.old_binding = Some((current, now + 10000));
        }
        if setup.get("restarted").and_then(Value::as_bool) == Some(true) {
            state.closed = true;
            state.candidate_secret = None;
            state.generation = 1;
        }
        let policy_id = setup
            .get("manager_policy_id")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| field(context, "policy_id").as_u64().expect("policy"))
            as u32;
        (
            CandidateManager {
                signing: SigningKey::from_bytes(&[0x55; 32]),
                local: r8_session::Identity {
                    role: receiver,
                    service_context: 1,
                    eid: r8_session::eid(&server),
                    public_key: server,
                },
                peer: r8_session::Identity {
                    role: sender,
                    service_context: 1,
                    eid: r8_session::eid(&client),
                    public_key: client,
                },
                profile: field(session, "profile").as_u64().expect("profile") as u8,
                scid: field(session, "scid").as_u64().expect("scid"),
                policy: Policy { policy_id },
                state: Arc::new(Mutex::new(state)),
            },
            invalid_roles,
        )
    }
    fn expected(value: &str) -> MobilityError {
        match value {
            "E-CANDIDATE" => MobilityError::Candidate,
            "E-CAPACITY" => MobilityError::Capacity,
            "E-TIMEOUT" => MobilityError::Timeout,
            "E-REPLAY" => MobilityError::Replay,
            _ => panic!("unknown category"),
        }
    }
    #[test]
    fn corpus_negative_state_machine_executes_43_exact_operations_and_categories() {
        let vectors: Value = serde_json::from_str(VECTORS).expect("vector JSON");
        let cases = field(&vectors, "negative_cases").as_array().expect("cases");
        assert_eq!(cases.len(), 43);
        let mut ids = BTreeSet::new();
        for case in cases {
            let id = field(case, "id").as_str().expect("id");
            assert!(ids.insert(id), "duplicate fixture {id}");
            let setup = field(case, "setup");
            let (manager, invalid_roles) = manager(setup, field(&vectors, "context"));
            let input = hex(field(case, "input_hex").as_str().expect("input"));
            let observed = binding(
                setup
                    .get("observed_binding_hex")
                    .unwrap_or_else(|| field(setup, "current_binding_hex"))
                    .as_str()
                    .expect("binding"),
            );
            let now = field(setup, "clock_ms").as_u64().expect("clock");
            let operation = field(case, "operation").as_str().expect("operation");
            let mut callbacks = 0;
            let before = snapshot(&manager, callbacks);
            let result = match operation {
                "parse_control" => Control::parse(&input).map(|_| ()),
                "validate_roles" if invalid_roles => Err(MobilityError::Candidate),
                "validate_update" | "submit_update" | "receive_probe" | "receive_response"
                | "receive_result" | "validate_roles" => {
                    manager.preview(&input, &observed, 1, now).map(|_| ())
                }
                "replay_control" => {
                    let first = hex(field(
                        &field(&vectors, "positive_cases")
                            .as_array()
                            .expect("positive")[0],
                        "plaintext_hex",
                    )
                    .as_str()
                    .expect("control"));
                    let transition = manager
                        .preview(&first, &observed, 1, now)
                        .expect("first preview");
                    manager
                        .commit(
                            transition,
                            || {
                                callbacks += 1;
                                Ok(())
                            },
                            || {},
                        )
                        .expect("first commit");
                    let before_replay = snapshot(&manager, callbacks);
                    let result =
                        manager
                            .preview(&first, &observed, 1, now)
                            .and_then(|transition| {
                                manager.commit(transition, || Err(MobilityError::Replay), || {})
                            });
                    assert_eq!(snapshot(&manager, callbacks), before_replay, "{id}");
                    result
                }
                other => panic!("unknown fixture operation {other}"),
            };
            assert_eq!(
                result,
                Err(expected(
                    field(case, "expected_error").as_str().expect("category")
                )),
                "{id}"
            );
            if operation != "replay_control" {
                assert_eq!(snapshot(&manager, callbacks), before, "{id}");
            }
        }
        assert_eq!(ids.len(), 43);
    }
}
