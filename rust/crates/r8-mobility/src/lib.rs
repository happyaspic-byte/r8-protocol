//! Strict R8M1 candidate binding controls.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, Weak,
};

use aws_lc_rs::hmac;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use r8_session::{
    ClientMachine, DirectionalSession, Identity, ObservedBinding, Profile3ReplayBinding,
    Profile3ReplayProof, ProtectedReplayBinding, ProtectedReplayProof, ServerMachine,
};
use zeroize::{Zeroize, Zeroizing};

static NEXT_CANDIDATE_MANAGER_OWNER_ID: AtomicU64 = AtomicU64::new(1);

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

#[derive(Eq, PartialEq)]
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
impl core::fmt::Debug for Control {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::LocUpdate { .. } => "Control::LocUpdate(<redacted>)",
            Self::BindProbe { .. } => "Control::BindProbe(<redacted>)",
            Self::BindChallenge { .. } => "Control::BindChallenge(<redacted>)",
            Self::BindResponse { .. } => "Control::BindResponse(<redacted>)",
            Self::CandidateResult { .. } => "Control::CandidateResult(<redacted>)",
        })
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        match self {
            Self::BindChallenge { token, .. } | Self::BindResponse { token, .. } => token.zeroize(),
            _ => {}
        }
    }
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
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, MobilityError> {
        let mut out = Zeroizing::new(b"R8M1".to_vec());
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
    if fields.binding.validate().is_err()
        || context.profile > 3
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
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    Ok(hmac::sign(&key, &token_input(context, fields)?)
        .as_ref()
        .try_into()
        .expect("SHA-256 HMAC length"))
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub policy_id: u32,
}
#[derive(Clone)]
struct Proposal {
    bytes: Zeroizing<Vec<u8>>,
    candidate_id: [u8; 16],
    loc: [u8; 16],
    epoch: u64,
    slot: u8,
    expiry_ms: u64,
}
impl core::fmt::Debug for Proposal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Proposal(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateState {
    Challenged,
    Proven,
    Failed,
    Promoted,
}

#[derive(Clone, Eq, PartialEq)]
struct BindResponseIdentity {
    loc: [u8; 16],
    binding: ObservedBinding,
    expiry_ms: u64,
    token: Zeroizing<[u8; 32]>,
}
impl core::fmt::Debug for BindResponseIdentity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BindResponseIdentity(<redacted>)")
    }
}
#[derive(Clone)]
struct Candidate {
    candidate_id: [u8; 16],
    loc: [u8; 16],
    epoch: u64,
    slot: u8,
    binding: ObservedBinding,
    expiry_ms: u64,
    response: Option<BindResponseIdentity>,
    state: CandidateState,
}
impl core::fmt::Debug for Candidate {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Candidate(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResultOrigin {
    Emitted,
    Received,
}

#[derive(Clone)]
struct ResultEntry {
    candidate_id: [u8; 16],
    epoch: u64,
    slot: u8,
    bytes: Zeroizing<Vec<u8>>,
    expiry_ms: u64,
    response: Option<BindResponseIdentity>,
    origin: ResultOrigin,
    received_binding: Option<ObservedBinding>,
}
impl core::fmt::Debug for ResultEntry {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ResultEntry(<redacted>)")
    }
}

#[derive(Clone)]
struct OutboundCandidate {
    candidate_id: [u8; 16],
    loc: [u8; 16],
    epoch: u64,
    slot: u8,
    binding: Option<ObservedBinding>,
    expiry_ms: u64,
}
impl core::fmt::Debug for OutboundCandidate {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("OutboundCandidate(<redacted>)")
    }
}
struct AdmissionCapability;

pub struct Profile3AdmissionIssuer {
    capability: Weak<AdmissionCapability>,
}

impl Profile3AdmissionIssuer {
    pub fn owner_is_live(&self) -> bool {
        self.capability.strong_count() != 0
    }

    pub fn admits(&self, admission: &Profile3Admission) -> bool {
        self.capability
            .upgrade()
            .is_some_and(|capability| Arc::ptr_eq(&capability, &admission.owner.capability))
    }
}

impl core::fmt::Debug for Profile3AdmissionIssuer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Profile3AdmissionIssuer(<redacted>)")
    }
}

pub struct Profile3AdmissionOwner {
    scid: u64,
    policy_id: u32,
    replay_binding: Profile3ReplayBinding,
    capability: Arc<AdmissionCapability>,
}

impl Profile3AdmissionOwner {
    pub fn issue(
        scid: u64,
        policy_id: u32,
        replay_binding: Profile3ReplayBinding,
    ) -> Result<(Self, Profile3AdmissionIssuer), MobilityError> {
        if scid == 0 {
            return Err(MobilityError::Candidate);
        }
        let capability = Arc::new(AdmissionCapability);
        Ok((
            Self {
                scid,
                policy_id,
                replay_binding,
                capability: capability.clone(),
            },
            Profile3AdmissionIssuer {
                capability: Arc::downgrade(&capability),
            },
        ))
    }
    pub fn scid(&self) -> u64 {
        self.scid
    }
    pub fn policy_id(&self) -> u32 {
        self.policy_id
    }
}
impl core::fmt::Debug for Profile3AdmissionOwner {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Profile3AdmissionOwner(<redacted>)")
    }
}

pub struct Profile3Admission {
    owner: Profile3AdmissionOwner,
    scid: u64,
    policy_id: u32,
    binding: ObservedBinding,
    local_loc: [u8; 16],
    peer_loc: [u8; 16],
    epoch: u64,
}
impl core::fmt::Debug for Profile3Admission {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Profile3Admission(<redacted>)")
    }
}
impl Profile3Admission {
    pub fn scid(&self) -> u64 {
        self.scid
    }
    pub fn policy_id(&self) -> u32 {
        self.policy_id
    }
    pub fn matches_replay_binding(&self, binding: &Profile3ReplayBinding) -> bool {
        self.owner.replay_binding.matches_binding(binding)
    }

    pub fn binding(&self) -> &ObservedBinding {
        &self.binding
    }

    pub fn local_loc(&self) -> [u8; 16] {
        self.local_loc
    }

    pub fn peer_loc(&self) -> [u8; 16] {
        self.peer_loc
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
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
    frozen_cohort: Option<(u64, Vec<Proposal>)>,
    outbound: Vec<OutboundCandidate>,
    emitted_results: Vec<Zeroizing<Vec<u8>>>,
    profile3_slot1_admitted: bool,
    profile3_admission: Option<Profile3Admission>,
    profile3_owner: Option<Profile3AdmissionOwner>,
    tombstones: Vec<([u8; 16], u64)>,
}

#[derive(Clone)]
enum Action {
    CacheProposal {
        proposal: Proposal,
        tokens: u8,
        refill_ms: u64,
    },
    Challenge(Candidate),
    ExistingChallenge(Candidate),
    Respond(Zeroizing<Vec<u8>>),
    CommitLocal {
        epoch: u64,
        loc: [u8; 16],
        binding: ObservedBinding,
        promote: bool,
        result: ResultEntry,
    },
    Prove {
        candidate_id: [u8; 16],
        epoch: u64,
        slot: u8,
        grace_until_ms: u64,
        response: BindResponseIdentity,
    },
    None,
}
fn frozen_slots(state: &State) -> usize {
    state
        .frozen_cohort
        .as_ref()
        .map_or(0, |(_, members)| members.len())
}
fn record_tombstone(state: &mut State, candidate_id: [u8; 16], now_ms: u64) {
    if state
        .tombstones
        .iter()
        .any(|(existing, _)| *existing == candidate_id)
    {
        return;
    }
    if state.tombstones.len() == RESULT_CACHE_SLOTS {
        state.tombstones.remove(0);
    }
    state
        .tombstones
        .push((candidate_id, now_ms.saturating_add(10_000)));
}

fn result_entry(
    proposal: &Proposal,
    result: u8,
    now_ms: u64,
    response: Option<BindResponseIdentity>,
) -> ResultEntry {
    ResultEntry {
        candidate_id: proposal.candidate_id,
        epoch: proposal.epoch,
        slot: proposal.slot,
        bytes: Control::CandidateResult {
            candidate_id: proposal.candidate_id,
            epoch: proposal.epoch,
            path_slot: proposal.slot,
            result,
        }
        .encode()
        .expect("fixed-width candidate result is valid"),
        expiry_ms: now_ms.saturating_add(10_000),
        response,
        origin: ResultOrigin::Emitted,
        received_binding: None,
    }
}

fn settle_frozen_cohort(state: &mut State, profile: u8, scid: u64, now_ms: u64) -> bool {
    let Some((epoch, members)) = state.frozen_cohort.clone() else {
        return false;
    };
    if members.iter().any(|proposal| {
        state
            .proposals
            .iter()
            .any(|current| current.candidate_id == proposal.candidate_id)
            && state.candidates.iter().any(|candidate| {
                candidate.candidate_id == proposal.candidate_id
                    && !matches!(
                        candidate.state,
                        CandidateState::Proven | CandidateState::Failed
                    )
            })
    }) {
        return false;
    }

    let mut proven: Vec<_> = members
        .iter()
        .filter(|proposal| {
            state.candidates.iter().any(|candidate| {
                candidate.candidate_id == proposal.candidate_id
                    && candidate.state == CandidateState::Proven
            })
        })
        .map(|proposal| proposal.candidate_id)
        .collect();
    proven.sort_unstable();
    if state.emitted_results.len().saturating_add(members.len()) > RESULT_CACHE_SLOTS {
        return false;
    }
    let winner = proven.first().copied();
    let outcomes: Vec<_> = members
        .iter()
        .map(|proposal| {
            let result = match winner {
                Some(candidate_id) if candidate_id == proposal.candidate_id => 1,
                Some(_)
                    if state
                        .candidates
                        .iter()
                        .any(|candidate| candidate.candidate_id == proposal.candidate_id) =>
                {
                    2
                }
                _ => 3,
            };
            let response = state
                .candidates
                .iter()
                .find(|candidate| candidate.candidate_id == proposal.candidate_id)
                .and_then(|candidate| candidate.response.clone());
            result_entry(proposal, result, now_ms, response)
        })
        .collect();
    debug_assert!(state.results.len().saturating_add(outcomes.len()) <= RESULT_CACHE_SLOTS);

    if let Some(winner) = winner {
        let candidate = state
            .candidates
            .iter()
            .find(|candidate| candidate.candidate_id == winner)
            .expect("proven candidate is present");
        if profile == 3 {
            if !state.profile3_slot1_admitted {
                if let Some(owner) = state.profile3_owner.take() {
                    state.profile3_admission = Some(Profile3Admission {
                        scid,
                        policy_id: owner.policy_id(),
                        owner,
                        binding: candidate.binding.clone(),
                        local_loc: state.local_loc,
                        peer_loc: candidate.loc,
                        epoch,
                    });
                    state.profile3_slot1_admitted = true;
                }
            }
            if state.profile3_slot1_admitted {
                state.emitted_results.clear();
                state
                    .emitted_results
                    .extend(outcomes.iter().map(|entry| entry.bytes.clone()));
                state.results.clear();
                state.proposals.clear();
                state.candidates.clear();
                state.outbound.clear();
                state.frozen_cohort = None;
                state.candidate_secret = None;
                return true;
            }
        } else {
            state.peer_epoch = epoch;
            state.peer_loc = candidate.loc;
            state.old_binding = Some((
                state.current_binding.clone(),
                now_ms.saturating_add(OLD_BINDING_GRACE_MS),
            ));
            state.current_binding = candidate.binding.clone();
        }
        for candidate in &mut state.candidates {
            if candidate.epoch == epoch {
                candidate.state = if candidate.candidate_id == winner {
                    CandidateState::Promoted
                } else {
                    CandidateState::Failed
                };
            }
        }
    }
    state
        .emitted_results
        .extend(outcomes.iter().map(|entry| entry.bytes.clone()));
    state.results.extend(outcomes);
    state.proposals.retain(|proposal| proposal.epoch > epoch);
    state.candidates.retain(|candidate| candidate.epoch > epoch);
    state.frozen_cohort = None;
    true
}

pub struct Transition {
    generation: u64,
    owner_id: u64,
    action: Action,
    protected_proof: Option<ProtectedReplayProof>,
    profile3_proof: Option<Profile3ReplayProof>,
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

pub struct CandidateManager {
    signing: SigningKey,
    local: Identity,
    peer: Identity,
    profile: u8,
    scid: u64,
    policy: Policy,
    owner_id: u64,
    state: Arc<Mutex<State>>,
    protected_replay_binding: Option<ProtectedReplayBinding>,
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
    /// Creates a manager bound to a protected-session replay authority.
    pub fn new_with_protected_replay_binding(
        config: CandidateManagerConfig,
        protected_replay_binding: ProtectedReplayBinding,
    ) -> Result<Self, MobilityError> {
        Self::new_inner(config, None, Some(protected_replay_binding))
    }

    pub fn new_with_profile3_admission_owner(
        config: CandidateManagerConfig,
        owner: Profile3AdmissionOwner,
    ) -> Result<Self, MobilityError> {
        Self::new_inner(config, Some(owner), None)
    }

    fn new_inner(
        config: CandidateManagerConfig,
        profile3_owner: Option<Profile3AdmissionOwner>,
        protected_replay_binding: Option<ProtectedReplayBinding>,
    ) -> Result<Self, MobilityError> {
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
            || initial_peer_binding.validate().is_err()
            || local.role == peer.role
            || signing.verifying_key().to_bytes() != local.public_key
            || (profile == 3
                && profile3_owner.as_ref().is_none_or(|owner| {
                    owner.scid() != scid || owner.policy_id() != policy.policy_id
                }))
            || (profile != 3 && profile3_owner.is_some())
            || (profile != 3 && protected_replay_binding.is_none())
            || (profile == 3 && protected_replay_binding.is_some())
        {
            return Err(MobilityError::Candidate);
        }
        let owner_id = NEXT_CANDIDATE_MANAGER_OWNER_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| MobilityError::Replay)?;
        Ok(Self {
            signing,
            local,
            peer,
            profile,
            scid,
            policy,
            owner_id,
            protected_replay_binding,
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
                profile3_slot1_admitted: false,
                profile3_admission: None,
                profile3_owner,
                tombstones: Vec::new(),
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
            || (self.profile == 3 && state.profile3_slot1_admitted)
            || state
                .tombstones
                .iter()
                .any(|(existing, expiry)| *existing == candidate_id && now_ms < *expiry)
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
        carrier.validate().map_err(|_| MobilityError::Candidate)?;
        let mut state = self.state.lock().map_err(|_| MobilityError::Candidate)?;
        if state.closed || (self.profile == 3 && state.profile3_slot1_admitted) {
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
    #[cfg(test)]
    fn preview(
        &self,
        plaintext: &[u8],
        binding: &ObservedBinding,
        replay_token: u64,
        now_ms: u64,
    ) -> Result<Transition, MobilityError> {
        if self.profile == 3 || replay_token == 0 {
            return Err(MobilityError::Replay);
        }
        self.preview_inner(plaintext, binding, now_ms, None, None)
    }
    pub fn preview_protected(
        &self,
        plaintext: &[u8],
        binding: &ObservedBinding,
        proof: ProtectedReplayProof,
        now_ms: u64,
    ) -> Result<Transition, MobilityError> {
        if self.profile == 3
            || !proof.matches_plaintext(plaintext)
            || !self
                .protected_replay_binding
                .as_ref()
                .is_some_and(|binding| binding.matches_proof(&proof))
        {
            return Err(MobilityError::Replay);
        }
        self.preview_inner(plaintext, binding, now_ms, Some(proof), None)
    }

    pub fn preview_profile3(
        &self,
        plaintext: &[u8],
        binding: &ObservedBinding,
        proof: Profile3ReplayProof,
        now_ms: u64,
    ) -> Result<Transition, MobilityError> {
        if self.profile != 3 || !proof.matches_plaintext(plaintext) {
            return Err(MobilityError::Candidate);
        }
        {
            let state = self.state.lock().map_err(|_| MobilityError::Candidate)?;
            if !state
                .profile3_owner
                .as_ref()
                .is_some_and(|owner| owner.replay_binding.matches_proof(&proof))
            {
                return Err(MobilityError::Replay);
            }
        }
        self.preview_inner(plaintext, binding, now_ms, None, Some(proof))
    }

    fn preview_inner(
        &self,
        plaintext: &[u8],
        binding: &ObservedBinding,
        now_ms: u64,
        protected_proof: Option<ProtectedReplayProof>,
        profile3_proof: Option<Profile3ReplayProof>,
    ) -> Result<Transition, MobilityError> {
        binding.validate().map_err(|_| MobilityError::Candidate)?;
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
        if state.closed
            || state.generation == u64::MAX
            || (self.profile == 3 && state.profile3_slot1_admitted)
        {
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
                if *old_loc != state.peer_loc
                    || *epoch <= state.peer_epoch
                    || (self.profile == 3 && state.profile3_slot1_admitted)
                {
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
                    .frozen_cohort
                    .as_ref()
                    .is_some_and(|(cohort_epoch, _)| *epoch <= *cohort_epoch)
                    || state
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
                    || state
                        .tombstones
                        .iter()
                        .any(|(existing, expiry)| *existing == *candidate_id && now_ms < *expiry)
                {
                    return Err(MobilityError::Candidate);
                } else {
                    if !state.emitted_results.is_empty() {
                        return Err(MobilityError::Capacity);
                    }
                    if state.proposals.len() == PROPOSAL_SLOTS
                        || state.results.len().saturating_add(state.proposals.len())
                            >= RESULT_CACHE_SLOTS
                    {
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
                        response: None,
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
                    if result.response.as_ref()
                        == Some(&BindResponseIdentity {
                            loc: *loc,
                            binding: binding.clone(),
                            expiry_ms: *expiry_ms,
                            token: Zeroizing::new(*supplied),
                        })
                    {
                        Action::Respond(result.bytes.clone())
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
                                .cloned()
                                .collect()
                        });
                    if state.frozen_cohort.is_none()
                        && *epoch == greatest
                        && state.results.len().saturating_add(members.len()) > RESULT_CACHE_SLOTS
                    {
                        return Err(MobilityError::Capacity);
                    }
                    Action::Prove {
                        candidate_id: *candidate_id,
                        epoch: *epoch,
                        slot: *path_slot,
                        grace_until_ms: now_ms,
                        response: BindResponseIdentity {
                            loc: *loc,
                            binding: binding.clone(),
                            expiry_ms: *expiry_ms,
                            token: Zeroizing::new(*supplied),
                        },
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
                Action::Respond(
                    Control::BindResponse {
                        candidate_id: candidate.candidate_id,
                        loc: candidate.loc,
                        epoch: candidate.epoch,
                        path_slot: candidate.slot,
                        expiry_ms: *expiry_ms,
                        token: *token,
                    }
                    .encode()?,
                )
            }
            Control::CandidateResult {
                candidate_id,
                epoch,
                path_slot,
                result,
            } => {
                if let Some(entry) = state.results.iter().find(|entry| {
                    entry.candidate_id == *candidate_id
                        && entry.epoch == *epoch
                        && entry.slot == *path_slot
                        && now_ms < entry.expiry_ms
                }) {
                    if entry.origin == ResultOrigin::Received
                        && entry.bytes.as_slice() == control.encode()?.as_slice()
                        && entry.received_binding.as_ref() == Some(binding)
                    {
                        Action::None
                    } else {
                        return Err(MobilityError::Candidate);
                    }
                } else {
                    let candidate = state
                        .outbound
                        .iter()
                        .find(|candidate| {
                            candidate.candidate_id == *candidate_id
                                && candidate.epoch == *epoch
                                && candidate.slot == *path_slot
                                && candidate.binding.as_ref() == Some(binding)
                                && now_ms < candidate.expiry_ms
                        })
                        .ok_or(MobilityError::Candidate)?;
                    if state.results.len().saturating_add(frozen_slots(&state))
                        >= RESULT_CACHE_SLOTS
                    {
                        return Err(MobilityError::Capacity);
                    }
                    Action::CommitLocal {
                        epoch: candidate.epoch,
                        loc: candidate.loc,
                        binding: candidate
                            .binding
                            .clone()
                            .expect("binding was verified while preparing transition"),
                        promote: *result == 1,
                        result: ResultEntry {
                            candidate_id: *candidate_id,
                            epoch: *epoch,
                            slot: *path_slot,
                            bytes: control.encode()?,
                            expiry_ms: now_ms.saturating_add(10_000),
                            response: None,
                            origin: ResultOrigin::Received,
                            received_binding: Some(binding.clone()),
                        },
                    }
                }
            }
        };
        Ok(Transition {
            generation: state.generation,
            owner_id: self.owner_id,
            action,
            protected_proof,
            profile3_proof,
        })
    }

    pub fn response_for(&self, transition: &Transition) -> Result<Option<Control>, MobilityError> {
        let state = self.state.lock().map_err(|_| MobilityError::Candidate)?;
        if state.closed
            || transition.owner_id != self.owner_id
            || state.generation != transition.generation
        {
            return Err(MobilityError::Replay);
        }
        let candidate = match &transition.action {
            Action::Challenge(candidate) | Action::ExistingChallenge(candidate) => candidate,
            Action::Respond(control) => return Control::parse(control).map(Some),
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

    fn apply_after_replay(
        &self,
        state: &mut State,
        transition: Transition,
    ) -> Result<(), MobilityError> {
        let mutates = !matches!(
            &transition.action,
            Action::ExistingChallenge(_) | Action::Respond(_) | Action::None
        );
        let next_generation = if mutates {
            state
                .generation
                .checked_add(1)
                .ok_or(MobilityError::Replay)?
        } else {
            state.generation
        };
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
                epoch,
                loc,
                binding,
                promote,
                result,
            } => {
                let result_expiry_ms = result.expiry_ms;
                let result_candidate_id = result.candidate_id;
                state.results.push(result);
                if promote {
                    if self.profile == 3 {
                        if !state.profile3_slot1_admitted {
                            if let Some(owner) = state.profile3_owner.take() {
                                state.profile3_admission = Some(Profile3Admission {
                                    scid: self.scid,
                                    policy_id: owner.policy_id(),
                                    owner,
                                    binding,
                                    local_loc: loc,
                                    peer_loc: state.peer_loc,
                                    epoch,
                                });
                                state.profile3_slot1_admitted = true;
                            }
                        }
                        if state.profile3_slot1_admitted {
                            state.proposals.clear();
                            state.candidates.clear();
                            state.outbound.clear();
                            state.results.clear();
                            state.frozen_cohort = None;
                            state.candidate_secret = None;
                        }
                    } else {
                        state.local_epoch = epoch;
                        state.local_loc = loc;
                        state.old_binding = Some((state.current_binding.clone(), result_expiry_ms));
                        state.current_binding = binding;
                    }
                }
                if promote {
                    state.outbound.retain(|candidate| candidate.epoch > epoch);
                } else {
                    state
                        .outbound
                        .retain(|candidate| candidate.candidate_id != result_candidate_id);
                }
            }
            Action::Prove {
                candidate_id,
                epoch,
                slot,
                grace_until_ms,
                response,
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
                candidate.response = Some(response);
                if state.frozen_cohort.is_none()
                    && state.proposals.iter().map(|proposal| proposal.epoch).max() == Some(epoch)
                {
                    let members = state
                        .proposals
                        .iter()
                        .filter(|proposal| proposal.epoch == epoch)
                        .cloned()
                        .collect();
                    state.frozen_cohort = Some((epoch, members));
                }
                settle_frozen_cohort(state, self.profile, self.scid, grace_until_ms);
            }
            Action::None => {}
        }
        if mutates {
            state.generation = next_generation;
        }
        Ok(())
    }

    fn commit_protected_replay(
        &self,
        mut transition: Transition,
        commit: impl FnOnce(&mut ProtectedReplayProof) -> Result<(), MobilityError>,
    ) -> Result<(), MobilityError> {
        if self.profile == 3 || transition.owner_id != self.owner_id {
            return Err(MobilityError::Replay);
        }
        let mut proof = transition
            .protected_proof
            .take()
            .ok_or(MobilityError::Replay)?;
        let mut state = self.state.lock().map_err(|_| MobilityError::Candidate)?;
        if state.closed || state.generation != transition.generation {
            return Err(MobilityError::Replay);
        }
        commit(&mut proof)?;
        if !proof.is_committed() {
            return Err(MobilityError::Replay);
        }
        self.apply_after_replay(&mut state, transition)
    }

    pub fn commit_protected(
        &self,
        transition: Transition,
        session: &mut DirectionalSession,
    ) -> Result<(), MobilityError> {
        self.commit_protected_replay(transition, |proof| {
            session
                .commit_protected_replay(proof)
                .map_err(|_| MobilityError::Replay)
        })
    }

    pub fn commit_protected_client(
        &self,
        transition: Transition,
        client: &mut ClientMachine,
    ) -> Result<(), MobilityError> {
        self.commit_protected_replay(transition, |proof| {
            client
                .commit_protected_replay(proof)
                .map_err(|_| MobilityError::Replay)
        })
    }

    pub fn commit_protected_server(
        &self,
        transition: Transition,
        server: &mut ServerMachine,
        scid: u64,
        now_ms: u64,
    ) -> Result<(), MobilityError> {
        self.commit_protected_replay(transition, |proof| {
            server
                .commit_protected_replay(scid, proof, now_ms)
                .map_err(|_| MobilityError::Replay)
        })
    }

    pub fn commit_profile3(
        &self,
        mut transition: Transition,
        session: &mut DirectionalSession,
    ) -> Result<(), MobilityError> {
        if self.profile != 3 || transition.owner_id != self.owner_id {
            return Err(MobilityError::Replay);
        }
        let mut proof = transition
            .profile3_proof
            .take()
            .ok_or(MobilityError::Replay)?;
        let mut state = self.state.lock().map_err(|_| MobilityError::Candidate)?;
        if state.closed || state.generation != transition.generation {
            return Err(MobilityError::Replay);
        }
        session
            .commit_profile3_replay(&mut proof)
            .map_err(|_| MobilityError::Replay)?;
        if !proof.is_committed() {
            return Err(MobilityError::Replay);
        }
        self.apply_after_replay(&mut state, transition)
    }
    #[cfg(test)]
    fn commit(
        &self,
        transition: Transition,
        replay_commit: impl FnOnce() -> Result<(), MobilityError>,
    ) -> Result<(), MobilityError> {
        let mut state = self.state.lock().map_err(|_| MobilityError::Candidate)?;
        if state.closed
            || transition.owner_id != self.owner_id
            || transition.protected_proof.is_some()
            || transition.profile3_proof.is_some()
            || state.generation != transition.generation
        {
            return Err(MobilityError::Replay);
        }
        replay_commit()?;
        self.apply_after_replay(&mut state, transition)
    }

    pub fn expire(&self, now_ms: u64) {
        if let Ok(mut state) = self.state.lock() {
            if state.closed {
                return;
            }
            let frozen_members = state
                .frozen_cohort
                .as_ref()
                .map(|(_, members)| members.clone())
                .unwrap_or_default();
            let mut changed = false;
            for candidate in &mut state.candidates {
                if now_ms >= candidate.expiry_ms && candidate.state == CandidateState::Challenged {
                    candidate.state = CandidateState::Failed;
                    candidate.response = None;
                    changed = true;
                }
            }
            for proposal in &frozen_members {
                let expired = now_ms >= proposal.expiry_ms;
                match state
                    .candidates
                    .iter_mut()
                    .find(|candidate| candidate.candidate_id == proposal.candidate_id)
                {
                    Some(candidate)
                        if expired
                            && !matches!(
                                candidate.state,
                                CandidateState::Proven | CandidateState::Failed
                            ) =>
                    {
                        candidate.state = CandidateState::Failed;
                        candidate.response = None;
                        changed = true;
                    }
                    None if expired => changed = true,
                    _ => {}
                }
                if expired {
                    record_tombstone(&mut state, proposal.candidate_id, now_ms);
                }
            }
            changed |= settle_frozen_cohort(&mut state, self.profile, self.scid, now_ms);
            let results = state.results.len();
            state.results.retain(|result| now_ms < result.expiry_ms);
            changed |= state.results.len() != results;
            let timeout_failures: Vec<_> = state
                .candidates
                .iter()
                .filter(|candidate| {
                    candidate.state == CandidateState::Failed
                        && !frozen_members
                            .iter()
                            .any(|proposal| proposal.candidate_id == candidate.candidate_id)
                })
                .filter_map(|candidate| {
                    state
                        .proposals
                        .iter()
                        .find(|proposal| proposal.candidate_id == candidate.candidate_id)
                        .cloned()
                })
                .collect();
            for proposal in timeout_failures {
                if state.results.len() >= RESULT_CACHE_SLOTS
                    || state.emitted_results.len() >= RESULT_CACHE_SLOTS
                    || state
                        .results
                        .iter()
                        .any(|result| result.candidate_id == proposal.candidate_id)
                {
                    continue;
                }
                let result = result_entry(&proposal, 3, now_ms, None);
                state.emitted_results.push(result.bytes.clone());
                state.results.push(result);
                changed = true;
            }
            let expired_ids: Vec<_> = state
                .proposals
                .iter()
                .filter(|proposal| now_ms >= proposal.expiry_ms)
                .map(|proposal| proposal.candidate_id)
                .chain(
                    state
                        .outbound
                        .iter()
                        .filter(|candidate| now_ms >= candidate.expiry_ms)
                        .map(|candidate| candidate.candidate_id),
                )
                .collect();
            for candidate_id in expired_ids {
                record_tombstone(&mut state, candidate_id, now_ms);
            }
            state.tombstones.retain(|(_, expiry)| now_ms < *expiry);
            let proposals = state.proposals.len();
            state
                .proposals
                .retain(|proposal| now_ms < proposal.expiry_ms);
            changed |= state.proposals.len() != proposals;
            if state.frozen_cohort.as_ref().is_some_and(|(epoch, _)| {
                !state
                    .proposals
                    .iter()
                    .any(|proposal| proposal.epoch == *epoch)
            }) {
                state.frozen_cohort = None;
                changed = true;
            }
            if state.frozen_cohort.is_none() {
                if let Some(epoch) = state
                    .proposals
                    .iter()
                    .filter(|proposal| {
                        state.candidates.iter().any(|candidate| {
                            candidate.candidate_id == proposal.candidate_id
                                && candidate.state == CandidateState::Proven
                        })
                    })
                    .map(|proposal| proposal.epoch)
                    .max()
                {
                    state.frozen_cohort = Some((
                        epoch,
                        state
                            .proposals
                            .iter()
                            .filter(|proposal| proposal.epoch == epoch)
                            .cloned()
                            .collect(),
                    ));
                    changed = true;
                }
            }
            let candidates = state.candidates.len();
            state.candidates.retain(|candidate| {
                candidate.state != CandidateState::Failed
                    || frozen_members
                        .iter()
                        .any(|proposal| proposal.candidate_id == candidate.candidate_id)
            });
            changed |= state.candidates.len() != candidates;
            let outbound = state.outbound.len();
            state
                .outbound
                .retain(|candidate| now_ms < candidate.expiry_ms);
            changed |= state.outbound.len() != outbound;
            if state
                .old_binding
                .as_ref()
                .is_some_and(|(_, expiry)| now_ms >= *expiry)
            {
                state.old_binding = None;
                changed = true;
            }
            changed |= settle_frozen_cohort(&mut state, self.profile, self.scid, now_ms);
            if changed {
                if let Some(next_generation) = state.generation.checked_add(1) {
                    state.generation = next_generation;
                } else {
                    state.closed = true;
                    state.proposals.clear();
                    state.candidates.clear();
                    state.results.clear();
                    state.outbound.clear();
                    state.emitted_results.clear();
                    state.profile3_admission = None;
                    state.profile3_owner = None;
                    state.old_binding = None;
                    state.frozen_cohort = None;
                    state.candidate_secret = None;
                    state.tombstones.clear();
                }
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
            state.profile3_admission = None;
            state.profile3_owner = None;
            state.old_binding = None;
            state.frozen_cohort = None;
            state.candidate_secret = None;
            state.tombstones.clear();
            state.generation = state.generation.saturating_add(1);
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
        binding.validate().is_ok()
            && self.state.lock().is_ok_and(|state| {
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
    pub fn take_profile3_admissions(&self) -> Vec<Profile3Admission> {
        let Ok(mut state) = self.state.lock() else {
            return Vec::new();
        };
        if !state.emitted_results.is_empty() {
            return Vec::new();
        }
        state.profile3_admission.take().into_iter().collect()
    }
}
#[cfg(test)]
mod corpus_negative_state_machine {
    use super::*;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
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
            profile3_slot1_admitted: false,
            profile3_admission: None,
            profile3_owner: None,
            tombstones: Vec::new(),
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
                .map(|v| Zeroizing::new(hex(v.as_str().expect("input"))))
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
                response: None,
                origin: ResultOrigin::Emitted,
                received_binding: None,
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
                response: None,
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
                protected_replay_binding: None,
                owner_id: NEXT_CANDIDATE_MANAGER_OWNER_ID.fetch_add(1, Ordering::Relaxed),
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
    fn cohort_manager() -> (CandidateManager, SigningKey, ObservedBinding) {
        let local_signing = SigningKey::from_bytes(&[0x11; 32]);
        let peer_signing = SigningKey::from_bytes(&[0x22; 32]);
        let local_key = local_signing.verifying_key().to_bytes();
        let peer_key = peer_signing.verifying_key().to_bytes();
        let binding = ObservedBinding::Native {
            ingress_descriptor_id: 1,
            next_hop_mac: [0x33; 6],
        };
        let manager = CandidateManager::new_with_protected_replay_binding(
            CandidateManagerConfig {
                signing: local_signing,
                local: Identity {
                    role: 2,
                    service_context: 1,
                    eid: r8_session::eid(&local_key),
                    public_key: local_key,
                },
                peer: Identity {
                    role: 1,
                    service_context: 1,
                    eid: r8_session::eid(&peer_key),
                    public_key: peer_key,
                },
                profile: 0,
                scid: 1,
                policy: Policy { policy_id: 1 },
                local_loc: [0x41; 16],
                peer_loc: [0x42; 16],
                initial_peer_binding: binding.clone(),
                candidate_secret: [0x43; 32],
            },
            DirectionalSession::new(
                Zeroizing::new([0x44; 32]),
                Zeroizing::new([0x45; 32]),
                [0; 32],
                1280,
            )
            .protected_replay_binding(),
        )
        .expect("manager");
        (manager, peer_signing, binding)
    }

    fn update(
        manager: &CandidateManager,
        peer_signing: &SigningKey,
        candidate_id: [u8; 16],
        new_loc: [u8; 16],
        epoch: u64,
    ) -> Control {
        sign_loc_update(
            peer_signing,
            MobilityContext {
                profile: manager.profile,
                scid: manager.scid,
                sender: &manager.peer,
                receiver: &manager.local,
                policy_id: manager.policy.policy_id,
            },
            LocUpdateFields {
                candidate_id,
                old_loc: manager.peer_loc(),
                new_loc,
                epoch,
                path_slot: 0,
            },
        )
        .expect("signed update")
    }

    fn proposal(control: &Control, expiry_ms: u64) -> Proposal {
        let Control::LocUpdate {
            candidate_id,
            new_loc,
            epoch,
            path_slot,
            ..
        } = control
        else {
            panic!("update control");
        };
        Proposal {
            bytes: control.encode().expect("encoded update"),
            candidate_id: *candidate_id,
            loc: *new_loc,
            epoch: *epoch,
            slot: *path_slot,
            expiry_ms,
        }
    }

    #[test]
    fn frozen_cohort_rejects_late_equal_epoch_without_mutation() {
        let (manager, peer_signing, binding) = cohort_manager();
        let a = [0x01; 16];
        let cached_a = update(&manager, &peer_signing, a, [0x51; 16], 1);
        {
            let mut state = manager.state.lock().expect("state lock");
            state.proposals.push(proposal(&cached_a, 5_000));
            state.candidates.push(Candidate {
                candidate_id: a,
                loc: [0x51; 16],
                epoch: 1,
                slot: 0,
                binding: binding.clone(),
                expiry_ms: 3_000,
                response: None,
                state: CandidateState::Proven,
            });
            state.frozen_cohort = Some((1, vec![proposal(&cached_a, 5_000)]));
        }
        let before = snapshot(&manager, 0);
        let late_b = update(&manager, &peer_signing, [0x02; 16], [0x52; 16], 1)
            .encode()
            .expect("encoded update");

        assert!(matches!(
            manager.preview(&late_b, &binding, 1, 1),
            Err(MobilityError::Candidate)
        ));
        assert_eq!(snapshot(&manager, 0), before);
    }

    #[test]
    fn promotion_discards_same_epoch_cohort_state_after_grace() {
        let (manager, peer_signing, binding) = cohort_manager();
        let a = [0x01; 16];
        let cached_a = update(&manager, &peer_signing, a, [0x51; 16], 1);
        {
            let mut state = manager.state.lock().expect("state lock");
            state.proposals.push(proposal(&cached_a, 5_000));
            state.candidates.push(Candidate {
                candidate_id: a,
                loc: [0x51; 16],
                epoch: 1,
                slot: 0,
                binding: binding.clone(),
                expiry_ms: 3_000,
                response: None,
                state: CandidateState::Challenged,
            });
        }
        manager
            .commit(
                Transition {
                    generation: 0,
                    owner_id: manager.owner_id,
                    action: Action::Prove {
                        candidate_id: a,
                        epoch: 1,
                        slot: 0,
                        grace_until_ms: OLD_BINDING_GRACE_MS,
                        response: BindResponseIdentity {
                            loc: [0x51; 16],
                            binding: binding.clone(),
                            expiry_ms: 3_000,
                            token: Zeroizing::new([0; 32]),
                        },
                    },
                    profile3_proof: None,
                    protected_proof: None,
                },
                || Ok(()),
            )
            .expect("promotion");

        manager.expire(OLD_BINDING_GRACE_MS);
        let state = manager.state.lock().expect("state lock");
        assert_eq!(state.peer_epoch, 1);
        assert!(state.proposals.is_empty());
        assert!(state.candidates.is_empty());
        assert!(state.frozen_cohort.is_none());
        drop(state);

        let stale_b = Control::BindProbe {
            candidate_id: [0x02; 16],
            loc: [0x52; 16],
            epoch: 1,
            path_slot: 0,
            probe_nonce: [0x44; 16],
        }
        .encode()
        .expect("encoded probe");
        assert!(matches!(
            manager.preview(&stale_b, &binding, 2, OLD_BINDING_GRACE_MS),
            Err(MobilityError::Candidate)
        ));
        let stale_update = update(&manager, &peer_signing, [0x02; 16], [0x52; 16], 1)
            .encode()
            .expect("encoded update");
        assert!(matches!(
            manager.preview(&stale_update, &binding, 3, OLD_BINDING_GRACE_MS),
            Err(MobilityError::Candidate)
        ));
        let stale_result = Control::CandidateResult {
            candidate_id: [0x02; 16],
            epoch: 1,
            path_slot: 0,
            result: 1,
        }
        .encode()
        .expect("encoded result");
        assert!(matches!(
            manager.preview(&stale_result, &binding, 4, OLD_BINDING_GRACE_MS),
            Err(MobilityError::Candidate)
        ));
    }
    #[test]
    fn expiry_settles_frozen_proven_and_unprobed_pair() {
        let (manager, peer_signing, binding) = cohort_manager();
        let a = [0x01; 16];
        let b = [0x02; 16];
        let cached_a = update(&manager, &peer_signing, a, [0x51; 16], 1);
        let cached_b = update(&manager, &peer_signing, b, [0x52; 16], 1);
        {
            let mut state = manager.state.lock().expect("state lock");
            let a_proposal = proposal(&cached_a, 5_000);
            let b_proposal = proposal(&cached_b, 5_000);
            state
                .proposals
                .extend([a_proposal.clone(), b_proposal.clone()]);
            state.candidates.push(Candidate {
                candidate_id: a,
                loc: [0x51; 16],
                epoch: 1,
                slot: 0,
                binding,
                expiry_ms: 3_000,
                response: None,
                state: CandidateState::Proven,
            });
            state.frozen_cohort = Some((1, vec![a_proposal, b_proposal]));
        }

        manager.expire(5_000);

        let state = manager.state.lock().expect("state lock");
        assert_eq!(state.peer_loc, [0x51; 16]);
        assert!(state.proposals.is_empty());
        assert!(state.candidates.is_empty());
        assert!(state.frozen_cohort.is_none());
        assert_eq!(state.results.len(), 2);
        assert!(state
            .tombstones
            .iter()
            .any(|(candidate_id, _)| *candidate_id == a));
        assert!(state
            .tombstones
            .iter()
            .any(|(candidate_id, _)| *candidate_id == b));
    }

    #[test]
    fn cached_equal_epoch_members_still_arbitrate_lexically() {
        let (manager, peer_signing, binding) = cohort_manager();
        let a = [0x01; 16];
        let b = [0x02; 16];
        let cached_a = update(&manager, &peer_signing, a, [0x51; 16], 1);
        let cached_b = update(&manager, &peer_signing, b, [0x52; 16], 1);
        {
            let mut state = manager.state.lock().expect("state lock");
            state.proposals = vec![proposal(&cached_a, 5_000), proposal(&cached_b, 5_000)];
            state.candidates = vec![
                Candidate {
                    candidate_id: a,
                    loc: [0x51; 16],
                    epoch: 1,
                    slot: 0,
                    binding: binding.clone(),
                    expiry_ms: 3_000,
                    response: None,
                    state: CandidateState::Challenged,
                },
                Candidate {
                    candidate_id: b,
                    loc: [0x52; 16],
                    epoch: 1,
                    slot: 0,
                    binding: binding.clone(),
                    expiry_ms: 3_000,
                    response: None,
                    state: CandidateState::Challenged,
                },
            ];
            state.frozen_cohort = None;
        }
        let first_response = Control::BindResponse {
            candidate_id: a,
            loc: [0x51; 16],
            epoch: 1,
            path_slot: 0,
            expiry_ms: 3_000,
            token: token(
                &[0x43; 32],
                MobilityContext {
                    profile: manager.profile,
                    scid: manager.scid,
                    sender: &manager.peer,
                    receiver: &manager.local,
                    policy_id: manager.policy.policy_id,
                },
                TokenFields {
                    candidate_id: a,
                    loc: [0x51; 16],
                    binding: &binding,
                    epoch: 1,
                    path_slot: 0,
                    expiry_ms: 3_000,
                },
            )
            .expect("token"),
        }
        .encode()
        .expect("encoded response");
        let transition = manager
            .preview(&first_response, &binding, 3, 1)
            .expect("first proven preview");
        manager
            .commit(transition, || Ok(()))
            .expect("cohort freeze");
        assert_eq!(
            manager
                .state
                .lock()
                .expect("state lock")
                .frozen_cohort
                .as_ref()
                .expect("frozen cohort")
                .1
                .iter()
                .map(|proposal| proposal.candidate_id)
                .collect::<Vec<_>>(),
            vec![a, b]
        );
        let response = Control::BindResponse {
            candidate_id: b,
            loc: [0x52; 16],
            epoch: 1,
            path_slot: 0,
            expiry_ms: 3_000,
            token: token(
                &[0x43; 32],
                MobilityContext {
                    profile: manager.profile,
                    scid: manager.scid,
                    sender: &manager.peer,
                    receiver: &manager.local,
                    policy_id: manager.policy.policy_id,
                },
                TokenFields {
                    candidate_id: b,
                    loc: [0x52; 16],
                    binding: &binding,
                    epoch: 1,
                    path_slot: 0,
                    expiry_ms: 3_000,
                },
            )
            .expect("token"),
        }
        .encode()
        .expect("encoded response");
        let transition = manager
            .preview(&response, &binding, 3, 1)
            .expect("proven preview");
        manager.commit(transition, || Ok(())).expect("settlement");

        assert_eq!(manager.peer_loc(), [0x51; 16]);
        assert_eq!(manager.take_results().len(), 2);
    }

    #[test]
    fn higher_epoch_updates_remain_admissible_after_a_frozen_cohort() {
        let (manager, peer_signing, binding) = cohort_manager();
        {
            let mut state = manager.state.lock().expect("state lock");
            state.frozen_cohort = Some((1, Vec::new()));
        }
        let higher = update(&manager, &peer_signing, [0x02; 16], [0x52; 16], 2)
            .encode()
            .expect("encoded update");
        let transition = manager
            .preview(&higher, &binding, 4, 1)
            .expect("higher epoch preview");
        manager
            .commit(transition, || Ok(()))
            .expect("higher epoch commit");

        let state = manager.state.lock().expect("state lock");
        assert_eq!(state.proposals.len(), 1);
        assert_eq!(state.proposals[0].epoch, 2);
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
                        .commit(transition, || {
                            callbacks += 1;
                            Ok(())
                        })
                        .expect("first commit");
                    let before_replay = snapshot(&manager, callbacks);
                    let result =
                        manager
                            .preview(&first, &observed, 1, now)
                            .and_then(|transition| {
                                manager.commit(transition, || Err(MobilityError::Replay))
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
