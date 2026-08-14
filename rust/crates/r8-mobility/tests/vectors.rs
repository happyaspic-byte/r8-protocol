use ed25519_dalek::SigningKey;
use r8_mobility::{
    sign_loc_update, CandidateManager, CandidateManagerConfig, Control, LocUpdateFields,
    MobilityContext, MobilityError, ObservedBinding, Policy,
};
use r8_session::{Identity, UdpBinding};
use serde_json::Value;

const VECTORS: &str = include_str!("../../../../tests/vectors/mobility-v0.1.json");

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect()
}
fn binding(last: u8) -> ObservedBinding {
    ObservedBinding::Udp(
        UdpBinding::ipv4([192, 0, 2, last], 4000 + u16::from(last), 1, [last; 16]).unwrap(),
    )
}

fn manager(role: u8, local_loc: [u8; 16], peer_loc: [u8; 16]) -> CandidateManager {
    let local_key = SigningKey::from_bytes(&[role; 32]);
    let peer_role = if role == 1 { 2 } else { 1 };
    let peer_key = SigningKey::from_bytes(&[peer_role; 32]);
    let local = Identity::from_public_key(role, 1, local_key.verifying_key().to_bytes()).unwrap();
    let peer =
        Identity::from_public_key(peer_role, 1, peer_key.verifying_key().to_bytes()).unwrap();
    CandidateManager::new(CandidateManagerConfig {
        signing: local_key,
        local,
        peer,
        profile: 0,
        scid: 7,
        policy: Policy { policy_id: 9 },
        local_loc,
        peer_loc,
        initial_peer_binding: binding(1),
        candidate_secret: [role; 32],
    })
    .unwrap()
}

fn commit(manager: &CandidateManager, transition: r8_mobility::Transition) {
    manager.commit(transition, || Ok(()), || {}).unwrap();
}

fn flow(mover_role: u8) {
    let old = [1; 16];
    let new = [2; 16];
    let mover = manager(mover_role, old, old);
    let receiver = manager(if mover_role == 1 { 2 } else { 1 }, old, old);
    let carrier = binding(9);
    let update = mover.propose_local([3; 16], new, 1, 0, 100).unwrap();
    let update_bytes = update.encode().unwrap();
    commit(
        &receiver,
        receiver.preview(&update_bytes, &carrier, 1, 100).unwrap(),
    );
    let probe = mover
        .make_probe([3; 16], carrier.clone(), [7; 16], 101)
        .unwrap();
    let probe_bytes = probe.encode().unwrap();
    let probe_transition = receiver.preview(&probe_bytes, &carrier, 2, 101).unwrap();
    let challenge = receiver.response_for(&probe_transition).unwrap().unwrap();
    commit(&receiver, probe_transition);
    let challenge_bytes = challenge.encode().unwrap();
    let response_transition = mover.preview(&challenge_bytes, &carrier, 3, 102).unwrap();
    let response = mover.response_for(&response_transition).unwrap().unwrap();
    commit(&mover, response_transition);
    let response_bytes = response.encode().unwrap();
    commit(
        &receiver,
        receiver.preview(&response_bytes, &carrier, 4, 103).unwrap(),
    );
    let results = receiver.take_results();
    assert_eq!(results.len(), 1);
    let result_bytes = results[0].encode().unwrap();
    commit(
        &mover,
        mover.preview(&result_bytes, &carrier, 5, 104).unwrap(),
    );
    assert_eq!(receiver.peer_loc(), new);
    assert_eq!(mover.local_loc(), new);
    assert_eq!(mover.current_binding(), Some(carrier));
}
#[test]
fn role1_mover_full_candidate_flow() {
    flow(1);
}

#[test]
fn role2_mover_full_candidate_flow() {
    flow(2);
}

#[test]
fn same_epoch_candidates_choose_lexical_winner_after_reverse_proof_order() {
    let mover = manager(1, [1; 16], [1; 16]);
    let receiver = manager(2, [1; 16], [1; 16]);
    let carrier_a = binding(8);
    let carrier_b = binding(9);
    let first = mover.propose_local([1; 16], [4; 16], 1, 0, 0).unwrap();
    let second = mover.propose_local([2; 16], [5; 16], 1, 0, 0).unwrap();

    for (update, carrier, replay) in [(&first, &carrier_a, 1_u64), (&second, &carrier_b, 2)] {
        commit(
            &receiver,
            receiver
                .preview(&update.encode().unwrap(), carrier, replay, 1)
                .unwrap(),
        );
    }

    let first_probe = mover
        .make_probe([1; 16], carrier_a.clone(), [1; 16], 2)
        .unwrap();
    let second_probe = mover
        .make_probe([2; 16], carrier_b.clone(), [2; 16], 2)
        .unwrap();
    let first_transition = receiver
        .preview(&first_probe.encode().unwrap(), &carrier_a, 3, 2)
        .unwrap();
    let first_challenge = receiver.response_for(&first_transition).unwrap().unwrap();
    commit(&receiver, first_transition);
    let second_transition = receiver
        .preview(&second_probe.encode().unwrap(), &carrier_b, 4, 2)
        .unwrap();
    let second_challenge = receiver.response_for(&second_transition).unwrap().unwrap();
    commit(&receiver, second_transition);

    for (challenge, carrier, replay) in [
        (&second_challenge, &carrier_b, 5_u64),
        (&first_challenge, &carrier_a, 6),
    ] {
        let response_transition = mover
            .preview(&challenge.encode().unwrap(), carrier, replay, 3)
            .unwrap();
        let response = mover.response_for(&response_transition).unwrap().unwrap();
        commit(&mover, response_transition);
        commit(
            &receiver,
            receiver
                .preview(&response.encode().unwrap(), carrier, replay + 10, 4)
                .unwrap(),
        );
    }

    let results = receiver.take_results();
    assert_eq!(receiver.peer_loc(), [4; 16]);
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|result| {
        matches!(
            result,
            Control::CandidateResult {
                candidate_id,
                result: 1,
                ..
            } if *candidate_id == [1; 16]
        )
    }));
}
#[test]
fn transition_callback_failure_and_staleness_preserve_state() {
    let mover = manager(1, [1; 16], [1; 16]);
    let manager = manager(2, [1; 16], [1; 16]);
    let update = mover.propose_local([4; 16], [2; 16], 1, 0, 0).unwrap();
    let transition = manager
        .preview(&update.encode().unwrap(), &binding(8), 1, 0)
        .unwrap();
    assert_eq!(
        manager.commit(transition, || Err(MobilityError::Replay), || {}),
        Err(MobilityError::Replay)
    );
    assert_eq!(manager.peer_loc(), [1; 16]);
    let transition = manager
        .preview(&update.encode().unwrap(), &binding(8), 2, 0)
        .unwrap();
    commit(&manager, transition);
    assert_eq!(manager.peer_loc(), [1; 16]);
}

#[test]
fn expiry_grace_and_restart_lifecycle() {
    let manager = manager(1, [1; 16], [1; 16]);
    let first = manager.propose_local([5; 16], [2; 16], 1, 0, 0).unwrap();
    manager.expire(5_000);
    assert!(matches!(
        manager.preview(&first.encode().unwrap(), &binding(8), 1, 5_000),
        Err(MobilityError::Candidate)
    ));
    assert!(manager.binding_allowed_inbound(&binding(1), 0));
    manager.restart();
    assert_eq!(
        manager.make_probe([5; 16], binding(8), [5; 16], 1),
        Err(MobilityError::Candidate)
    );
}
#[test]
fn local_proposals_are_idempotent_capacity_bounded_and_nonce_exact() {
    let manager = manager(1, [1; 16], [1; 16]);
    let first = manager.propose_local([6; 16], [2; 16], 1, 0, 0).unwrap();
    assert_eq!(
        manager.propose_local([6; 16], [2; 16], 1, 0, 100).unwrap(),
        first
    );
    assert_eq!(
        manager.propose_local([6; 16], [3; 16], 1, 0, 100),
        Err(MobilityError::Candidate)
    );
    manager.propose_local([7; 16], [3; 16], 2, 0, 100).unwrap();
    assert_eq!(
        manager.propose_local([8; 16], [4; 16], 3, 0, 100),
        Err(MobilityError::Capacity)
    );
    let probe = manager
        .make_probe([6; 16], binding(8), [9; 16], 101)
        .unwrap();
    assert!(matches!(
        probe,
        Control::BindProbe {
            probe_nonce,
            ..
        } if probe_nonce == [9; 16]
    ));
}
#[test]
fn inbound_same_candidate_id_conflict_is_state_preserving() {
    let receiver = manager(2, [1; 16], [1; 16]);
    let sender_key = SigningKey::from_bytes(&[1; 32]);
    let sender = Identity::from_public_key(1, 1, sender_key.verifying_key().to_bytes()).unwrap();
    let receiver_key = SigningKey::from_bytes(&[2; 32]);
    let receiver_identity =
        Identity::from_public_key(2, 1, receiver_key.verifying_key().to_bytes()).unwrap();
    let context = MobilityContext {
        profile: 0,
        scid: 7,
        sender: &sender,
        receiver: &receiver_identity,
        policy_id: 9,
    };
    let accepted = sign_loc_update(
        &sender_key,
        context,
        LocUpdateFields {
            candidate_id: [7; 16],
            old_loc: [1; 16],
            new_loc: [2; 16],
            epoch: 1,
            path_slot: 0,
        },
    )
    .unwrap();
    commit(
        &receiver,
        receiver
            .preview(&accepted.encode().unwrap(), &binding(8), 1, 0)
            .unwrap(),
    );
    commit(
        &receiver,
        receiver
            .preview(&accepted.encode().unwrap(), &binding(8), 2, 1)
            .unwrap(),
    );
    let conflicting = sign_loc_update(
        &sender_key,
        context,
        LocUpdateFields {
            candidate_id: [7; 16],
            old_loc: [1; 16],
            new_loc: [3; 16],
            epoch: 1,
            path_slot: 0,
        },
    )
    .unwrap();
    assert!(matches!(
        receiver.preview(&conflicting.encode().unwrap(), &binding(8), 2, 1),
        Err(MobilityError::Candidate)
    ));
    assert_eq!(receiver.peer_loc(), [1; 16]);
}
#[test]
fn failed_candidate_id_cannot_be_reused_after_proposal_expiry() {
    let mover = manager(1, [1; 16], [1; 16]);
    let receiver = manager(2, [1; 16], [1; 16]);
    let carrier = binding(8);
    let update = mover.propose_local([8; 16], [2; 16], 1, 0, 0).unwrap();
    commit(
        &receiver,
        receiver
            .preview(&update.encode().unwrap(), &carrier, 1, 0)
            .unwrap(),
    );
    let probe = mover
        .make_probe([8; 16], carrier.clone(), [8; 16], 1)
        .unwrap();
    let transition = receiver
        .preview(&probe.encode().unwrap(), &carrier, 2, 1)
        .unwrap();
    commit(&receiver, transition);
    receiver.expire(5_000);

    assert!(matches!(
        receiver.preview(&update.encode().unwrap(), &carrier, 3, 5_000),
        Err(MobilityError::Candidate)
    ));
    assert_eq!(receiver.peer_loc(), [1; 16]);
}

#[test]
fn profile_slot_contract_rejects_every_control_kind() {
    let manager = manager(1, [1; 16], [1; 16]);
    for control in [
        Control::LocUpdate {
            candidate_id: [1; 16],
            old_loc: [1; 16],
            new_loc: [2; 16],
            epoch: 1,
            not_before_ms: 0,
            valid_for_ms: 5_000,
            path_slot: 1,
            signature: [0; 64],
        },
        Control::BindProbe {
            candidate_id: [1; 16],
            loc: [2; 16],
            epoch: 1,
            path_slot: 1,
            probe_nonce: [0; 16],
        },
        Control::BindChallenge {
            candidate_id: [1; 16],
            loc: [2; 16],
            epoch: 1,
            path_slot: 1,
            expiry_ms: 1,
            token: [0; 32],
        },
        Control::BindResponse {
            candidate_id: [1; 16],
            loc: [2; 16],
            epoch: 1,
            path_slot: 1,
            expiry_ms: 1,
            token: [0; 32],
        },
        Control::CandidateResult {
            candidate_id: [1; 16],
            epoch: 1,
            path_slot: 1,
            result: 1,
        },
    ] {
        assert!(matches!(
            manager.preview(&control.encode().unwrap(), &binding(8), 1, 0),
            Err(MobilityError::Candidate)
        ));
    }
}

#[test]
fn outbound_result_capacity_rejects_before_local_commit() {
    let manager = manager(1, [1; 16], [1; 16]);

    for (candidate_id, epoch, carrier) in [([1; 16], 1_u64, binding(8)), ([2; 16], 2, binding(9))] {
        manager
            .propose_local(candidate_id, [epoch as u8 + 1; 16], epoch, 0, 0)
            .unwrap();
        manager
            .make_probe(candidate_id, carrier.clone(), candidate_id, 1)
            .unwrap();
        let result = Control::CandidateResult {
            candidate_id,
            epoch,
            path_slot: 0,
            result: 1,
        };
        let transition = manager
            .preview(&result.encode().unwrap(), &carrier, epoch, 2)
            .unwrap();
        commit(&manager, transition);
    }

    let carrier = binding(10);
    manager.propose_local([3; 16], [4; 16], 3, 0, 3).unwrap();
    manager
        .make_probe([3; 16], carrier.clone(), [3; 16], 4)
        .unwrap();
    let result = Control::CandidateResult {
        candidate_id: [3; 16],
        epoch: 3,
        path_slot: 0,
        result: 1,
    };
    assert!(matches!(
        manager.preview(&result.encode().unwrap(), &carrier, 3, 5),
        Err(MobilityError::Capacity)
    ));
    assert_eq!(manager.local_loc(), [3; 16]);
}
#[test]
fn corpus_positive_controls_are_byte_identical() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    for case in vectors["positive_cases"].as_array().unwrap() {
        let plaintext = hex(case["plaintext_hex"].as_str().unwrap());
        assert_eq!(
            Control::parse(&plaintext).unwrap().encode().unwrap(),
            plaintext
        );
        assert_eq!(
            plaintext.len(),
            case["exact_size"].as_u64().unwrap() as usize
        );
    }
}

#[test]
fn corpus_negative_fixture_schema_and_bytes_are_well_formed() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let negative = vectors["negative_cases"].as_array().unwrap();
    assert_eq!(negative.len(), 43);

    for case in negative {
        let input = hex(case["input_hex"].as_str().unwrap());
        assert!(!input.is_empty(), "{}", case["id"]);
        assert!(case["setup"]["clock_ms"].is_u64(), "{}", case["id"]);
        assert!(
            case["setup"]["current_binding_hex"].is_string(),
            "{}",
            case["id"]
        );
        match case["expected_error"].as_str().unwrap() {
            "E-CANDIDATE" | "E-CAPACITY" | "E-TIMEOUT" | "E-REPLAY" => {}
            other => panic!("unknown fixture category {other}"),
        }
        match case["operation"].as_str().unwrap() {
            "parse_control" | "validate_update" | "submit_update" | "receive_probe"
            | "receive_response" | "receive_result" | "replay_control" | "validate_roles" => {}
            other => panic!("unknown fixture operation {other}"),
        }
    }
}

#[test]
fn observed_bindings_are_canonical() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let bytes = hex(vectors["context"]["udp_binding_ipv4_hex"].as_str().unwrap());
    assert_eq!(ObservedBinding::parse(&bytes).unwrap().encode(), bytes);
    assert_eq!(
        ObservedBinding::parse(&[2, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6]),
        Err(MobilityError::Candidate)
    );
    assert!(UdpBinding::parse(bytes).is_ok());
}
