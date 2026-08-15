use core::num::NonZeroU64;

use ed25519_dalek::SigningKey;
use r8_mobility::{
    CandidateManager, CandidateManagerConfig, Control, MobilityError, Policy,
    Profile3AdmissionOwner,
};
use r8_redundant::{
    PathState, ReceiveOutcome, RedundantError, RedundantEvent, RedundantSession, SendOutcome,
    SessionState,
};
use r8_session::{
    ClientMachine, ClientMaterial, HandshakeConfig, Identity, ObservedBinding, ServerMachine,
    ServerMaterial, UdpBinding,
};

fn binding(last: u8) -> ObservedBinding {
    ObservedBinding::Udp(
        UdpBinding::ipv4([192, 0, 2, last], 4000 + u16::from(last), 1, [last; 16]).unwrap(),
    )
}

fn identity(role: u8) -> (SigningKey, Identity) {
    let key = SigningKey::from_bytes(&[role; 32]);
    let identity = Identity::from_public_key(role, 7, key.verifying_key().to_bytes()).unwrap();
    (key, identity)
}

fn bootstraps() -> (
    r8_session::Profile3Bootstrap,
    r8_session::Profile3Bootstrap,
    u64,
) {
    let (client_key, client_identity) = identity(1);
    let (server_key, server_identity) = identity(2);
    let scid = 0x0102_0304_0506_0708;
    let client_config = HandshakeConfig {
        local: client_identity.clone(),
        peer: server_identity.clone(),
        profile: 3,
        source: [3; 16],
        destination: [4; 16],
        budget: 1280,
        pending_limit: 4,
        established_limit: 4,
        server_context_id: 1,
    };
    let server_config = HandshakeConfig {
        local: server_identity,
        peer: client_identity,
        profile: 3,
        source: [3; 16],
        destination: [4; 16],
        budget: 1280,
        pending_limit: 4,
        established_limit: 4,
        server_context_id: 1,
    };
    let mut client = ClientMachine::new(client_config, client_key).unwrap();
    let mut server = ServerMachine::new(
        server_config,
        server_key,
        ServerMaterial {
            boot_instance: [5; 16],
            current_cookie_key: [6; 32],
            previous_cookie_key: [7; 32],
            previous_key_rotated_ms: 0,
        },
    )
    .unwrap();
    let carrier = binding(1);
    let open = client
        .start(
            scid,
            ClientMaterial {
                ephemeral_secret: [9; 32],
                nonce: [10; 32],
            },
            0,
        )
        .unwrap();
    let verify = server.receive_open(&open, &carrier, 0).unwrap();
    let auth = client.receive_verify(&verify, 0).unwrap();
    let ack = server
        .receive_open_auth(
            &auth,
            &carrier,
            0,
            0,
            Some(ServerMaterial::handshake_material([11; 32], [12; 32])),
        )
        .unwrap();
    let accept = client.receive_ack(&ack, 0).unwrap();
    server.receive_accept(&accept, 0).unwrap();
    (
        client.take_profile3_bootstrap().unwrap(),
        server.take_profile3_bootstrap(scid).unwrap(),
        scid,
    )
}

fn manager(
    role: u8,
    local_loc: [u8; 16],
    peer_loc: [u8; 16],
    scid: u64,
    policy_id: u32,
    owner: Profile3AdmissionOwner,
) -> CandidateManager {
    let (signing, local) = identity(role);
    let (_, peer) = identity(if role == 1 { 2 } else { 1 });
    CandidateManager::new_with_profile3_admission_owner(
        CandidateManagerConfig {
            signing,
            local,
            peer,
            profile: 3,
            scid,
            policy: Policy { policy_id },
            local_loc,
            peer_loc,
            initial_peer_binding: binding(1),
            candidate_secret: [role; 32],
        },
        owner,
    )
    .unwrap()
}

fn protected_control(
    sender: &mut RedundantSession,
    receiver: &mut RedundantSession,
    manager: &CandidateManager,
    control: &Control,
    observed_binding: &ObservedBinding,
    now_ms: u64,
) -> Option<Control> {
    let packets = match sender.outbound(&control.encode().unwrap()).unwrap() {
        SendOutcome::Enqueued { packets, .. } => packets,
        SendOutcome::DroppedNewest => panic!("control queue"),
    };
    let wire = packets
        .iter()
        .find(|packet| packet.slot() == 0)
        .unwrap()
        .packet()
        .to_vec();
    let preview = receiver
        .preview_mobility_inbound(0, observed_binding, &wire, now_ms)
        .unwrap();
    let commit = receiver
        .prepare_mobility_commit(manager, observed_binding, preview, now_ms)
        .unwrap();
    let response = receiver.mobility_response(manager, &commit).unwrap();
    receiver.commit_mobility(manager, commit).unwrap();
    sender.confirm_sent(0, &wire).unwrap();
    response
}

fn admissions(
    client_state: &mut RedundantSession,
    server_state: &mut RedundantSession,
    scid: u64,
    client_owner: Profile3AdmissionOwner,
    server_owner: Profile3AdmissionOwner,
    policy_id: u32,
) -> (
    r8_mobility::Profile3Admission,
    r8_mobility::Profile3Admission,
) {
    let mover = manager(1, [3; 16], [4; 16], scid, policy_id, client_owner);
    let receiver = manager(2, [4; 16], [3; 16], scid, policy_id, server_owner);
    let initial = binding(1);
    let candidate = binding(9);
    let update = mover.propose_local([13; 16], [9; 16], 1, 1, 100).unwrap();
    assert!(protected_control(
        client_state,
        server_state,
        &receiver,
        &update,
        &initial,
        100,
    )
    .is_none());
    let probe = mover
        .make_probe([13; 16], candidate.clone(), [7; 16], 101)
        .unwrap();
    let challenge = protected_control(
        client_state,
        server_state,
        &receiver,
        &probe,
        &candidate,
        101,
    )
    .unwrap();
    let response = protected_control(
        server_state,
        client_state,
        &mover,
        &challenge,
        &candidate,
        102,
    )
    .unwrap();
    assert!(protected_control(
        client_state,
        server_state,
        &receiver,
        &response,
        &candidate,
        103,
    )
    .is_none());
    let result = receiver.take_results().pop().unwrap();
    assert!(
        protected_control(server_state, client_state, &mover, &result, &candidate, 104,).is_none()
    );
    let client = mover.take_profile3_admissions().pop().unwrap();
    let server = receiver.take_profile3_admissions().pop().unwrap();
    assert_eq!(client.scid(), scid);
    assert_eq!(server.scid(), scid);
    assert_ne!(client.local_loc(), server.local_loc());
    assert_ne!(client.binding(), &initial);
    assert_ne!(server.binding(), &initial);
    assert_eq!(mover.take_profile3_admissions().len(), 0);
    assert_eq!(receiver.take_profile3_admissions().len(), 0);
    (client, server)
}

fn sessions(seed: u64) -> (RedundantSession, RedundantSession) {
    let (client_bootstrap, server_bootstrap, _scid) = bootstraps();
    let mut client =
        RedundantSession::new(client_bootstrap, binding(1), NonZeroU64::new(seed).unwrap())
            .unwrap();
    let mut server = RedundantSession::new(
        server_bootstrap,
        binding(1),
        NonZeroU64::new(
            seed.checked_add(30)
                .filter(|value| *value < u64::MAX - 2)
                .unwrap_or(1),
        )
        .unwrap(),
    )
    .unwrap();
    let client_owner = client.issue_profile3_admission_owner(9).unwrap();
    let server_owner = server.issue_profile3_admission_owner(9).unwrap();
    let (client_admission, server_admission) = admissions(
        &mut client,
        &mut server,
        client_owner.scid(),
        client_owner,
        server_owner,
        9,
    );
    assert_eq!(client.drain_events(), vec![RedundantEvent::InitialDegraded]);
    assert_eq!(server.drain_events(), vec![RedundantEvent::InitialDegraded]);
    client.activate(client_admission, 1280).unwrap();
    server.activate(server_admission, 1280).unwrap();
    assert_eq!(client.drain_events(), vec![RedundantEvent::Recovered]);
    assert_eq!(server.drain_events(), vec![RedundantEvent::Recovered]);
    assert_eq!(client.path_state(0), Some(PathState::Active));
    assert_eq!(client.path_state(1), Some(PathState::Active));
    assert_eq!(server.path_state(0), Some(PathState::Active));
    assert_eq!(server.path_state(1), Some(PathState::Active));
    (client, server)
}
#[test]
fn slot1_uses_its_admitted_budget() {
    let (client_bootstrap, server_bootstrap, _scid) = bootstraps();
    let mut client =
        RedundantSession::new(client_bootstrap, binding(1), NonZeroU64::new(1).unwrap()).unwrap();
    let mut server =
        RedundantSession::new(server_bootstrap, binding(1), NonZeroU64::new(31).unwrap()).unwrap();
    let client_owner = client.issue_profile3_admission_owner(9).unwrap();
    let server_owner = server.issue_profile3_admission_owner(9).unwrap();
    let (client_admission, _) = admissions(
        &mut client,
        &mut server,
        client_owner.scid(),
        client_owner,
        server_owner,
        9,
    );

    client.activate(client_admission, 84).unwrap();
    assert!(matches!(
        client.outbound(b"x"),
        Err(RedundantError::MtuExceeded)
    ));
    assert!(matches!(
        client.outbound(b""),
        Ok(SendOutcome::Enqueued { .. })
    ));
}
#[test]
fn same_scid_foreign_session_and_policy_admissions_do_not_consume_target_owner() {
    let (target_bootstrap, target_peer_bootstrap, _scid) = bootstraps();
    let (foreign_bootstrap, foreign_peer_bootstrap, _scid) = bootstraps();
    let (policy_bootstrap, policy_peer_bootstrap, _scid) = bootstraps();
    let mut target =
        RedundantSession::new(target_bootstrap, binding(1), NonZeroU64::new(1).unwrap()).unwrap();
    let mut target_peer = RedundantSession::new(
        target_peer_bootstrap,
        binding(1),
        NonZeroU64::new(31).unwrap(),
    )
    .unwrap();
    let mut foreign =
        RedundantSession::new(foreign_bootstrap, binding(1), NonZeroU64::new(2).unwrap()).unwrap();
    let mut foreign_peer = RedundantSession::new(
        foreign_peer_bootstrap,
        binding(1),
        NonZeroU64::new(32).unwrap(),
    )
    .unwrap();
    let mut other_policy =
        RedundantSession::new(policy_bootstrap, binding(1), NonZeroU64::new(3).unwrap()).unwrap();
    let mut policy_peer = RedundantSession::new(
        policy_peer_bootstrap,
        binding(1),
        NonZeroU64::new(33).unwrap(),
    )
    .unwrap();
    let target_owner = target.issue_profile3_admission_owner(9).unwrap();
    let scid = target_owner.scid();
    let target_peer_owner = target_peer.issue_profile3_admission_owner(9).unwrap();

    let foreign_owner = foreign.issue_profile3_admission_owner(9).unwrap();
    let foreign_peer_owner = foreign_peer.issue_profile3_admission_owner(9).unwrap();
    let foreign_admission = admissions(
        &mut foreign,
        &mut foreign_peer,
        scid,
        foreign_owner,
        foreign_peer_owner,
        9,
    )
    .0;
    assert_eq!(
        target.activate(foreign_admission, 1280),
        Err(RedundantError::AdmissionInvalid)
    );

    let policy_owner = other_policy.issue_profile3_admission_owner(10).unwrap();
    let policy_peer_owner = policy_peer.issue_profile3_admission_owner(10).unwrap();
    let policy_admission = admissions(
        &mut other_policy,
        &mut policy_peer,
        scid,
        policy_owner,
        policy_peer_owner,
        10,
    )
    .0;
    assert_eq!(
        target.activate(policy_admission, 1280),
        Err(RedundantError::AdmissionInvalid)
    );
    assert_eq!(target.path_state(1), Some(PathState::Absent));

    let target_admission = admissions(
        &mut target,
        &mut target_peer,
        scid,
        target_owner,
        target_peer_owner,
        9,
    )
    .0;
    target.activate(target_admission, 1280).unwrap();
}

fn enqueued(
    session: &mut RedundantSession,
    bytes: &[u8],
) -> (NonZeroU64, Vec<r8_redundant::OutboundPacket>) {
    match session.outbound(bytes).unwrap() {
        SendOutcome::Enqueued {
            delivery_id,
            packets,
        } => (delivery_id, packets),
        SendOutcome::DroppedNewest => panic!("unexpected queue overflow"),
    }
}

#[test]
fn authenticated_redundant_delivery_and_hop_decrement() {
    let (mut client, mut server) = sessions(41);
    let (id, mut packets) = enqueued(&mut client, b"one authenticated delivery");
    assert_eq!(id.get(), 44);
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].slot(), 0);
    assert_eq!(packets[0].binding(), &binding(1));
    assert_eq!(packets[1].slot(), 1);
    assert_ne!(packets[1].binding(), &binding(1));
    let mut first_packet = packets[0].packet().to_vec();
    first_packet[5] -= 1;
    let second = packets.pop().unwrap();
    let first = packets.pop().unwrap();
    assert!(matches!(
        server.inbound(second.slot(), second.binding(), second.packet(), 1).unwrap(),
        ReceiveOutcome::Delivered(bytes) if bytes == b"one authenticated delivery"
    ));
    assert!(matches!(
        server
            .inbound(first.slot(), first.binding(), &first_packet, 2)
            .unwrap(),
        ReceiveOutcome::Suppressed
    ));
}

#[test]
fn budget_queue_and_exact_fifo_confirmation() {
    let (mut client, _) = sessions(41);
    let (first_id, _) = enqueued(&mut client, &vec![0x51; 1196]);
    assert_eq!(first_id.get(), 44);
    assert_eq!(
        client.outbound(&vec![0x52; 1197]).unwrap_err().category(),
        "E-BUDGET"
    );
    let (next_id, _) = enqueued(&mut client, b"counter unchanged by budget rejection");
    assert_eq!(next_id.get(), 45);

    let (mut client, _) = sessions(41);
    for _ in 0..256 {
        let _ = enqueued(&mut client, b"q");
    }
    assert!(matches!(
        client.outbound(b"q").unwrap(),
        SendOutcome::DroppedNewest
    ));
    assert_eq!(client.drain_events(), vec![RedundantEvent::QueueOverflow]);
    let packet = client.front(0).unwrap().packet().to_vec();
    assert_eq!(
        client
            .confirm_sent(0, b"not the queued ciphertext")
            .unwrap_err()
            .category(),
        "E-PATH"
    );
    assert_eq!(client.front(0).unwrap().packet(), packet.as_slice());
    client.confirm_sent(0, &packet).unwrap();
    assert_ne!(client.front(0).unwrap().packet(), packet.as_slice());
}

#[test]
fn lifecycle_errors_and_redaction_are_observable() {
    let (mut client, mut server) = sessions(41);
    let (_, packets) = enqueued(&mut client, b"sensitive plaintext");
    let packet = &packets[0];
    assert_eq!(
        server
            .inbound(packet.slot(), &binding(99), packet.packet(), 0)
            .unwrap_err()
            .category(),
        "E-PATH"
    );
    client.remove_path(1).unwrap();
    assert_eq!(client.path_state(1), Some(PathState::Removed));
    assert_eq!(client.drain_events(), vec![RedundantEvent::Degraded]);
    let (fresh_bootstrap, fresh_peer_bootstrap, fresh_scid) = bootstraps();
    let mut fresh =
        RedundantSession::new(fresh_bootstrap, binding(1), NonZeroU64::new(71).unwrap()).unwrap();
    let mut fresh_peer = RedundantSession::new(
        fresh_peer_bootstrap,
        binding(1),
        NonZeroU64::new(72).unwrap(),
    )
    .unwrap();
    let fresh_owner = fresh.issue_profile3_admission_owner(9).unwrap();
    let fresh_peer_owner = fresh_peer.issue_profile3_admission_owner(9).unwrap();
    let foreign_admission = admissions(
        &mut fresh,
        &mut fresh_peer,
        fresh_scid,
        fresh_owner,
        fresh_peer_owner,
        9,
    )
    .0;
    assert_eq!(
        client
            .activate(foreign_admission, 1280)
            .unwrap_err()
            .category(),
        "E-CANDIDATE"
    );
    client.remove_path(0).unwrap();
    assert_eq!(client.state(), SessionState::Released);
    assert_eq!(
        client.drain_events(),
        vec![RedundantEvent::Degraded, RedundantEvent::Released]
    );
    assert_eq!(
        client.outbound(b"after close").unwrap_err().category(),
        "E-TIMEOUT"
    );
    let debug = format!("{client:?}{packet:?}");
    for secret in [
        "sensitive plaintext",
        "0102030405060708",
        "[9, 9",
        "[192, 0, 2",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn error_categories_are_stable() {
    assert_eq!(RedundantError::MtuExceeded.category(), "E-BUDGET");
    assert_eq!(RedundantError::DedupCapacity.category(), "E-CAPACITY");
    assert_eq!(RedundantError::DeliveryGap.category(), "E-REPLAY");
    assert_eq!(RedundantError::AdmissionInvalid.category(), "E-CANDIDATE");
    assert_eq!(RedundantError::Released.category(), "E-TIMEOUT");
    assert_eq!(RedundantError::DivergentDelivery.category(), "E-PATH");
    assert_eq!(MobilityError::Candidate.as_str(), "E-CANDIDATE");
}

#[test]
fn delivery_gap_boundaries_are_authenticated() {
    let (mut sender, mut receiver) = sessions(41);
    let (_, packets) = enqueued(&mut sender, b"stored delivery");
    assert!(matches!(
        receiver.inbound(packets[0].slot(), packets[0].binding(), packets[0].packet(), 0).unwrap(),
        ReceiveOutcome::Delivered(bytes) if bytes == b"stored delivery"
    ));

    let (mut exact_sender, _) = sessions(41 + 65_535);
    let (burned, _) = enqueued(&mut exact_sender, b"burned counter two");
    assert_eq!(burned.get(), 65_579);
    let (exact_id, packets) = enqueued(&mut exact_sender, b"exact delivery gap");
    assert_eq!(exact_id.get(), 65_580);
    assert!(matches!(
        receiver.inbound(packets[0].slot(), packets[0].binding(), packets[0].packet(), 1).unwrap(),
        ReceiveOutcome::Delivered(bytes) if bytes == b"exact delivery gap"
    ));

    let (mut baseline_sender, mut gap_receiver) = sessions(41);
    let (_, packets) = enqueued(&mut baseline_sender, b"stored delivery");
    assert!(matches!(
        gap_receiver
            .inbound(
                packets[0].slot(),
                packets[0].binding(),
                packets[0].packet(),
                0
            )
            .unwrap(),
        ReceiveOutcome::Delivered(_)
    ));
    let (mut too_far_sender, _) = sessions(41 + 65_536);
    let (burned, _) = enqueued(&mut too_far_sender, b"burned counter two");
    assert_eq!(burned.get(), 65_580);
    let (too_far_id, packets) = enqueued(&mut too_far_sender, b"too far delivery gap");
    assert_eq!(too_far_id.get(), 65_581);
    assert_eq!(
        gap_receiver
            .inbound(
                packets[0].slot(),
                packets[0].binding(),
                packets[0].packet(),
                1
            )
            .unwrap_err()
            .category(),
        "E-REPLAY"
    );
}

#[test]
fn dedup_capacity_advances_identity_window_without_redelivery() {
    let (mut sender, mut receiver) = sessions(41);
    let mut oldest = None;
    for value in 0_u16..4096 {
        let bytes = value.to_be_bytes();
        let (_, packets) = enqueued(&mut sender, &bytes);
        if value == 0 {
            oldest = Some((
                packets[1].slot(),
                packets[1].binding().clone(),
                packets[1].packet().to_vec(),
            ));
        }
        for packet in &packets {
            sender.confirm_sent(packet.slot(), packet.packet()).unwrap();
        }
        assert!(matches!(
            receiver.inbound(packets[0].slot(), packets[0].binding(), packets[0].packet(), 0).unwrap(),
            ReceiveOutcome::Delivered(received) if received == bytes
        ));
    }

    let (_, packets) = enqueued(&mut sender, b"after dedup capacity");
    for packet in &packets {
        sender.confirm_sent(packet.slot(), packet.packet()).unwrap();
    }
    assert!(matches!(
        receiver.inbound(packets[0].slot(), packets[0].binding(), packets[0].packet(), 1).unwrap(),
        ReceiveOutcome::Delivered(bytes) if bytes == b"after dedup capacity"
    ));
    let (slot, binding, packet) = oldest.unwrap();
    assert_eq!(
        receiver.inbound(slot, &binding, &packet, 2).unwrap_err(),
        RedundantError::Replay
    );
    assert_eq!(receiver.state(), SessionState::Active);
}
#[test]
fn transactional_receive_abort_preserves_replay_and_delivery_state() {
    let (mut sender, mut receiver) = sessions(41);
    let (_, packets) = enqueued(&mut sender, b"transactional");
    let preview = receiver
        .preview_inbound(
            packets[0].slot(),
            packets[0].binding(),
            packets[0].packet(),
            0,
        )
        .unwrap();
    assert_eq!(preview.plaintext().unwrap(), b"transactional");
    assert!(matches!(
        receiver.preview_inbound(
            packets[0].slot(),
            packets[0].binding(),
            packets[0].packet(),
            0,
        ),
        Err(RedundantError::DedupCapacity)
    ));
    receiver.abort_inbound(preview).unwrap();
    assert!(matches!(
        receiver
            .inbound(
                packets[0].slot(),
                packets[0].binding(),
                packets[0].packet(),
                0,
            )
            .unwrap(),
        ReceiveOutcome::Delivered(bytes) if bytes == b"transactional"
    ));
}
#[test]
fn dropped_receive_preview_releases_occupancy_without_replaying() {
    let (mut sender, mut receiver) = sessions(41);
    let (_, packets) = enqueued(&mut sender, b"dropped preview");
    let preview = receiver
        .preview_inbound(
            packets[0].slot(),
            packets[0].binding(),
            packets[0].packet(),
            0,
        )
        .unwrap();
    drop(preview);
    let preview = receiver
        .preview_inbound(
            packets[0].slot(),
            packets[0].binding(),
            packets[0].packet(),
            0,
        )
        .unwrap();
    assert_eq!(preview.plaintext().unwrap(), b"dropped preview");
    receiver.abort_inbound(preview).unwrap();
}
#[test]
fn close_revokes_preview_plaintext() {
    let (mut sender, mut receiver) = sessions(41);
    let (_, packets) = enqueued(&mut sender, b"revocable preview");
    let preview = receiver
        .preview_inbound(
            packets[0].slot(),
            packets[0].binding(),
            packets[0].packet(),
            0,
        )
        .unwrap();
    receiver.close();
    assert_eq!(preview.plaintext(), Err(RedundantError::Released));
}
#[test]
fn delayed_second_path_copy_is_suppressed_after_digest_expiry() {
    let (mut sender, mut receiver) = sessions(41);
    let (_, packets) = enqueued(&mut sender, b"delayed redundant delivery");

    assert!(matches!(
        receiver
            .inbound(packets[0].slot(), packets[0].binding(), packets[0].packet(), 0)
            .unwrap(),
        ReceiveOutcome::Delivered(bytes) if bytes == b"delayed redundant delivery"
    ));
    assert!(matches!(
        receiver
            .inbound(
                packets[1].slot(),
                packets[1].binding(),
                packets[1].packet(),
                30_000
            )
            .unwrap(),
        ReceiveOutcome::Suppressed
    ));
    assert_eq!(receiver.state(), SessionState::Active);
}

#[test]
fn delivered_window_suppresses_copy_at_its_expired_lower_boundary() {
    let (mut sender, mut receiver) = sessions(41);
    let (_, first) = enqueued(&mut sender, b"window lower boundary");

    assert!(matches!(
        receiver
            .inbound(first[0].slot(), first[0].binding(), first[0].packet(), 0)
            .unwrap(),
        ReceiveOutcome::Delivered(_)
    ));
    for packet in &first {
        sender.confirm_sent(packet.slot(), packet.packet()).unwrap();
    }
    for value in 1_u16..=4095 {
        let (_, packets) = enqueued(&mut sender, &value.to_be_bytes());
        for packet in &packets {
            sender.confirm_sent(packet.slot(), packet.packet()).unwrap();
        }
        assert!(matches!(
            receiver
                .inbound(
                    packets[0].slot(),
                    packets[0].binding(),
                    packets[0].packet(),
                    u64::from(value) * 30_000
                )
                .unwrap(),
            ReceiveOutcome::Delivered(_)
        ));
    }

    assert!(matches!(
        receiver
            .inbound(
                first[1].slot(),
                first[1].binding(),
                first[1].packet(),
                4096 * 30_000
            )
            .unwrap(),
        ReceiveOutcome::Suppressed
    ));
    assert_eq!(receiver.state(), SessionState::Active);
}

#[test]
fn divergent_same_id_after_plaintext_expiry_releases_receiver() {
    let (mut sender, mut receiver) = sessions(41);
    let (mut divergent_sender, _) = sessions(41);
    let (_, original) = enqueued(&mut sender, b"original");
    let (_, divergent) = enqueued(&mut divergent_sender, b"different");
    assert!(matches!(
        receiver
            .inbound(
                original[0].slot(),
                original[0].binding(),
                original[0].packet(),
                0
            )
            .unwrap(),
        ReceiveOutcome::Delivered(bytes) if bytes == b"original"
    ));
    assert!(matches!(
        receiver
            .inbound(
                divergent[1].slot(),
                divergent[1].binding(),
                divergent[1].packet(),
                30_000
            )
            .unwrap(),
        ReceiveOutcome::Closed
    ));
    assert_eq!(receiver.state(), SessionState::Released);
    assert_eq!(
        receiver.drain_events(),
        vec![RedundantEvent::Divergence, RedundantEvent::Released]
    );
}
#[test]
fn divergent_authenticated_delivery_releases_the_receiver() {
    let (mut sender, mut receiver) = sessions(41);
    let (_, packets) = enqueued(&mut sender, b"original delivery");
    assert!(matches!(
        receiver
            .inbound(
                packets[0].slot(),
                packets[0].binding(),
                packets[0].packet(),
                0
            )
            .unwrap(),
        ReceiveOutcome::Delivered(_)
    ));

    let (mut divergent_sender, _) = sessions(40);
    let (burned, _) = enqueued(&mut divergent_sender, b"burned counter two");
    assert_eq!(burned.get(), 43);
    let (id, packets) = enqueued(&mut divergent_sender, b"divergent delivery");
    assert_eq!(id.get(), 44);
    assert!(matches!(
        receiver
            .inbound(
                packets[0].slot(),
                packets[0].binding(),
                packets[0].packet(),
                1
            )
            .unwrap(),
        ReceiveOutcome::Closed
    ));
    assert_eq!(
        receiver.drain_events(),
        vec![RedundantEvent::Divergence, RedundantEvent::Released]
    );
    assert_eq!(receiver.state(), SessionState::Released);
    let debug = format!("{sender:?}{receiver:?}{packets:?}");
    assert!(!debug.contains("divergent delivery"));
}

#[test]
fn counter_exhaustion_and_event_buffer_boundaries_release_without_leaking() {
    let (mut exhausted, _) = sessions(u64::MAX - 3);
    assert_eq!(
        exhausted
            .outbound(b"counter exhaustion")
            .unwrap_err()
            .category(),
        "E-COUNTER"
    );
    assert_eq!(exhausted.state(), SessionState::Released);
    assert_eq!(exhausted.drain_events(), vec![RedundantEvent::Released]);

    let (mut queued, _) = sessions(41);
    for _ in 0..256 {
        let _ = enqueued(&mut queued, b"q");
    }
    for _ in 0..100 {
        assert!(matches!(
            queued.outbound(b"q").unwrap(),
            SendOutcome::DroppedNewest
        ));
    }
    let events = queued.drain_events();
    assert_eq!(events.len(), 64);
    assert!(events
        .iter()
        .all(|event| *event == RedundantEvent::QueueOverflow));
    assert!(!format!("{queued:?}").contains("[41, 41"));
}
