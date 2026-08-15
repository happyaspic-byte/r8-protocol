use ed25519_dalek::SigningKey;
use r8_mobility::{CandidateManager, CandidateManagerConfig, Control, MobilityError, Policy};
use r8_proto::{Header, NH_SES};
use r8_session::{DirectionalSession, Identity, ObservedBinding, UdpBinding, SESSION_DATA};
use zeroize::Zeroizing;

fn binding() -> ObservedBinding {
    ObservedBinding::Udp(UdpBinding::ipv4([192, 0, 2, 1], 4001, 1, [1; 16]).unwrap())
}

fn manager() -> CandidateManager {
    let signing = SigningKey::from_bytes(&[1; 32]);
    CandidateManager::new_with_protected_replay_binding(
        CandidateManagerConfig {
            signing,
            local: Identity::from_public_key(
                1,
                1,
                SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
            )
            .unwrap(),
            peer: Identity::from_public_key(
                2,
                1,
                SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes(),
            )
            .unwrap(),
            profile: 0,
            scid: 7,
            policy: Policy { policy_id: 9 },
            local_loc: [1; 16],
            peer_loc: [1; 16],
            initial_peer_binding: binding(),
            candidate_secret: [3; 32],
        },
        DirectionalSession::new(
            Zeroizing::new([7; 32]),
            Zeroizing::new([8; 32]),
            [0; 32],
            1280,
        )
        .protected_replay_binding(),
    )
    .unwrap()
}

fn header() -> Header {
    Header {
        profile: 0,
        tc: 0,
        next_header: NH_SES,
        hop_limit: 64,
        flags: 1,
        path_slot: 0,
        scid: 7,
        src: [1; 16],
        dst: [2; 16],
    }
}

#[test]
fn protected_proof_is_session_and_plaintext_bound() {
    let mut sender = DirectionalSession::new(
        Zeroizing::new([1; 32]),
        Zeroizing::new([2; 32]),
        [0; 32],
        1280,
    );
    let receiver = DirectionalSession::new(
        Zeroizing::new([2; 32]),
        Zeroizing::new([1; 32]),
        [0; 32],
        1280,
    );
    let control = Control::LocUpdate {
        candidate_id: [7; 16],
        old_loc: [1; 16],
        new_loc: [2; 16],
        epoch: 1,
        not_before_ms: 0,
        valid_for_ms: 1,
        path_slot: 0,
        signature: [0; 64],
    };
    let plaintext = control.encode().unwrap();
    let packet = sender
        .encrypt(&header(), SESSION_DATA, &plaintext, 1280)
        .unwrap();
    let preview = receiver.preview(&packet).unwrap();
    let proof = preview.into_replay_proof();
    let manager = manager();
    assert!(matches!(
        manager.preview_protected(b"different", &binding(), proof, 1),
        Err(MobilityError::Replay)
    ));

    let preview = receiver.preview(&packet).unwrap();
    let transition =
        manager.preview_protected(&plaintext, &binding(), preview.into_replay_proof(), 1);
    assert!(
        transition.is_err(),
        "the unsigned control must fail before replay commit"
    );
    assert!(
        receiver.preview(&packet).is_ok(),
        "failed manager preview must not burn replay"
    );
}

#[test]
fn protected_proof_cannot_commit_on_another_session() {
    let mut sender = DirectionalSession::new(
        Zeroizing::new([1; 32]),
        Zeroizing::new([2; 32]),
        [0; 32],
        1280,
    );
    let receiver = DirectionalSession::new(
        Zeroizing::new([2; 32]),
        Zeroizing::new([1; 32]),
        [0; 32],
        1280,
    );
    let mut other = DirectionalSession::new(
        Zeroizing::new([2; 32]),
        Zeroizing::new([1; 32]),
        [0; 32],
        1280,
    );
    let packet = sender
        .encrypt(&header(), SESSION_DATA, b"control", 1280)
        .unwrap();
    let mut proof = receiver.preview(&packet).unwrap().into_replay_proof();
    assert!(other.commit_protected_replay(&mut proof).is_err());
}
#[test]
fn protected_preview_is_revoked_when_session_drops() {
    let mut sender = DirectionalSession::new(
        Zeroizing::new([1; 32]),
        Zeroizing::new([2; 32]),
        [0; 32],
        1280,
    );
    let receiver = DirectionalSession::new(
        Zeroizing::new([2; 32]),
        Zeroizing::new([1; 32]),
        [0; 32],
        1280,
    );
    let packet = sender
        .encrypt(&header(), SESSION_DATA, b"lease", 1280)
        .unwrap();
    let preview = receiver.preview(&packet).unwrap();
    drop(receiver);
    assert!(preview.plaintext().is_err());
}
