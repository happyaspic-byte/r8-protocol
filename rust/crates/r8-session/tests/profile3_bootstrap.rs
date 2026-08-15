use core::num::NonZeroU64;

use ed25519_dalek::SigningKey;
use r8_proto::{Header, NH_SES};
use r8_session::{
    ClientMachine, ClientMaterial, HandshakeConfig, Identity, ObservedBinding, ServerMachine,
    ServerMaterial, SessionError,
};

fn machines(profile: u8) -> (ClientMachine, ServerMachine) {
    let client_key = SigningKey::from_bytes(&[1; 32]);
    let server_key = SigningKey::from_bytes(&[2; 32]);
    let client_identity =
        Identity::from_public_key(1, 7, client_key.verifying_key().to_bytes()).unwrap();
    let server_identity =
        Identity::from_public_key(2, 7, server_key.verifying_key().to_bytes()).unwrap();
    let client_config = HandshakeConfig {
        local: client_identity.clone(),
        peer: server_identity.clone(),
        profile,
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
        profile,
        source: [3; 16],
        destination: [4; 16],
        budget: 1280,
        pending_limit: 4,
        established_limit: 4,
        server_context_id: 1,
    };
    let server_material = ServerMaterial {
        boot_instance: [5; 16],
        current_cookie_key: [6; 32],
        previous_cookie_key: [7; 32],
        previous_key_rotated_ms: 0,
    };
    (
        ClientMachine::new(client_config, client_key).unwrap(),
        ServerMachine::new(server_config, server_key, server_material).unwrap(),
    )
}

fn established(profile: u8) -> (ClientMachine, ServerMachine, u64) {
    let (mut client, mut server) = machines(profile);
    let scid = 9;
    let binding = ObservedBinding::Native {
        ingress_descriptor_id: 1,
        next_hop_mac: [8; 6],
    };
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
    let verify = server.receive_open(&open, &binding, 0).unwrap();
    let auth = client.receive_verify(&verify, 0).unwrap();
    let ack = server
        .receive_open_auth(
            &auth,
            &binding,
            0,
            0,
            Some(ServerMaterial::handshake_material([11; 32], [12; 32])),
        )
        .unwrap();
    let accept = client.receive_ack(&ack, 0).unwrap();
    server.receive_accept(&accept, 0).unwrap();
    (client, server, scid)
}

fn header(slot: u8, scid: u64, source: [u8; 16], destination: [u8; 16]) -> Header {
    Header {
        profile: 3,
        tc: 0,
        next_header: NH_SES,
        hop_limit: 64,
        flags: if slot == 0 { 1 } else { 3 },
        path_slot: slot,
        scid,
        src: source,
        dst: destination,
    }
}

#[test]
fn bootstrap_transfers_slot0_without_safe_slot1_derivation() {
    let (mut client, mut server, scid) = established(3);
    let mut client_bootstrap = client.take_profile3_bootstrap().unwrap();
    let mut server_bootstrap = server.take_profile3_bootstrap(scid).unwrap();
    assert_eq!(
        client.send_data(b"disposed"),
        Err(SessionError::UnexpectedMessage)
    );
    assert!(!server.is_live(scid));

    let c0 = header(
        0,
        scid,
        *client_bootstrap.local_loc(),
        *client_bootstrap.peer_loc(),
    );
    let _s0 = header(
        0,
        scid,
        *server_bootstrap.local_loc(),
        *server_bootstrap.peer_loc(),
    );
    let mut client_slot0 = client_bootstrap.take_slot0().unwrap();
    let mut server_slot0 = server_bootstrap.take_slot0().unwrap();
    assert!(matches!(
        client_bootstrap.take_slot0(),
        Err(SessionError::UnexpectedMessage)
    ));
    let packet = client_slot0
        .encrypt_profile3_data(&c0, NonZeroU64::new(1).unwrap(), b"slot0", 1280)
        .unwrap();
    assert_eq!(u64::from_be_bytes(packet[52..60].try_into().unwrap()), 2);
    assert_eq!(
        server_slot0.decrypt_profile3_data(&packet).unwrap().1,
        b"slot0"
    );
}

#[test]
fn non_profile3_transfer_is_rejected_without_disposal() {
    for profile in 0..=2 {
        let (mut client, mut server, scid) = established(profile);
        assert!(matches!(
            client.take_profile3_bootstrap(),
            Err(SessionError::Profile)
        ));
        assert!(matches!(
            server.take_profile3_bootstrap(scid),
            Err(SessionError::Profile)
        ));
        assert!(server.is_live(scid));
    }
}

#[test]
fn bootstrap_debug_is_redacted_and_close_is_final() {
    let (mut client, mut server, scid) = established(3);
    let mut client_bootstrap = client.take_profile3_bootstrap().unwrap();
    let mut server_bootstrap = server.take_profile3_bootstrap(scid).unwrap();
    let debug = format!("{client_bootstrap:?}");
    assert!(debug.contains("slot0_active: true"));
    assert!(debug.contains("slot1_available: true"));
    assert!(!debug.contains("scid"));
    assert!(!debug.contains("local_loc"));
    assert!(!debug.contains("peer_loc"));
    assert!(!debug.contains("transcript"));
    assert!(!debug.contains("9"));
    assert!(!debug.contains("[3, 3"));
    assert_eq!(client_bootstrap.close(), Ok(()));
    assert_eq!(
        client_bootstrap.close(),
        Err(SessionError::UnexpectedMessage)
    );
    assert_eq!(server_bootstrap.close(), Ok(()));
}
