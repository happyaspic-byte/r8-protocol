use core::num::NonZeroU64;
use r8_proto::{Header, NH_SES};
use r8_session::{
    ClientMaterial, DirectionalSession, ObservedBinding, SecretMaterial, ServerHandshakeMaterial,
    ServerMaterial, SessionError, PROFILE3_DATA_PACKET_OVERHEAD, SESSION_DATA,
};
use zeroize::Zeroizing;

fn make_header(slot: u8) -> Header {
    Header {
        profile: 3,
        tc: 0,
        next_header: NH_SES,
        hop_limit: 64,
        flags: if slot == 0 { 1 } else { 3 },
        path_slot: slot,
        scid: 7,
        src: [1; 16],
        dst: [2; 16],
    }
}

fn sessions_with_receive_budget(
    slot: u8,
    receive_budget: usize,
) -> (DirectionalSession, DirectionalSession, Header) {
    let send_key = [slot + 1; 32];
    let receive_key = [slot + 17; 32];
    (
        DirectionalSession::new(
            Zeroizing::new(send_key),
            Zeroizing::new(receive_key),
            [0; 32],
            1280,
        ),
        DirectionalSession::new(
            Zeroizing::new(receive_key),
            Zeroizing::new(send_key),
            [0; 32],
            receive_budget,
        ),
        make_header(slot),
    )
}

fn sessions(slot: u8) -> (DirectionalSession, DirectionalSession, Header) {
    sessions_with_receive_budget(slot, 1280)
}

#[test]
fn profile3_data_both_slots_use_distinct_ciphers_and_commit_ids() {
    let id = NonZeroU64::new(9).unwrap();
    let (mut send0, mut receive0, header0) = sessions(0);
    let (mut send1, mut receive1, header1) = sessions(1);
    let packet0 = send0
        .encrypt_profile3_data(&header0, id, b"same delivery", 1280)
        .unwrap();
    let packet1 = send1
        .encrypt_profile3_data(&header1, id, b"same delivery", 1280)
        .unwrap();

    assert_ne!(packet0, packet1);
    assert_eq!(packet0[6..8], [1, 0]);
    assert_eq!(packet1[6..8], [3, 1]);
    let preview0 = receive0.preview_profile3_data(&packet0).unwrap();
    assert_eq!(preview0.delivery_id(), id);
    assert_eq!(preview0.plaintext(), b"same delivery");
    assert_eq!(
        receive0.commit_profile3_data(preview0).unwrap(),
        (id, b"same delivery".to_vec())
    );
    assert_eq!(
        receive1.decrypt_profile3_data(&packet1).unwrap(),
        (id, b"same delivery".to_vec())
    );
}

#[test]
fn profile3_data_budget_preflight_does_not_reserve_a_counter() {
    let id = NonZeroU64::new(1).unwrap();
    let (mut sender, mut receiver, header) = sessions(0);
    assert!(sender.can_reserve());
    assert_eq!(
        sender.encrypt_profile3_data(&header, id, b"", PROFILE3_DATA_PACKET_OVERHEAD - 1),
        Err(SessionError::Budget)
    );
    assert!(sender.can_reserve());
    let packet = sender
        .encrypt_profile3_data(&header, id, b"", PROFILE3_DATA_PACKET_OVERHEAD)
        .unwrap();
    assert_eq!(packet.len(), PROFILE3_DATA_PACKET_OVERHEAD);
    assert_eq!(u64::from_be_bytes(packet[52..60].try_into().unwrap()), 1);
    assert!(sender.can_reserve());
    assert_eq!(
        receiver.decrypt_profile3_data(&packet).unwrap(),
        (id, Vec::new())
    );
}

#[test]
fn profile3_data_authenticates_id_header_and_tag_but_not_wire_hop() {
    let id = NonZeroU64::new(22).unwrap();
    let (mut sender, mut receiver, header) = sessions(1);
    let packet = sender
        .encrypt_profile3_data(&header, id, b"payload", 1280)
        .unwrap();

    let mut forwarded = packet.clone();
    forwarded[5] = 1;
    assert_eq!(
        receiver.decrypt_profile3_data(&forwarded).unwrap(),
        (id, b"payload".to_vec())
    );

    let (_, header_receiver, _) = sessions(1);
    let mut changed_id = packet.clone();
    changed_id[60] ^= 1;
    assert!(matches!(
        header_receiver.preview_profile3_data(&changed_id),
        Err(SessionError::AuthFailed)
    ));

    let (_, tag_receiver, _) = sessions(1);
    let mut changed_tag = packet.clone();
    *changed_tag.last_mut().unwrap() ^= 1;
    assert!(matches!(
        tag_receiver.preview_profile3_data(&changed_tag),
        Err(SessionError::AuthFailed)
    ));

    let (_, source_receiver, _) = sessions(1);
    let mut changed_header = packet;
    changed_header[16] ^= 1;
    assert!(matches!(
        source_receiver.preview_profile3_data(&changed_header),
        Err(SessionError::AuthFailed)
    ));
}

#[test]
fn profile3_data_replay_and_invalid_slot_are_rejected_without_delivery() {
    let id = NonZeroU64::new(3).unwrap();
    let (mut sender, mut receiver, header) = sessions(0);
    let packet = sender
        .encrypt_profile3_data(&header, id, b"payload", 1280)
        .unwrap();
    assert_eq!(
        receiver.decrypt_profile3_data(&packet).unwrap(),
        (id, b"payload".to_vec())
    );
    assert_eq!(
        receiver.decrypt_profile3_data(&packet),
        Err(SessionError::Replay)
    );

    let mut invalid = make_header(0);
    invalid.path_slot = 2;
    assert_eq!(
        sender.encrypt_profile3_data(&invalid, id, b"payload", 1280),
        Err(SessionError::AuthFailed)
    );
}
#[test]
fn profile3_preview_is_receiver_budget_bound_and_session_owned() {
    let id = NonZeroU64::new(4).unwrap();
    let (mut sender, mut receiver, header) =
        sessions_with_receive_budget(0, PROFILE3_DATA_PACKET_OVERHEAD);
    let oversized = sender
        .encrypt_profile3_data(&header, id, b"payload", 1280)
        .unwrap();
    assert!(matches!(
        receiver.preview_profile3_data(&oversized),
        Err(SessionError::Budget)
    ));

    let accepted = sender
        .encrypt_profile3_data(&header, id, b"", PROFILE3_DATA_PACKET_OVERHEAD)
        .unwrap();
    assert_eq!(
        receiver.decrypt_profile3_data(&accepted).unwrap(),
        (id, Vec::new())
    );

    let (mut generic_sender, mut generic_receiver, generic_header) = sessions(0);
    let generic_packet = generic_sender
        .encrypt(&generic_header, SESSION_DATA, b"payload", 1280)
        .unwrap();
    let preview = generic_receiver.preview(&generic_packet).unwrap();
    let (_, mut other_receiver, _) = sessions(0);
    assert_eq!(other_receiver.commit(preview), Err(SessionError::Replay));
    assert_eq!(
        generic_receiver.decrypt(&generic_packet).unwrap(),
        b"payload".to_vec()
    );
}

#[test]
fn sensitive_material_and_binding_debug_is_finite_and_redacted() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    assert_zeroize_on_drop::<SecretMaterial>();
    assert_zeroize_on_drop::<ClientMaterial>();
    assert_zeroize_on_drop::<ServerHandshakeMaterial>();
    assert_zeroize_on_drop::<ServerMaterial>();

    let secret = SecretMaterial {
        key_id: 13,
        bytes: [6; 32],
    };
    let client = ClientMaterial {
        ephemeral_secret: [7; 32],
        nonce: [8; 32],
    };
    let server = ServerMaterial {
        boot_instance: [9; 16],
        current_cookie_key: [10; 32],
        previous_cookie_key: [11; 32],
        previous_key_rotated_ms: 12,
    };
    let binding = ObservedBinding::Native {
        ingress_descriptor_id: 0x0102_0304,
        next_hop_mac: [0xaa; 6],
    };
    let rendered = format!("{secret:?}{client:?}{server:?}{binding:?}");
    for marker in [
        "6, 6", "7, 7", "8, 8", "9, 9", "10, 10", "11, 11", "16909060", "170, 170",
    ] {
        assert!(!rendered.contains(marker));
    }
    assert!(rendered.len() < 256);
}
