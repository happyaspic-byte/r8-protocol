use core::num::NonZeroU64;

use r8_proto::Header;
use r8_session::{derive_key, DirectionalSession, SessionError, PROFILE3_DATA_PACKET_OVERHEAD};
use serde_json::Value;
use zeroize::Zeroizing;

const VECTORS: &str = include_str!("../../../../tests/vectors/redundant-v0.1.json");

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn array<const N: usize>(text: &str) -> [u8; N] {
    hex(text).try_into().unwrap()
}

fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().unwrap()
}
fn session(send_key: Zeroizing<[u8; 32]>, receive_key: Zeroizing<[u8; 32]>) -> DirectionalSession {
    DirectionalSession::new(send_key, receive_key, [0; 32], 1280)
}

fn key(vectors: &Value, direction: &str, slot: u8) -> Zeroizing<[u8; 32]> {
    let crypto = &vectors["cryptography"];
    let (sender, receiver, name) = match (direction, slot) {
        ("c2s", 0) => (1, 2, "c2s_slot0_key_hex"),
        ("c2s", 1) => (1, 2, "c2s_slot1_key_hex"),
        ("s2c", 0) => (2, 1, "s2c_slot0_key_hex"),
        ("s2c", 1) => (2, 1, "s2c_slot1_key_hex"),
        _ => panic!("invalid direction or slot"),
    };
    let shared = Zeroizing::new(array(field(crypto, "shared_secret_hex")));
    let actual = derive_key(
        &shared,
        array(field(crypto, "transcript_hash_hex")),
        3,
        sender,
        receiver,
        slot,
    )
    .unwrap();
    assert_eq!(&*actual, &array(field(&crypto["keys"], name)));
    actual
}

#[test]
fn frozen_profile3_packets_are_cross_language_byte_identical() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert!(vectors["synthetic_only"].as_bool().unwrap());
    assert_eq!(vectors["common"]["profile3_overhead"].as_u64(), Some(84));
    let keys = [
        key(&vectors, "c2s", 0),
        key(&vectors, "c2s", 1),
        key(&vectors, "s2c", 0),
        key(&vectors, "s2c", 1),
    ];
    assert_ne!(keys[0], keys[1]);
    assert_ne!(keys[0], keys[2]);

    let mut senders = [
        DirectionalSession::new(keys[0].clone(), keys[2].clone(), [0; 32], 1280),
        DirectionalSession::new(keys[1].clone(), keys[3].clone(), [0; 32], 1280),
    ];
    for case in vectors["positive_cases"].as_array().unwrap() {
        assert_eq!(field(case, "direction"), "c2s");
        let slot = case["slot"].as_u64().unwrap() as usize;
        let expected = hex(field(case, "full_packet_hex"));
        let plaintext = hex(field(case, "plaintext_hex"));
        let (header, _) = Header::unpack(&expected).unwrap();
        assert_eq!(header.profile, 3);
        assert_eq!(header.path_slot as usize, slot);
        assert_eq!(header.flags, if slot == 0 { 1 } else { 3 });
        assert_eq!(
            expected.len(),
            PROFILE3_DATA_PACKET_OVERHEAD + plaintext.len()
        );
        assert_eq!(
            expected.len(),
            case["exact_size"].as_u64().unwrap() as usize
        );
        assert_eq!(&expected[..48], hex(field(case, "header_hex")).as_slice());
        assert_eq!(&expected[48..52], hex(field(case, "prefix_hex")).as_slice());
        assert_eq!(
            u64::from_be_bytes(expected[52..60].try_into().unwrap()),
            case["counter"].as_u64().unwrap()
        );
        assert_eq!(
            u64::from_be_bytes(expected[60..68].try_into().unwrap()),
            case["delivery_id"].as_u64().unwrap()
        );
        let delivery = NonZeroU64::new(case["delivery_id"].as_u64().unwrap()).unwrap();
        let packet = senders[slot]
            .encrypt_profile3_data(
                &header,
                delivery,
                &plaintext,
                case["binding_budget"].as_u64().unwrap() as usize,
            )
            .unwrap();
        assert_eq!(packet, expected, "{}", field(case, "id"));
        let mut receiver = DirectionalSession::new(
            keys[2 + slot].clone(),
            keys[slot].clone(),
            [0; 32],
            case["binding_budget"].as_u64().unwrap() as usize,
        );
        let preview = receiver.preview_profile3_data(&packet).unwrap();
        assert_eq!(preview.delivery_id(), delivery);
        assert_eq!(preview.plaintext(), plaintext);
        assert_eq!(
            receiver.commit_profile3_data(preview).unwrap(),
            (delivery, plaintext)
        );
    }
}

#[test]
fn concrete_packet_mutations_return_exposed_session_categories() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let base = vectors["positive_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| field(case, "id") == "p3-data-slot0")
        .unwrap();
    let packet = hex(field(base, "full_packet_hex"));
    let key0 = key(&vectors, "c2s", 0);
    let key1 = key(&vectors, "c2s", 1);
    for cut in [47, 50, 55, 63, packet.len() - 1] {
        let receiver = session(key1.clone(), key0.clone());
        assert!(matches!(
            receiver.preview_profile3_data(&packet[..cut]),
            Err(SessionError::AuthFailed)
        ));
    }
    let mut profile = packet.clone();
    profile[4] = 2;
    profile[50] = 2;
    let mut flags = packet.clone();
    flags[6] = 0;
    let mut slot = packet.clone();
    slot[7] = 1;
    let mut header = packet.clone();
    header[15] ^= 1;
    let mut counter = packet.clone();
    counter[52..60].fill(0);
    let mut delivery_zero = packet.clone();
    delivery_zero[60..68].fill(0);
    let mut delivery_max = packet.clone();
    delivery_max[60..68].copy_from_slice(&[u8::MAX; 8]);
    let mut counter_max = packet.clone();
    counter_max[52..60].copy_from_slice(&[u8::MAX; 8]);
    assert_eq!(&counter[52..60], &[0; 8]);
    assert_eq!(&counter_max[52..60], &[u8::MAX; 8]);
    for hostile in [profile, flags, slot, header] {
        let receiver = session(key1.clone(), key0.clone());
        assert!(matches!(
            receiver.preview_profile3_data(&hostile),
            Err(SessionError::AuthFailed)
        ));
    }
    let receiver = session(key1.clone(), key0.clone());
    let error = match receiver.preview_profile3_data(&counter) {
        Err(error) => error,
        Ok(_) => panic!("accepted hostile counter"),
    };
    assert_eq!(error, SessionError::CounterRange);
    let receiver = session(key1.clone(), key0.clone());
    assert!(matches!(
        receiver.preview_profile3_data(&delivery_zero),
        Err(SessionError::AuthFailed)
    ));
    let receiver = session(key1.clone(), key0.clone());
    assert!(matches!(
        receiver.preview_profile3_data(&delivery_max),
        Err(SessionError::CounterRange)
    ));
    let receiver = session(key1.clone(), key0.clone());
    let error = match receiver.preview_profile3_data(&counter_max) {
        Err(error) => error,
        Ok(_) => panic!("accepted hostile counter"),
    };
    assert_eq!(error, SessionError::CounterRange);
    let wrong_key = session(key0.clone(), key1.clone());
    assert!(matches!(
        wrong_key.preview_profile3_data(&packet),
        Err(SessionError::AuthFailed)
    ));
    let mut receiver = session(key1.clone(), key0.clone());
    let preview = receiver.preview_profile3_data(&packet).unwrap();
    receiver.commit_profile3_data(preview).unwrap();
    assert!(matches!(
        receiver.preview_profile3_data(&packet),
        Err(SessionError::Replay)
    ));
    let mut hop = packet.clone();
    hop[5] -= 1;
    let mut forwarded = session(key1.clone(), key0.clone());
    assert_eq!(
        forwarded.decrypt_profile3_data(&hop).unwrap().1,
        hex(field(base, "plaintext_hex"))
    );
    let boundary = vectors["positive_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| field(case, "id") == "p3-boundary-slot0")
        .unwrap();
    let boundary_packet = hex(field(boundary, "full_packet_hex"));
    let (boundary_header, _) = Header::unpack(&boundary_packet).unwrap();
    let mut sender = session(key0, key1);
    assert_eq!(
        sender.encrypt_profile3_data(
            &boundary_header,
            NonZeroU64::new(boundary["delivery_id"].as_u64().unwrap()).unwrap(),
            &hex(field(boundary, "plaintext_hex")),
            1279
        ),
        Err(SessionError::Budget)
    );
}

#[test]
fn state_only_cases_are_present_once_with_one_category() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let state = [
        "first-anchor",
        "lower-reorder",
        "equal-suppression",
        "divergence-close",
        "replay-window-4096",
        "replay-window-4097",
        "dedup-capacity-4096",
        "dedup-capacity-4097",
        "gap-65536",
        "gap-65537",
        "queue-256",
        "queue-257",
        "dedup-expiry",
        "slot-remove",
        "slot-nonreuse",
        "restart-required",
        "events-degraded-recovered",
    ];
    let negatives = vectors["negative_cases"].as_array().unwrap();
    for id in state {
        assert_eq!(
            negatives
                .iter()
                .filter(|case| field(case, "id") == id)
                .count(),
            1,
            "{id}"
        );
        assert!(!negatives
            .iter()
            .find(|case| field(case, "id") == id)
            .unwrap()["expected_error"]
            .as_str()
            .unwrap()
            .is_empty());
    }
    assert!(!vectors["state_traces"].as_array().unwrap().is_empty());
}
