use ed25519_dalek::SigningKey;
use r8_proto::Header;
use r8_session::*;
use serde_json::Value;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const VECTORS: &str = include_str!("../../../../tests/vectors/session-v0.1.json");

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

#[test]
fn all_six_canonical_messages_and_protected_payloads_decode() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    for case in vectors["positive_cases"].as_array().unwrap() {
        if let Some(payload) = case["payload_hex"].as_str() {
            let payload = hex(payload);
            assert!(
                SessionMessage::decode(&payload, payload[2], 1280).is_ok(),
                "{}",
                case["id"]
            );
        } else {
            let packet = hex(field(&case["protected"], "packet_hex"));
            assert!(
                SessionMessage::decode(&packet[48..], packet[50], 1280).is_ok(),
                "{}",
                case["id"]
            );
        }
    }
}

#[test]
fn corpus_crypto_is_byte_identical() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let identities = &vectors["identities"];
    let context = &vectors["context"];
    let transcript = &vectors["transcript"];
    let client = Identity::from_public_key(
        1,
        context["service_context"].as_u64().unwrap() as u32,
        array(field(identities, "client_public_key_hex")),
    )
    .unwrap();
    let server = Identity::from_public_key(
        2,
        context["service_context"].as_u64().unwrap() as u32,
        array(field(identities, "server_public_key_hex")),
    )
    .unwrap();
    assert_eq!(client.eid, array(field(identities, "client_eid_hex")));
    assert_eq!(server.eid, array(field(identities, "server_eid_hex")));
    let binding = ObservedBinding::Udp(
        UdpBinding::parse(hex(field(context, "udp_binding_ipv4_hex"))).unwrap(),
    );
    let cookie_input_bytes = cookie_input(&CookieContext {
        binding: &binding,
        client: &client,
        server: &server,
        scid: context["scid"].as_u64().unwrap(),
        client_ephemeral: array(field(identities, "client_ephemeral_hex")),
        boot: array(field(context, "server_boot_instance_hex")),
        bucket: context["cookie_bucket"].as_u64().unwrap(),
        server_context_id: context["server_context_id"].as_u64().unwrap() as u32,
    })
    .unwrap();
    assert_eq!(cookie_input_bytes, hex(field(context, "cookie_input_hex")));
    assert_eq!(
        cookie(
            &array(field(context, "cookie_key_hex")),
            &cookie_input_bytes
        ),
        array(field(context, "cookie_hmac_hex"))
    );
    let placeholder_server = Identity {
        role: 2,
        service_context: client.service_context,
        eid: server.eid,
        public_key: [0; 32],
    };
    let placeholder = transcript_t0(&TranscriptContext {
        profile: context["profile"].as_u64().unwrap() as u8,
        scid: context["scid"].as_u64().unwrap(),
        client: &client,
        server: &placeholder_server,
        client_ephemeral: array(field(identities, "client_ephemeral_hex")),
        server_ephemeral: [0; 32],
        client_nonce: array(field(context, "client_nonce_hex")),
        server_nonce: [0; 32],
        boot: array(field(context, "server_boot_instance_hex")),
    })
    .unwrap();
    assert_eq!(placeholder, hex(field(transcript, "placeholder_t0_hex")));
    let actual = transcript_t0(&TranscriptContext {
        profile: context["profile"].as_u64().unwrap() as u8,
        scid: context["scid"].as_u64().unwrap(),
        client: &client,
        server: &server,
        client_ephemeral: array(field(identities, "client_ephemeral_hex")),
        server_ephemeral: array(field(identities, "server_ephemeral_hex")),
        client_nonce: array(field(context, "client_nonce_hex")),
        server_nonce: array(field(context, "server_nonce_hex")),
        boot: array(field(context, "server_boot_instance_hex")),
    })
    .unwrap();
    assert_eq!(actual, hex(field(transcript, "actual_t0_hex")));
    let client_signature = sign_open_auth(
        &SigningKey::from_bytes(&array(field(identities, "client_ed25519_seed_hex"))),
        &placeholder,
    );
    let server_signature = sign_open_ack(
        &SigningKey::from_bytes(&array(field(identities, "server_ed25519_seed_hex"))),
        &actual,
    );
    assert_eq!(
        client_signature,
        array(field(transcript, "client_signature_hex"))
    );
    assert_eq!(
        server_signature,
        array(field(transcript, "server_signature_hex"))
    );
    let hash = transcript_hash(&actual, &client_signature, &server_signature);
    assert_eq!(hash, array(field(transcript, "transcript_hash_hex")));
    let shared = x25519(
        StaticSecret::from(array(field(identities, "client_x25519_secret_hex"))),
        PublicKey::from(array(field(identities, "server_ephemeral_hex"))),
    )
    .unwrap();
    assert_eq!(
        shared.as_bytes(),
        &array(field(identities, "shared_secret_hex"))
    );
    let shared_key = Zeroizing::new(array(field(identities, "shared_secret_hex")));
    assert_eq!(
        &*derive_key(&shared_key, hash, 0, 1, 2, 0).unwrap(),
        &array(field(&vectors["key_schedule"], "c2s_slot0_key_hex"))
    );
    assert_eq!(
        &*derive_key(&shared_key, hash, 0, 2, 1, 0).unwrap(),
        &array(field(&vectors["key_schedule"], "s2c_slot0_key_hex"))
    );
}

#[test]
fn finite_negative_fixture_categories_have_concrete_operations() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let supported = [
        "ROLE_MISMATCH",
        "SERVICE_MISMATCH",
        "PIN_MISMATCH",
        "EID_KEY_MISMATCH",
        "COOKIE_INVALID",
        "AUTH_FAILED",
        "COUNTER_RANGE",
        "COUNTER_EXHAUSTED",
        "REPLAY",
        "TRUNCATED",
        "TRAILING_BYTES",
        "SCID_COLLISION",
        "CAPACITY",
        "RESTART_REQUIRED",
        "UNEXPECTED_MESSAGE",
        "TIMEOUT",
        "BUDGET",
        "BINDING_INVALID",
        "CONFIG_ERROR",
        "RNG_FAILURE",
    ];
    for case in vectors["negative_cases"].as_array().unwrap() {
        assert!(
            supported.contains(&field(case, "expected_error")),
            "{}",
            case["id"]
        );
    }
    let mut replay = ReplayWindow::new();
    assert!(replay.mark_after_auth(1).is_ok());
    assert_eq!(replay.check(1), Err(SessionError::Replay));
    let snapshot = replay.clone();
    let preview = replay.preview(2).unwrap();
    assert_eq!(replay, snapshot);
    replay.commit(preview).unwrap();
    assert_eq!(replay.check(2), Err(SessionError::Replay));
    assert_eq!(nonce(0), Err(SessionError::CounterRange));
    assert!(matches!(
        x25519(StaticSecret::from([1; 32]), PublicKey::from([0; 32])),
        Err(SessionError::AuthFailed)
    ));
    assert_eq!(
        SessionMessage::decode(&[OPEN, 1, 0, 0], 0, 1280),
        Err(SessionError::Truncated)
    );
    assert_eq!(SessionError::Timeout.as_str(), "TIMEOUT");
    assert_eq!(SessionError::Budget.as_str(), "BUDGET");
    assert_eq!(SessionError::Binding.as_str(), "BINDING_INVALID");
    assert_eq!(SessionError::ConfigError.as_str(), "CONFIG_ERROR");
    assert_eq!(SessionError::RngFailure.as_str(), "RNG_FAILURE");
}
#[test]
fn current_aad_replay_counter_binding_and_secret_contracts() {
    let header = Header {
        profile: 0,
        tc: 0,
        next_header: r8_proto::NH_SES,
        hop_limit: 64,
        flags: 1,
        path_slot: 0,
        scid: 1,
        src: [1; 16],
        dst: [2; 16],
    };
    let mut sender = DirectionalSession::new(
        Zeroizing::new([7; 32]),
        Zeroizing::new([8; 32]),
        [9; 32],
        1280,
    );
    let mut receiver = DirectionalSession::new(
        Zeroizing::new([8; 32]),
        Zeroizing::new([7; 32]),
        [9; 32],
        1280,
    );
    let mut hop_changed = sender
        .encrypt(&header, SESSION_DATA, b"data", 1280)
        .unwrap();
    hop_changed[5] = 1;
    assert_eq!(receiver.decrypt(&hop_changed), Ok(b"data".to_vec()));
    let mut other_changed = sender
        .encrypt(&header, SESSION_DATA, b"data", 1280)
        .unwrap();
    other_changed[16] ^= 1;
    assert_eq!(
        receiver.decrypt(&other_changed),
        Err(SessionError::AuthFailed)
    );
    assert_eq!(nonce(u64::MAX), Err(SessionError::CounterRange));

    let mut replay = ReplayWindow::new();
    replay.mark_after_auth(1).unwrap();
    replay.mark_after_auth(4097).unwrap();
    assert!(replay.check(2).is_ok());
    assert_eq!(replay.check(1), Err(SessionError::Replay));
    let mut forward_replay = ReplayWindow::new();
    forward_replay.mark_after_auth(1).unwrap();
    assert!(forward_replay.check(65_537).is_ok());
    assert_eq!(forward_replay.check(65_538), Err(SessionError::Replay));
    assert_eq!(
        forward_replay.check(u64::MAX),
        Err(SessionError::CounterRange)
    );

    let udp = ObservedBinding::Udp(UdpBinding::ipv4([192, 0, 2, 1], 1234, 1, [0; 16]).unwrap());
    let native = ObservedBinding::Native {
        ingress_descriptor_id: 1,
        next_hop_mac: [1, 2, 3, 4, 5, 6],
    };
    assert_eq!(ObservedBinding::parse(&native.encode()), Ok(native.clone()));
    assert_eq!(
        ObservedBinding::parse(&[2, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6]),
        Err(SessionError::Binding)
    );
    let client = Identity::from_public_key(1, 1, [1; 32]).unwrap();
    let server = Identity::from_public_key(2, 1, [2; 32]).unwrap();
    let udp_context = CookieContext {
        binding: &udp,
        client: &client,
        server: &server,
        scid: 1,
        client_ephemeral: [3; 32],
        boot: [4; 16],
        bucket: 1,
        server_context_id: 1,
    };
    let native_context = CookieContext {
        binding: &native,
        ..udp_context
    };
    assert_ne!(
        cookie_input(&udp_context).unwrap(),
        cookie_input(&native_context).unwrap()
    );

    let debug = format!("{sender:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("7, 7"));
    drop(sender);
}
#[test]
fn deterministic_client_server_cookie_handshake_reaches_authenticated_accept() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let identities = &vectors["identities"];
    let context = &vectors["context"];
    let base = context["cookie_bucket"].as_u64().unwrap() * 10_000;
    let service_context = context["service_context"].as_u64().unwrap() as u32;
    let client_identity = Identity::from_public_key(
        1,
        service_context,
        array(field(identities, "client_public_key_hex")),
    )
    .unwrap();
    let server_identity = Identity::from_public_key(
        2,
        service_context,
        array(field(identities, "server_public_key_hex")),
    )
    .unwrap();
    let source = array("00112233445566778899aabbccddeeff");
    let destination = array("ffeeddccbbaa99887766554433221100");
    let client_config = HandshakeConfig {
        local: client_identity.clone(),
        peer: server_identity.clone(),
        profile: 0,
        source,
        destination,
        budget: 1280,
        pending_limit: 256,
        established_limit: 1024,
        server_context_id: context["server_context_id"].as_u64().unwrap() as u32,
    };
    let server_config = HandshakeConfig {
        local: server_identity.clone(),
        peer: client_identity.clone(),
        profile: 0,
        source,
        destination,
        budget: 1280,
        pending_limit: 256,
        established_limit: 1,
        server_context_id: context["server_context_id"].as_u64().unwrap() as u32,
    };
    let mut client = ClientMachine::new(
        client_config,
        SigningKey::from_bytes(&array(field(identities, "client_ed25519_seed_hex"))),
    )
    .unwrap();
    let mut server = ServerMachine::new(
        server_config,
        SigningKey::from_bytes(&array(field(identities, "server_ed25519_seed_hex"))),
        ServerMaterial {
            boot_instance: array(field(context, "server_boot_instance_hex")),
            current_cookie_key: array(field(context, "cookie_key_hex")),
            previous_cookie_key: [0; 32],
            previous_key_rotated_ms: 0,
        },
    )
    .unwrap();
    let binding = ObservedBinding::Udp(
        UdpBinding::parse(hex(field(context, "udp_binding_ipv4_hex"))).unwrap(),
    );
    let open = client
        .start(
            context["scid"].as_u64().unwrap(),
            ClientMaterial {
                ephemeral_secret: array(field(identities, "client_x25519_secret_hex")),
                nonce: array(field(context, "client_nonce_hex")),
            },
            base,
        )
        .unwrap();
    let verify = server
        .receive_open(&open, &binding, context["cookie_bucket"].as_u64().unwrap())
        .unwrap();
    let auth = client.receive_verify(&verify, base).unwrap();
    let ack = server
        .receive_open_auth(
            &auth,
            &binding,
            base,
            context["cookie_bucket"].as_u64().unwrap(),
            Some(ServerHandshakeMaterial {
                ephemeral_secret: array(field(identities, "server_x25519_secret_hex")),
                nonce: array(field(context, "server_nonce_hex")),
            }),
        )
        .unwrap();
    assert_eq!(
        server.receive_open_auth(&auth, &binding, base + 1, 0, None),
        Ok(ack.clone())
    );
    let mut competing_auth = auth.clone();
    *competing_auth.last_mut().unwrap() ^= 1;
    assert_eq!(
        server.receive_open_auth(&competing_auth, &binding, base + 1, 0, None),
        Err(SessionError::ScidCollision)
    );
    assert_eq!(
        &open[48..],
        hex(field(&vectors["positive_cases"][0], "payload_hex"))
    );
    assert_eq!(
        &verify[48..],
        hex(field(&vectors["positive_cases"][1], "payload_hex"))
    );
    assert_eq!(
        &auth[48..],
        hex(field(&vectors["positive_cases"][2], "payload_hex"))
    );
    assert_eq!(
        &ack[48..],
        hex(field(&vectors["positive_cases"][3], "payload_hex"))
    );
    let accept = client.receive_ack(&ack, base).unwrap();
    assert_eq!(
        accept,
        hex(field(
            &vectors["positive_cases"][4]["protected"],
            "packet_hex"
        ))
    );
    let hash: [u8; 32] = array(field(&vectors["transcript"], "transcript_hash_hex"));
    let shared_key = Zeroizing::new(array(field(identities, "shared_secret_hex")));
    let mut semantic_session = DirectionalSession::new(
        derive_key(&shared_key, hash, 0, 1, 2, 0).unwrap(),
        Zeroizing::new([0; 32]),
        hash,
        1280,
    );
    let mut invalid_plaintext = b"R8 ACCEPT v1".to_vec();
    invalid_plaintext.extend_from_slice(&[0; 32]);
    let semantic_accept = semantic_session
        .encrypt(
            &Header {
                profile: 0,
                tc: 0,
                next_header: r8_proto::NH_SES,
                hop_limit: 64,
                flags: 1,
                path_slot: 0,
                scid: context["scid"].as_u64().unwrap(),
                src: source,
                dst: destination,
            },
            SESSION_ACCEPT,
            &invalid_plaintext,
            1280,
        )
        .unwrap();
    assert_eq!(
        server.receive_accept(&semantic_accept, base),
        Err(SessionError::AuthFailed)
    );
    server.receive_accept(&accept, base).unwrap();
    assert_eq!(server.receive_accept(&accept, base + 1), Ok(()));
    assert_eq!(
        server.receive_open_auth(&auth, &binding, base + 1, 0, None),
        Ok(ack.clone())
    );
    assert_eq!(
        server.receive_open_auth(&competing_auth, &binding, base + 1, 0, None),
        Err(SessionError::ScidCollision)
    );
    let mut forged_accept = accept.clone();
    *forged_accept.last_mut().unwrap() ^= 1;
    assert_eq!(
        server.receive_accept(&forged_accept, base + 1),
        Err(SessionError::AuthFailed)
    );
    assert!(server.is_live(context["scid"].as_u64().unwrap()));
    server.rotate_cookie_key([9; 32], 600_000);
    assert!(server.is_live(context["scid"].as_u64().unwrap()));

    let data = client.send_data(b"synthetic session data").unwrap();
    assert_eq!(
        data,
        hex(field(
            &vectors["positive_cases"][5]["protected"],
            "packet_hex"
        ))
    );
    let mut tampered = data.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        server.preview_data_with_locs(&tampered, &[], &[], base + 1),
        Err(SessionError::AuthFailed)
    ));
    let preview = server
        .preview_data_with_locs(&data, &[], &[], base + 1)
        .unwrap();
    assert_eq!(preview.plaintext().unwrap(), b"synthetic session data");
    let stale = server
        .preview_data_with_locs(&data, &[], &[], base + 1)
        .unwrap();
    assert_eq!(
        server.commit_data(preview, base + 1).unwrap(),
        b"synthetic session data"
    );
    assert_eq!(
        server.commit_data(stale, base + 2),
        Err(SessionError::Replay)
    );
    assert_eq!(
        server.receive_data(&data, base + 3),
        Err(SessionError::Replay)
    );

    let alternate_source = [3; 16];
    let alternate_destination = [4; 16];
    let alternate = client
        .send_data_with_locs(
            b"alternate loc data",
            alternate_source,
            alternate_destination,
        )
        .unwrap();
    assert!(matches!(
        server.preview_data_with_locs(&alternate, &[], &[], base + 4),
        Err(SessionError::AuthFailed)
    ));
    let preview = server
        .preview_data_with_locs(
            &alternate,
            &[alternate_source],
            &[alternate_destination],
            base + 4,
        )
        .unwrap();
    assert_eq!(
        server.commit_data(preview, base + 4).unwrap(),
        b"alternate loc data"
    );
    client.promote_local_loc(alternate_source);
    client.promote_peer_loc(alternate_destination);
    server.promote_local_loc(alternate_destination);
    server.promote_peer_loc(alternate_source);
    assert_eq!(client.effective_local_loc(), alternate_source);
    assert_eq!(server.effective_peer_loc(), alternate_source);

    let response = server
        .send_data(context["scid"].as_u64().unwrap(), b"ok")
        .unwrap();
    assert_eq!(client.receive_data(&response).unwrap(), b"ok");
    let second_config = HandshakeConfig {
        local: client_identity,
        peer: server_identity,
        profile: 0,
        source,
        destination,
        budget: 1280,
        pending_limit: 256,
        established_limit: 1,
        server_context_id: context["server_context_id"].as_u64().unwrap() as u32,
    };
    let mut second_client = ClientMachine::new(
        second_config,
        SigningKey::from_bytes(&array(field(identities, "client_ed25519_seed_hex"))),
    )
    .unwrap();
    let second_open = second_client
        .start(
            context["scid"].as_u64().unwrap() + 1,
            ClientMaterial {
                ephemeral_secret: [7; 32],
                nonce: [8; 32],
            },
            base,
        )
        .unwrap();
    let second_verify = server
        .receive_open(
            &second_open,
            &binding,
            context["cookie_bucket"].as_u64().unwrap(),
        )
        .unwrap();
    let second_auth = second_client.receive_verify(&second_verify, base).unwrap();
    let second_ack = server
        .receive_open_auth(
            &second_auth,
            &binding,
            base + 1,
            context["cookie_bucket"].as_u64().unwrap(),
            Some(ServerHandshakeMaterial {
                ephemeral_secret: [9; 32],
                nonce: [10; 32],
            }),
        )
        .unwrap();
    let second_accept = second_client.receive_ack(&second_ack, base).unwrap();
    assert_eq!(
        server.receive_accept(&second_accept, base),
        Err(SessionError::Capacity)
    );
    let close = server.close(context["scid"].as_u64().unwrap(), 7).unwrap();
    assert_eq!(client.receive_close(&close).unwrap(), 7);
    assert_eq!(server.receive_accept(&second_accept, base), Ok(()));
    second_client.promote_local_loc(alternate_source);
    second_client.promote_peer_loc(alternate_destination);
    let late_data = second_client.send_data(b"late").unwrap();
    assert!(server
        .preview_data_with_locs(&late_data, &[], &[], base + 119_999)
        .is_ok());
    let late_close = second_client.close(8).unwrap();
    assert_eq!(
        server.receive_close(&late_close, base + 120_000),
        Err(SessionError::UnexpectedMessage)
    );
    assert!(matches!(
        server.preview_data_with_locs(&late_data, &[], &[], base + 120_000),
        Err(SessionError::UnexpectedMessage)
    ));
    assert_eq!(
        server.receive_data(&late_data, base + 120_000),
        Err(SessionError::UnexpectedMessage)
    );
    assert!(!server.is_live(context["scid"].as_u64().unwrap() + 1));
    assert_eq!(
        client.receive_data(&response),
        Err(SessionError::UnexpectedMessage)
    );
}

#[test]
fn owned_secret_buffers_zeroize_and_redact_debug() {
    use zeroize::Zeroize;
    let mut secret = SecretMaterial {
        key_id: 7,
        bytes: [0x5a; 32],
    };
    assert_eq!(format!("{secret:?}"), "<SecretMaterial>");
    secret.zeroize();
    assert_eq!(secret.bytes, [0; 32]);

    let mut client = ClientMaterial {
        ephemeral_secret: [0x11; 32],
        nonce: [0x22; 32],
    };
    assert_eq!(format!("{client:?}"), "<ClientMaterial>");
    client.zeroize();
    assert_eq!(client.ephemeral_secret, [0; 32]);
    assert_eq!(client.nonce, [0; 32]);

    let mut server = ServerMaterial {
        boot_instance: [0x33; 16],
        current_cookie_key: [0x44; 32],
        previous_cookie_key: [0x55; 32],
        previous_key_rotated_ms: 9,
    };
    assert_eq!(format!("{server:?}"), "<ServerMaterial>");
    server.zeroize();
    assert_eq!(server.current_cookie_key, [0; 32]);
    assert_eq!(server.previous_cookie_key, [0; 32]);
}

#[test]
fn prevalidation_limiter_enforces_ratio_and_source_bounds() {
    let mut limiter = PrevalidationLimiter::new();
    assert!(limiter.admit([1; 32], 64, 64, 0).is_ok());
    assert_eq!(limiter.admit([1; 32], 1, 2, 0), Err(SessionError::Capacity));
    for source in 2u16..=4096 {
        let mut key = [0u8; 32];
        key[..2].copy_from_slice(&source.to_be_bytes());
        assert!(limiter.admit(key, 1, 1, u64::from(source) * 1000).is_ok());
    }
    assert!(limiter.admit([9; 32], 1, 1, 4_097_000).is_ok());
}
#[test]
fn typed_udp_binding_rejects_noncanonical_forms() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let binding = hex(field(&vectors["context"], "udp_binding_ipv4_hex"));
    assert_eq!(
        UdpBinding::parse(binding.clone()).unwrap().as_bytes(),
        binding
    );
    assert_eq!(UdpBinding::parse(vec![1, 4]), Err(SessionError::Binding));
    assert!(UdpBinding::ipv4([192, 0, 2, 10], 0, 1, [0; 16]).is_err());
    assert!(UdpBinding::ipv6([0; 16], 9, 2, [1; 16]).is_ok());
}
#[test]
fn client_handshake_deadline_is_exact_and_retries_do_not_extend_it() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let identities = &vectors["identities"];
    let service = vectors["context"]["service_context"].as_u64().unwrap() as u32;
    let local = Identity::from_public_key(
        1,
        service,
        array(field(identities, "client_public_key_hex")),
    )
    .unwrap();
    let peer = Identity::from_public_key(
        2,
        service,
        array(field(identities, "server_public_key_hex")),
    )
    .unwrap();
    let config = HandshakeConfig {
        local,
        peer,
        profile: 0,
        source: [1; 16],
        destination: [2; 16],
        budget: 1280,
        pending_limit: 256,
        established_limit: 1024,
        server_context_id: 1,
    };
    let mut client = ClientMachine::new(
        config,
        SigningKey::from_bytes(&array(field(identities, "client_ed25519_seed_hex"))),
    )
    .unwrap();
    client
        .start(
            1,
            ClientMaterial {
                ephemeral_secret: [3; 32],
                nonce: [4; 32],
            },
            10,
        )
        .unwrap();
    assert!(client.retry(5_009).is_ok());
    client.expire(5_009);
    assert!(client.retry(5_009).is_ok());
    assert_eq!(
        client.receive_verify(&[], 5_010),
        Err(SessionError::UnexpectedMessage)
    );
    assert_eq!(client.retry(5_010), Err(SessionError::UnexpectedMessage));
}
#[test]
fn open_auth_budget_failure_releases_cookie_wait() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let identities = &vectors["identities"];
    let context = &vectors["context"];
    let service = context["service_context"].as_u64().unwrap() as u32;
    let client_identity = Identity::from_public_key(
        1,
        service,
        array(field(identities, "client_public_key_hex")),
    )
    .unwrap();
    let server_identity = Identity::from_public_key(
        2,
        service,
        array(field(identities, "server_public_key_hex")),
    )
    .unwrap();
    let client_config = HandshakeConfig {
        local: client_identity.clone(),
        peer: server_identity.clone(),
        profile: 0,
        source: [1; 16],
        destination: [2; 16],
        budget: 170,
        pending_limit: 1,
        established_limit: 1,
        server_context_id: 1,
    };
    let server_config = HandshakeConfig {
        local: server_identity,
        peer: client_identity,
        profile: 0,
        source: [1; 16],
        destination: [2; 16],
        budget: 1280,
        pending_limit: 1,
        established_limit: 1,
        server_context_id: 1,
    };
    let mut client = ClientMachine::new(
        client_config,
        SigningKey::from_bytes(&array(field(identities, "client_ed25519_seed_hex"))),
    )
    .unwrap();
    let server = ServerMachine::new(
        server_config,
        SigningKey::from_bytes(&array(field(identities, "server_ed25519_seed_hex"))),
        ServerMaterial {
            boot_instance: array(field(context, "server_boot_instance_hex")),
            current_cookie_key: array(field(context, "cookie_key_hex")),
            previous_cookie_key: [0; 32],
            previous_key_rotated_ms: 0,
        },
    )
    .unwrap();
    let binding = ObservedBinding::Udp(
        UdpBinding::parse(hex(field(context, "udp_binding_ipv4_hex"))).unwrap(),
    );
    let open = client
        .start(
            1,
            ClientMaterial {
                ephemeral_secret: array(field(identities, "client_x25519_secret_hex")),
                nonce: array(field(context, "client_nonce_hex")),
            },
            0,
        )
        .unwrap();
    let verify = server.receive_open(&open, &binding, 0).unwrap();
    assert_eq!(client.receive_verify(&verify, 0), Err(SessionError::Budget));
    assert_eq!(client.retry(0), Err(SessionError::UnexpectedMessage));
}
#[test]
fn handshake_config_and_previous_cookie_key_boundaries_are_strict() {
    let local = Identity::from_public_key(1, 1, [1; 32]).unwrap();
    let peer = Identity::from_public_key(2, 1, [2; 32]).unwrap();
    for budget in [47, 1281] {
        assert_eq!(
            HandshakeConfig {
                local: local.clone(),
                peer: peer.clone(),
                profile: 0,
                source: [1; 16],
                destination: [2; 16],
                budget,
                pending_limit: 1,
                established_limit: 1,
                server_context_id: 1,
            }
            .validate(),
            Err(SessionError::ConfigError)
        );
    }
    assert!(HandshakeConfig {
        local: local.clone(),
        peer: peer.clone(),
        profile: 0,
        source: [1; 16],
        destination: [2; 16],
        budget: 48,
        pending_limit: 1,
        established_limit: 1,
        server_context_id: 1,
    }
    .validate()
    .is_ok());
    let binding = ObservedBinding::Udp(UdpBinding::ipv4([192, 0, 2, 1], 1234, 1, [0; 16]).unwrap());
    let context = CookieContext {
        binding: &binding,
        client: &local,
        server: &peer,
        scid: 1,
        client_ephemeral: [3; 32],
        boot: [4; 16],
        bucket: 2,
        server_context_id: 1,
    };
    let previous = [5; 32];
    let input = cookie_input(&context).unwrap();
    let supplied = cookie(&previous, &input);
    assert!(cookie_matches_buckets(&[6; 32], &previous, 0, &supplied, context, 20_000).unwrap());
    assert!(!cookie_matches_buckets(&[6; 32], &previous, 0, &supplied, context, 20_001).unwrap());
}
