use ed25519_dalek::SigningKey;
use r8_session::*;
use serde_json::Value;

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
    let binding = UdpBinding::parse(hex(field(context, "udp_binding_ipv4_hex"))).unwrap();
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
        array(field(identities, "client_x25519_secret_hex")),
        array(field(identities, "server_ephemeral_hex")),
    )
    .unwrap();
    assert_eq!(shared, array(field(identities, "shared_secret_hex")));
    assert_eq!(
        hkdf_prk(shared, hash),
        array(field(&vectors["key_schedule"], "hkdf_prk_hex"))
    );
    assert_eq!(
        derive_key(shared, hash, 0, 1, 2, 0).unwrap(),
        array(field(&vectors["key_schedule"], "c2s_slot0_key_hex"))
    );
    assert_eq!(
        derive_key(shared, hash, 0, 2, 1, 0).unwrap(),
        array(field(&vectors["key_schedule"], "s2c_slot0_key_hex"))
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
    assert_eq!(x25519([1; 32], [0; 32]), Err(SessionError::AuthFailed));
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
fn deterministic_client_server_cookie_handshake_reaches_authenticated_accept() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let identities = &vectors["identities"];
    let context = &vectors["context"];
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
        local: server_identity,
        peer: client_identity,
        profile: 0,
        source,
        destination,
        budget: 1280,
        pending_limit: 256,
        established_limit: 1024,
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
    let binding = UdpBinding::parse(hex(field(context, "udp_binding_ipv4_hex"))).unwrap();
    let open = client
        .start(
            context["scid"].as_u64().unwrap(),
            ClientMaterial {
                ephemeral_secret: array(field(identities, "client_x25519_secret_hex")),
                nonce: array(field(context, "client_nonce_hex")),
            },
            0,
        )
        .unwrap();
    let verify = server
        .receive_open(&open, &binding, context["cookie_bucket"].as_u64().unwrap())
        .unwrap();
    let auth = client.receive_verify(&verify, 0).unwrap();
    let ack = server
        .receive_open_auth(
            &auth,
            &binding,
            0,
            context["cookie_bucket"].as_u64().unwrap(),
            Some(ServerHandshakeMaterial {
                ephemeral_secret: array(field(identities, "server_x25519_secret_hex")),
                nonce: array(field(context, "server_nonce_hex")),
            }),
        )
        .unwrap();
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
    let accept = client.receive_ack(&ack, 0).unwrap();
    assert_eq!(
        accept,
        hex(field(
            &vectors["positive_cases"][4]["protected"],
            "packet_hex"
        ))
    );
    server.receive_accept(&accept, 0).unwrap();
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
        server.preview_data_with_locs(&tampered, &[], &[]),
        Err(SessionError::AuthFailed)
    ));
    let preview = server.preview_data_with_locs(&data, &[], &[]).unwrap();
    assert_eq!(preview.plaintext(), b"synthetic session data");
    let stale = server.preview_data_with_locs(&data, &[], &[]).unwrap();
    assert_eq!(
        server.commit_data(preview, 1).unwrap(),
        b"synthetic session data"
    );
    assert_eq!(server.commit_data(stale, 2), Err(SessionError::Replay));
    assert_eq!(server.receive_data(&data, 3), Err(SessionError::Replay));

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
        server.preview_data_with_locs(&alternate, &[], &[]),
        Err(SessionError::AuthFailed)
    ));
    let preview = server
        .preview_data_with_locs(&alternate, &[alternate_source], &[alternate_destination])
        .unwrap();
    assert_eq!(
        server.commit_data(preview, 4).unwrap(),
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
    let close = server.close(context["scid"].as_u64().unwrap(), 7).unwrap();
    assert_eq!(client.receive_close(&close).unwrap(), 7);
    assert_eq!(
        client.receive_data(&response),
        Err(SessionError::UnexpectedMessage)
    );
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
    client.expire(5_010);
    assert_eq!(client.retry(5_010), Err(SessionError::UnexpectedMessage));
}
