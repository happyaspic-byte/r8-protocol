use std::panic::{catch_unwind, AssertUnwindSafe};

use r8_proto::{
    build_ctl_with_budget, build_dgram_with_budget, Header, WireError, NH_CTL, NH_DGRAM,
    SERIALIZED_R8_MAX,
};
use serde_json::Value;

const VECTORS: &str = include_str!("../../../../tests/vectors/wire-v0.2.json");

fn bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn category(name: &str) -> WireError {
    match name {
        "TRUNCATED" => WireError::Truncated,
        "TRAILING_BYTES" => WireError::TrailingBytes,
        "PACKET_CAP" => WireError::PacketCap,
        "BINDING_BUDGET" => WireError::BindingBudget,
        "LENGTH_OVERFLOW" => WireError::LengthOverflow,
        "VERSION" => WireError::Version,
        "PROFILE" => WireError::Profile,
        "TRAFFIC_CLASS" => WireError::TrafficClass,
        "NEXT_HEADER" => WireError::NextHeader,
        "HOP_LIMIT" => WireError::HopLimit,
        "FLAGS" => WireError::Flags,
        "PATH_SLOT" => WireError::PathSlot,
        "SCID" => WireError::Scid,
        "NONE_PAYLOAD" => WireError::NonePayload,
        "CTL_SHORT" => WireError::CtlShort,
        "CTL_TYPE" => WireError::CtlType,
        "CTL_CODE" => WireError::CtlCode,
        "CTL_BODY" => WireError::CtlBody,
        "CTL_CHECKSUM" => WireError::CtlChecksum,
        "DGRAM_SHORT" => WireError::DgramShort,
        "DGRAM_LENGTH" => WireError::DgramLength,
        "DGRAM_CHECKSUM" => WireError::DgramChecksum,
        _ => panic!("unknown corpus category: {name}"),
    }
}

#[test]
fn reviewed_corpus_is_accepted_or_rejected_by_exact_category() {
    let corpus: Value = serde_json::from_str(VECTORS).unwrap();
    for case in corpus["positive_cases"].as_array().unwrap() {
        let packet = bytes(case["packet_hex"].as_str().unwrap());
        Header::unpack(&packet).unwrap_or_else(|e| panic!("{}: {e}", case["id"]));
    }
    for case in corpus["negative_cases"].as_array().unwrap() {
        let packet = bytes(case["packet_hex"].as_str().unwrap());
        let result = match case["binding_budget_bytes"].as_u64() {
            Some(budget) => Header::unpack_with_budget(
                &packet,
                usize::try_from(budget).expect("binding budget must fit usize"),
            ),
            None => Header::unpack(&packet),
        };
        assert_eq!(
            result,
            Err(category(case["expected_error"].as_str().unwrap())),
            "{}",
            case["id"]
        );
    }
    for case in corpus["binding_boundary_cases"].as_array().unwrap() {
        let packet = bytes(case["packet_hex"].as_str().unwrap());
        let (header, payload) =
            Header::unpack(&packet).unwrap_or_else(|e| panic!("{}: {e}", case["id"]));
        assert_eq!(packet.len(), payload.len() + 48);
        for (budget, expected) in [
            (1252, "ipv4_udp_1252"),
            (1232, "ipv6_udp_1232"),
            (1280, "serialized_1280"),
        ] {
            let result = header.pack_with_budget(payload, budget);
            let outcome = case["serializer_budget_outcomes"][expected]
                .as_str()
                .unwrap();
            assert_eq!(
                result.is_ok(),
                outcome == "accept",
                "{} at {budget}",
                case["id"]
            );
        }
    }
}

#[test]
fn budget_boundaries_and_overflow_are_fail_closed() {
    let corpus: Value = serde_json::from_str(VECTORS).unwrap();
    let packet = bytes(
        corpus["binding_boundary_cases"][2]["packet_hex"]
            .as_str()
            .unwrap(),
    );
    let (header, payload) = Header::unpack(&packet).unwrap();
    assert_eq!(packet.len(), SERIALIZED_R8_MAX);
    assert_eq!(
        header.pack_with_budget(payload, SERIALIZED_R8_MAX),
        Ok(packet.clone())
    );
    assert_eq!(
        header.pack_with_budget(payload, SERIALIZED_R8_MAX - 1),
        Err(WireError::BindingBudget)
    );
    assert_eq!(
        Header::unpack_with_budget(&packet, SERIALIZED_R8_MAX - 1),
        Err(WireError::BindingBudget)
    );
    assert_eq!(
        header.pack(&vec![0; SERIALIZED_R8_MAX]),
        Err(WireError::PacketCap)
    );

    let mut ctl_header = header.clone();
    ctl_header.next_header = NH_CTL;
    assert_eq!(
        build_ctl_with_budget(&ctl_header, 1, 0, &vec![0; 1228], SERIALIZED_R8_MAX - 1),
        Err(WireError::BindingBudget)
    );
    assert_eq!(
        build_dgram_with_budget(&ctl_header, 1, 2, &[], SERIALIZED_R8_MAX),
        Err(WireError::NextHeader)
    );

    let mut dgram_header = header;
    dgram_header.next_header = NH_DGRAM;
    assert_eq!(
        build_ctl_with_budget(&dgram_header, 1, 0, &[0, 0, 0, 0], SERIALIZED_R8_MAX),
        Err(WireError::NextHeader)
    );
    assert_eq!(
        build_dgram_with_budget(
            &dgram_header,
            1,
            2,
            &vec![0; SERIALIZED_R8_MAX],
            SERIALIZED_R8_MAX
        ),
        Err(WireError::PacketCap)
    );
}

#[test]
fn deterministic_mutations_never_panic() {
    let corpus: Value = serde_json::from_str(VECTORS).unwrap();
    for case in corpus["positive_cases"].as_array().unwrap() {
        let packet = bytes(case["packet_hex"].as_str().unwrap());
        for index in 0..packet.len() {
            let mut mutated = packet.clone();
            mutated[index] ^= 1u8 << (index % 8);
            let result = catch_unwind(AssertUnwindSafe(|| Header::unpack(&mutated)));
            assert!(result.is_ok(), "{} byte {index}", case["id"]);
        }
    }
    let mut state = 0x8f3a_52d1u32;
    for length in 0..=1281 {
        let mut input = vec![0u8; length];
        for byte in &mut input {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            *byte = (state >> 24) as u8;
        }
        assert!(catch_unwind(AssertUnwindSafe(|| Header::unpack(&input))).is_ok());
    }
}
