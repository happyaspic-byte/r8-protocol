use r8_proto::{build_dgram, Header, NH_DGRAM, NH_NONE, R8_ETHERTYPE};
use r8_session::ObservedBinding;
use r8d::{
    process_frame, validate_manifest_json, DescriptorBudgets, FrameAction, FrameDropReason,
    NativeManifest,
};
use serde_json::json;

const SOURCE: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
const NEXT_HOP: [u8; 6] = [0x02, 0, 0, 0, 0, 2];

fn make_manifest(local_delivery: bool, transit: bool) -> NativeManifest {
    let value = json!({
        "local_locs": [[0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]],
        "interfaces": [
            {"descriptor_id": 1, "interface_name": "in", "allowed_source_macs": [SOURCE], "local_delivery": local_delivery, "transit": transit},
            {"descriptor_id": 2, "interface_name": "out", "allowed_source_macs": [NEXT_HOP], "local_delivery": true, "transit": true}
        ],
        "routes": [
            {"destination_prefix": {"network": [0x20, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "prefix_length": 16}, "egress_descriptor_id": 2, "next_hop_mac": NEXT_HOP},
            {"destination_prefix": {"network": [0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "prefix_length": 8}, "egress_descriptor_id": 1, "next_hop_mac": SOURCE}
        ]
    });
    validate_manifest_json(value.to_string().as_bytes(), ["in", "out"]).unwrap()
}

fn make_packet(dst: [u8; 16], hop_limit: u8) -> Vec<u8> {
    let mut header = Header::new(NH_NONE, [0; 16], dst);
    header.hop_limit = hop_limit;
    header.pack(&[]).unwrap()
}
fn dgram_packet(dst: [u8; 16], hop_limit: u8) -> Vec<u8> {
    let mut header = Header::new(NH_DGRAM, [0; 16], dst);
    header.hop_limit = hop_limit;
    build_dgram(&header, 1, 2, &[0]).unwrap()
}

fn frame(packet: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 9]);
    frame.extend_from_slice(&SOURCE);
    frame.extend_from_slice(&R8_ETHERTYPE.to_be_bytes());
    frame.extend_from_slice(packet);
    frame
}

fn make_budgets(manifest: &NativeManifest, ingress: usize, egress: usize) -> DescriptorBudgets {
    DescriptorBudgets::new(manifest, [(1, ingress), (2, egress)]).unwrap()
}

#[test]
fn delivers_exact_packet_and_native_binding() {
    let manifest = make_manifest(true, true);
    let packet = make_packet([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 2);
    assert_eq!(
        process_frame(
            &manifest,
            &make_budgets(&manifest, 1280, 1280),
            1,
            &frame(&packet)
        ),
        FrameAction::Deliver {
            packet,
            binding: ObservedBinding::Native {
                ingress_descriptor_id: 1,
                next_hop_mac: SOURCE
            },
        }
    );
}

#[test]
fn forwards_by_longest_prefix_and_changes_only_hop_byte() {
    let manifest = make_manifest(true, true);
    let packet = make_packet([0x20, 2, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 3);
    let action = process_frame(
        &manifest,
        &make_budgets(&manifest, 1280, 1280),
        1,
        &frame(&packet),
    );
    let FrameAction::Forward {
        packet: forwarded,
        egress_descriptor_id,
        next_hop_mac,
    } = action
    else {
        panic!("expected forward")
    };
    assert_eq!(egress_descriptor_id, 2);
    assert_eq!(next_hop_mac, NEXT_HOP);
    assert_eq!(forwarded.len(), packet.len());
    assert_eq!(forwarded[5], packet[5] - 1);
    assert!(forwarded
        .iter()
        .enumerate()
        .all(|(index, byte)| index == 5 || *byte == packet[index]));

    let packet = make_packet([0x20, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 2);
    assert!(matches!(
        process_frame(
            &manifest,
            &make_budgets(&manifest, 1280, 1280),
            1,
            &frame(&packet)
        ),
        FrameAction::Forward {
            egress_descriptor_id: 1,
            ..
        }
    ));
}

#[test]
fn rejects_invalid_admission_and_policy_cases() {
    let manifest = make_manifest(true, true);
    let budgets = make_budgets(&manifest, 48, 48);
    let packet = make_packet([0x20, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 2);
    assert_eq!(
        process_frame(&manifest, &budgets, 99, &frame(&packet)),
        FrameAction::Drop(FrameDropReason::UnknownIngressDescriptor)
    );
    let mut wrong_type = frame(&packet);
    wrong_type[12..14].copy_from_slice(&0u16.to_be_bytes());
    assert_eq!(
        process_frame(&manifest, &budgets, 1, &wrong_type),
        FrameAction::Drop(FrameDropReason::InvalidFrame)
    );
    let mut truncated = frame(&packet);
    truncated.truncate(13);
    assert_eq!(
        process_frame(&manifest, &budgets, 1, &truncated),
        FrameAction::Drop(FrameDropReason::InvalidFrame)
    );
    let mut trailing = frame(&packet);
    trailing.push(0);
    assert_eq!(
        process_frame(
            &manifest,
            &make_budgets(&manifest, 1280, 1280),
            1,
            &trailing
        ),
        FrameAction::Drop(FrameDropReason::MalformedPacket)
    );
    let mut spoofed = frame(&packet);
    spoofed[6] = 3;
    assert_eq!(
        process_frame(&manifest, &budgets, 1, &spoofed),
        FrameAction::Drop(FrameDropReason::SourceNotAllowed)
    );
    let oversized = vec![0; 49];
    assert_eq!(
        process_frame(&manifest, &budgets, 1, &frame(&oversized)),
        FrameAction::Drop(FrameDropReason::IngressBudget)
    );
}

#[test]
fn rejects_local_and_transit_policy_hop_route_and_egress_budget() {
    let local = make_packet([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 2);
    let transit = make_packet([0x20, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 2);
    let no_route = make_packet([0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 2);
    let manifest = make_manifest(false, false);
    let descriptor_budgets = make_budgets(&manifest, 1280, 1280);
    assert_eq!(
        process_frame(&manifest, &descriptor_budgets, 1, &frame(&local)),
        FrameAction::Drop(FrameDropReason::LocalDeliveryDisabled)
    );
    assert_eq!(
        process_frame(&manifest, &descriptor_budgets, 1, &frame(&transit)),
        FrameAction::Drop(FrameDropReason::TransitDisabled)
    );
    let manifest = make_manifest(true, true);
    let descriptor_budgets = make_budgets(&manifest, 1280, 1280);
    assert_eq!(
        process_frame(
            &manifest,
            &descriptor_budgets,
            1,
            &frame(&make_packet(
                [0x20, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                1
            ))
        ),
        FrameAction::Drop(FrameDropReason::HopLimit)
    );
    assert_eq!(
        process_frame(&manifest, &descriptor_budgets, 1, &frame(&no_route)),
        FrameAction::Drop(FrameDropReason::NoRoute)
    );
    let oversized_for_egress = dgram_packet([0x20, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 2);
    assert_eq!(
        process_frame(
            &manifest,
            &make_budgets(&manifest, 1280, 48),
            1,
            &frame(&oversized_for_egress)
        ),
        FrameAction::Drop(FrameDropReason::EgressBudget)
    );
}

#[test]
fn debug_output_does_not_include_packet_mac_or_loc_bytes() {
    let manifest = make_manifest(true, true);
    let packet = make_packet([0x20, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 2);
    let action = process_frame(
        &manifest,
        &make_budgets(&manifest, 1280, 1280),
        1,
        &frame(&packet),
    );
    let debug = format!("{action:?}");
    assert!(!debug.contains("["));
    assert!(!debug.contains("32"));
}
