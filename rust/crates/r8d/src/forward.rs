//! Stateless Ethernet II R8 frame admission and forwarding.

use crate::NativeManifest;
use r8_proto::{Header, R8_ETHERTYPE, SERIALIZED_R8_MAX};
use r8_session::ObservedBinding;
use std::collections::BTreeMap;
use std::fmt;

const ETHERNET_II_HEADER_LEN: usize = 14;
const MIN_R8_PACKET_BUDGET: usize = 48;

/// A finite, redacted descriptor-budget validation failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorBudgetError {
    Invalid,
    Incomplete,
}

impl fmt::Display for DescriptorBudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("descriptor budgets rejected")
    }
}

impl std::error::Error for DescriptorBudgetError {}

/// Immutable R8 packet budgets indexed by native descriptor ID.
#[derive(Clone, Eq, PartialEq)]
pub struct DescriptorBudgets(BTreeMap<u32, usize>);

impl DescriptorBudgets {
    /// Validates one explicit packet budget for every and only manifest interface.
    pub fn new<I>(manifest: &NativeManifest, budgets: I) -> Result<Self, DescriptorBudgetError>
    where
        I: IntoIterator<Item = (u32, usize)>,
    {
        let mut values = BTreeMap::new();
        for (descriptor_id, budget) in budgets {
            if !(MIN_R8_PACKET_BUDGET..=SERIALIZED_R8_MAX).contains(&budget)
                || values.insert(descriptor_id, budget).is_some()
            {
                return Err(DescriptorBudgetError::Invalid);
            }
        }
        if values.len() != manifest.interfaces().len()
            || manifest
                .interfaces()
                .iter()
                .any(|interface| !values.contains_key(&interface.descriptor_id()))
        {
            return Err(DescriptorBudgetError::Incomplete);
        }
        Ok(Self(values))
    }

    pub fn get(&self, descriptor_id: u32) -> Option<usize> {
        self.0.get(&descriptor_id).copied()
    }
}

impl fmt::Debug for DescriptorBudgets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DescriptorBudgets")
            .field("descriptor_count", &self.0.len())
            .finish()
    }
}

/// A finite, redacted frame rejection category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameDropReason {
    InvalidFrame,
    UnknownIngressDescriptor,
    SourceNotAllowed,
    IngressBudget,
    MalformedPacket,
    LocalDeliveryDisabled,
    TransitDisabled,
    HopLimit,
    NoRoute,
    EgressBudget,
}

impl fmt::Display for FrameDropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("frame dropped")
    }
}

impl std::error::Error for FrameDropReason {}

/// The only possible result of processing one Ethernet II frame.
#[derive(Clone, Eq, PartialEq)]
pub enum FrameAction {
    Drop(FrameDropReason),
    Deliver {
        packet: Vec<u8>,
        binding: ObservedBinding,
    },
    Forward {
        packet: Vec<u8>,
        egress_descriptor_id: u32,
        next_hop_mac: [u8; 6],
    },
}

impl fmt::Debug for FrameAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Drop(reason) => f.debug_tuple("Drop").field(reason).finish(),
            Self::Deliver { .. } => f.debug_struct("Deliver").finish_non_exhaustive(),
            Self::Forward {
                egress_descriptor_id,
                ..
            } => f
                .debug_struct("Forward")
                .field("egress_descriptor_id", egress_descriptor_id)
                .finish_non_exhaustive(),
        }
    }
}

/// Strictly admits and either locally delivers or forwards exactly one R8 Ethernet II frame.
pub fn process_frame(
    manifest: &NativeManifest,
    descriptor_budgets: &DescriptorBudgets,
    ingress_descriptor_id: u32,
    ethernet_frame: &[u8],
) -> FrameAction {
    if ethernet_frame.len() < ETHERNET_II_HEADER_LEN
        || ethernet_frame[12..14] != R8_ETHERTYPE.to_be_bytes()
    {
        return FrameAction::Drop(FrameDropReason::InvalidFrame);
    }

    let Some(ingress) = manifest.interface(ingress_descriptor_id) else {
        return FrameAction::Drop(FrameDropReason::UnknownIngressDescriptor);
    };
    let source_mac: [u8; 6] = ethernet_frame[6..12]
        .try_into()
        .expect("Ethernet II frame source is six bytes");
    if !ingress.permits_source_mac(&source_mac) {
        return FrameAction::Drop(FrameDropReason::SourceNotAllowed);
    }

    let packet = &ethernet_frame[ETHERNET_II_HEADER_LEN..];
    let Some(ingress_budget) = descriptor_budgets.get(ingress_descriptor_id) else {
        return FrameAction::Drop(FrameDropReason::IngressBudget);
    };
    if packet.len() > ingress_budget {
        return FrameAction::Drop(FrameDropReason::IngressBudget);
    }
    let Ok((header, _)) = Header::unpack_with_budget(packet, ingress_budget) else {
        return FrameAction::Drop(FrameDropReason::MalformedPacket);
    };

    if manifest.is_local_loc(&header.dst) {
        if !ingress.local_delivery() {
            return FrameAction::Drop(FrameDropReason::LocalDeliveryDisabled);
        }
        return FrameAction::Deliver {
            packet: packet.to_vec(),
            binding: ObservedBinding::Native {
                ingress_descriptor_id,
                next_hop_mac: source_mac,
            },
        };
    }

    if !ingress.transit() {
        return FrameAction::Drop(FrameDropReason::TransitDisabled);
    }
    if header.hop_limit <= 1 {
        return FrameAction::Drop(FrameDropReason::HopLimit);
    }
    let Some(route) = manifest.route_for(&header.dst) else {
        return FrameAction::Drop(FrameDropReason::NoRoute);
    };
    let Some(egress_budget) = descriptor_budgets.get(route.egress_descriptor_id()) else {
        return FrameAction::Drop(FrameDropReason::EgressBudget);
    };
    if packet.len() > egress_budget {
        return FrameAction::Drop(FrameDropReason::EgressBudget);
    }

    let mut forwarded_packet = packet.to_vec();
    forwarded_packet[5] -= 1;
    FrameAction::Forward {
        packet: forwarded_packet,
        egress_descriptor_id: route.egress_descriptor_id(),
        next_hop_mac: *route.next_hop_mac(),
    }
}
