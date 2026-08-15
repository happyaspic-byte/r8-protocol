//! Fail-closed long-lived native daemon runtime.

use crate::{process_frame, DescriptorBudgets, FrameAction, NativeManifest};
use r8_proto::{
    build_ctl_with_budget, parse_ctl, Header, CTL_ECHO_REPLY, CTL_ECHO_REQUEST, NH_CTL, NH_DGRAM,
    NH_SES, R8_ETHERTYPE, SERIALIZED_R8_MAX,
};
use r8_session::ObservedBinding;
use std::fmt;

pub const ETHERNET_HEADER_LEN: usize = 14;
pub const RECEIVE_CAPACITY: usize = ETHERNET_HEADER_LEN + SERIALIZED_R8_MAX + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeError {
    Receive,
    Send,
    ShortWrite,
    Revoked,
    Invariant,
}
impl fmt::Display for NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("native daemon stopped")
    }
}
impl std::error::Error for NativeError {}

/// Redacted, finite runtime accounting. It deliberately contains no network identifiers or data.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct RuntimeTelemetry {
    received: u64,
    dropped: u64,
    forwarded: u64,
    delivered: u64,
    faults: u64,
    descriptor_high_water: u32,
}
impl RuntimeTelemetry {
    pub fn received(&self) -> u64 {
        self.received
    }
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
    pub fn forwarded(&self) -> u64 {
        self.forwarded
    }
    pub fn delivered(&self) -> u64 {
        self.delivered
    }
    pub fn faults(&self) -> u64 {
        self.faults
    }
    pub fn descriptor_high_water(&self) -> u32 {
        self.descriptor_high_water
    }
}
impl fmt::Debug for RuntimeTelemetry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeTelemetry")
            .field("received", &self.received)
            .field("dropped", &self.dropped)
            .field("forwarded", &self.forwarded)
            .field("delivered", &self.delivered)
            .field("faults", &self.faults)
            .field("descriptor_high_water", &self.descriptor_high_water)
            .finish()
    }
}

/// Receive/send seam. A successful receive must be one complete Ethernet frame.
pub trait NativeIo {
    fn receive(
        &mut self,
        descriptor_id: u32,
        buffer: &mut [u8],
    ) -> Result<Option<usize>, NativeError>;
    fn send(&mut self, descriptor_id: u32, frame: &[u8]) -> Result<usize, NativeError>;
}
/// Event seam; any event is a revocation, including malformed watcher output.
pub trait EventSource {
    fn event(&mut self) -> Result<bool, NativeError>;
}
/// Clock seam for deterministic callers. Runtime does not persist clock values.
pub trait Clock {
    fn now(&mut self) -> Result<(), NativeError>;
}
/// Bounded session handoff. The default implementation is intentionally a counted sink.
pub trait SessionDelivery {
    fn deliver(&mut self, packet: &[u8], binding: ObservedBinding) -> Result<(), NativeError>;
}
#[derive(Default)]
pub struct DropSessions {
    dropped: u64,
}
impl DropSessions {
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}
impl SessionDelivery for DropSessions {
    fn deliver(&mut self, _packet: &[u8], _binding: ObservedBinding) -> Result<(), NativeError> {
        self.dropped = self.dropped.saturating_add(1);
        Ok(())
    }
}

pub fn build_ethernet_frame(
    destination: [u8; 6],
    source: [u8; 6],
    packet: &[u8],
) -> Result<Vec<u8>, NativeError> {
    if packet.len() > SERIALIZED_R8_MAX {
        return Err(NativeError::Invariant);
    }
    let mut frame = Vec::with_capacity(ETHERNET_HEADER_LEN + packet.len());
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&R8_ETHERTYPE.to_be_bytes());
    frame.extend_from_slice(packet);
    Ok(frame)
}

pub struct NativeRuntime {
    manifest: NativeManifest,
    budgets: DescriptorBudgets,
    local_macs: Vec<(u32, [u8; 6])>,
    telemetry: RuntimeTelemetry,
    stopped: bool,
}
impl NativeRuntime {
    pub fn new(
        manifest: NativeManifest,
        budgets: DescriptorBudgets,
        local_macs: Vec<(u32, [u8; 6])>,
    ) -> Result<Self, NativeError> {
        if !manifest.local_locs().is_empty()
            || manifest
                .interfaces()
                .iter()
                .any(|interface| interface.local_delivery())
            || local_macs.len() != manifest.interfaces().len()
            || local_macs.iter().any(|(id, mac)| {
                manifest.interface(*id).is_none()
                    || *mac == [0; 6]
                    || *mac == [0xff; 6]
                    || mac[0] & 1 != 0
            })
        {
            return Err(NativeError::Invariant);
        }
        let mut ids = local_macs.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() != local_macs.len()
            || manifest
                .interfaces()
                .iter()
                .any(|interface| budgets.get(interface.descriptor_id()).is_none())
        {
            return Err(NativeError::Invariant);
        }
        Ok(Self {
            manifest,
            budgets,
            local_macs,
            telemetry: RuntimeTelemetry::default(),
            stopped: false,
        })
    }
    pub fn telemetry(&self) -> &RuntimeTelemetry {
        &self.telemetry
    }
    fn mac(&self, id: u32) -> Result<[u8; 6], NativeError> {
        self.local_macs
            .iter()
            .find(|(known, _)| *known == id)
            .map(|(_, mac)| *mac)
            .ok_or(NativeError::Invariant)
    }
    fn fatal<T>(&mut self, error: NativeError) -> Result<T, NativeError> {
        if !self.stopped {
            self.stopped = true;
            self.telemetry.faults = self.telemetry.faults.saturating_add(1);
        }
        Err(error)
    }
    pub fn step_with_clock<I: NativeIo, E: EventSource, S: SessionDelivery, C: Clock>(
        &mut self,
        io: &mut I,
        events: &mut E,
        sessions: &mut S,
        clock: &mut C,
    ) -> Result<(), NativeError> {
        if let Err(error) = clock.now() {
            return self.fatal(error);
        }
        self.step(io, events, sessions)
    }
    pub fn step<I: NativeIo, E: EventSource, S: SessionDelivery>(
        &mut self,
        io: &mut I,
        events: &mut E,
        sessions: &mut S,
    ) -> Result<(), NativeError> {
        if self.stopped {
            return Err(NativeError::Invariant);
        }
        match events.event() {
            Ok(true) => return self.fatal(NativeError::Revoked),
            Ok(false) => {}
            Err(error) => return self.fatal(error),
        }
        let ids: Vec<u32> = self.local_macs.iter().map(|(id, _)| *id).collect();
        for id in ids {
            let mut buffer = [0u8; RECEIVE_CAPACITY];
            let received = match io.receive(id, &mut buffer) {
                Ok(value) => value,
                Err(error) => return self.fatal(error),
            };
            let Some(length) = received else { continue };
            self.telemetry.received = self.telemetry.received.saturating_add(1);
            self.telemetry.descriptor_high_water = self.telemetry.descriptor_high_water.max(id);
            if length > ETHERNET_HEADER_LEN + SERIALIZED_R8_MAX {
                self.telemetry.dropped = self.telemetry.dropped.saturating_add(1);
                continue;
            }
            match process_frame(&self.manifest, &self.budgets, id, &buffer[..length]) {
                FrameAction::Drop(_) => {
                    self.telemetry.dropped = self.telemetry.dropped.saturating_add(1)
                }
                FrameAction::Forward {
                    packet,
                    egress_descriptor_id,
                    next_hop_mac,
                } => {
                    if let Err(error) = self.send(io, egress_descriptor_id, next_hop_mac, &packet) {
                        return self.fatal(error);
                    }
                }
                FrameAction::Deliver { packet, binding } => {
                    if let Err(error) = self.local(&packet, binding, io, sessions) {
                        return self.fatal(error);
                    }
                }
            }
        }
        Ok(())
    }
    fn send<I: NativeIo>(
        &mut self,
        io: &mut I,
        descriptor: u32,
        destination: [u8; 6],
        packet: &[u8],
    ) -> Result<(), NativeError> {
        let source = match self.mac(descriptor) {
            Ok(source) => source,
            Err(error) => return self.fatal(error),
        };
        let frame = match build_ethernet_frame(destination, source, packet) {
            Ok(frame) => frame,
            Err(error) => return self.fatal(error),
        };
        match io.send(descriptor, &frame) {
            Ok(written) if written == frame.len() => {
                self.telemetry.forwarded = self.telemetry.forwarded.saturating_add(1);
                Ok(())
            }
            Ok(_) => self.fatal(NativeError::ShortWrite),
            Err(error) => self.fatal(error),
        }
    }
    fn local<I: NativeIo, S: SessionDelivery>(
        &mut self,
        packet: &[u8],
        binding: ObservedBinding,
        io: &mut I,
        sessions: &mut S,
    ) -> Result<(), NativeError> {
        let (header, payload) = match Header::unpack_with_budget(packet, SERIALIZED_R8_MAX) {
            Ok(value) => value,
            Err(_) => {
                self.telemetry.dropped = self.telemetry.dropped.saturating_add(1);
                return Ok(());
            }
        };
        match header.next_header {
            NH_CTL => {
                let (typ, _, body) = match parse_ctl(&header, payload) {
                    Ok(value) => value,
                    Err(_) => {
                        self.telemetry.dropped = self.telemetry.dropped.saturating_add(1);
                        return Ok(());
                    }
                };
                if typ == CTL_ECHO_REQUEST {
                    let Some(route) = self.manifest.route_for(&header.src) else {
                        self.telemetry.dropped = self.telemetry.dropped.saturating_add(1);
                        return Ok(());
                    };
                    let Some(budget) = self.budgets.get(route.egress_descriptor_id()) else {
                        self.telemetry.dropped = self.telemetry.dropped.saturating_add(1);
                        return Ok(());
                    };
                    let reply = Header::new(NH_CTL, header.dst, header.src);
                    let packet =
                        match build_ctl_with_budget(&reply, CTL_ECHO_REPLY, 0, body, budget) {
                            Ok(packet) => packet,
                            Err(_) => {
                                self.telemetry.dropped = self.telemetry.dropped.saturating_add(1);
                                return Ok(());
                            }
                        };
                    self.send(
                        io,
                        route.egress_descriptor_id(),
                        *route.next_hop_mac(),
                        &packet,
                    )?;
                } else {
                    self.telemetry.dropped = self.telemetry.dropped.saturating_add(1);
                }
            }
            NH_DGRAM => self.telemetry.dropped = self.telemetry.dropped.saturating_add(1),
            NH_SES => {
                if let Err(error) = sessions.deliver(packet, binding) {
                    return self.fatal(error);
                }
                self.telemetry.delivered = self.telemetry.delivered.saturating_add(1);
            }
            _ => self.telemetry.dropped = self.telemetry.dropped.saturating_add(1),
        };
        Ok(())
    }
}
