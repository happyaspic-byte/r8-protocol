use r8_proto::{build_ctl_with_budget, Header, CTL_ECHO_REQUEST, NH_CTL};
use r8d::{
    build_ethernet_frame, validate_manifest_json, DescriptorBudgets, DropSessions, EventSource,
    NativeError, NativeIo, NativeRuntime, RuntimeTelemetry, ETHERNET_HEADER_LEN,
};

#[test]
fn ethernet_ii_frame_is_exact() {
    let frame =
        build_ethernet_frame([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12], &[0xaa, 0xbb]).unwrap();
    assert_eq!(frame.len(), ETHERNET_HEADER_LEN + 2);
    assert_eq!(
        &frame[..14],
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x88, 0xb5]
    );
    assert_eq!(&frame[14..], &[0xaa, 0xbb]);
}

#[test]
fn telemetry_debug_is_finite_and_redacted() {
    let rendered = format!("{:?}", RuntimeTelemetry::default());
    assert!(rendered.contains("descriptor_high_water"));
    assert!(!rendered.contains("mac"));
    assert!(!rendered.contains("payload"));
}

const LOCAL: [u8; 16] = [1; 16];
const SOURCE: [u8; 6] = [2, 0, 0, 0, 0, 1];
const LOCAL_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];

fn runtime() -> NativeRuntime {
    let manifest = validate_manifest_json(
        br#"{"local_locs":[],"interfaces":[{"descriptor_id":1,"interface_name":"r8a","allowed_source_macs":[[2,0,0,0,0,1]],"local_delivery":false,"transit":true}],"routes":[]}"#,
        ["r8a"],
    )
    .unwrap();
    let budgets = DescriptorBudgets::new(&manifest, [(1, 1280)]).unwrap();
    NativeRuntime::new(manifest, budgets, vec![(1, LOCAL_MAC)]).unwrap()
}

struct Io(Option<Result<Vec<u8>, NativeError>>);
impl NativeIo for Io {
    fn receive(&mut self, _: u32, buffer: &mut [u8]) -> Result<Option<usize>, NativeError> {
        match self.0.take() {
            Some(Ok(frame)) => {
                buffer[..frame.len()].copy_from_slice(&frame);
                Ok(Some(frame.len()))
            }
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }
    fn send(&mut self, _: u32, _: &[u8]) -> Result<usize, NativeError> {
        Err(NativeError::Send)
    }
}
struct NoEvent;
impl EventSource for NoEvent {
    fn event(&mut self) -> Result<bool, NativeError> {
        Ok(false)
    }
}

#[test]
fn malformed_ctl_is_a_drop_and_runtime_remains_live() {
    let mut packet = vec![0; 52];
    packet[0] = 0x80;
    packet[2..4].copy_from_slice(&4u16.to_be_bytes());
    packet[4] = NH_CTL;
    packet[5] = 64;
    packet[32..48].copy_from_slice(&LOCAL);
    packet[48] = CTL_ECHO_REQUEST;
    let frame = build_ethernet_frame(LOCAL_MAC, SOURCE, &packet).unwrap();
    let mut runtime = runtime();
    let mut io = Io(Some(Ok(frame)));
    let mut events = NoEvent;
    let mut sessions = DropSessions::default();
    assert!(runtime.step(&mut io, &mut events, &mut sessions).is_ok());
    assert!(runtime.step(&mut io, &mut events, &mut sessions).is_ok());
    assert_eq!(runtime.telemetry().dropped(), 1);
}

#[test]
fn echo_route_miss_is_a_drop_and_runtime_remains_live() {
    let header = Header::new(NH_CTL, [3; 16], LOCAL);
    let packet = build_ctl_with_budget(&header, CTL_ECHO_REQUEST, 0, &[0, 0, 0, 0], 1280).unwrap();
    let frame = build_ethernet_frame(LOCAL_MAC, SOURCE, &packet).unwrap();
    let mut runtime = runtime();
    let mut io = Io(Some(Ok(frame)));
    let mut events = NoEvent;
    let mut sessions = DropSessions::default();
    assert!(runtime.step(&mut io, &mut events, &mut sessions).is_ok());
    assert!(runtime.step(&mut io, &mut events, &mut sessions).is_ok());
    assert_eq!(runtime.telemetry().dropped(), 1);
}
#[test]
fn transit_over_egress_budget_is_a_drop_and_runtime_remains_live() {
    let manifest = validate_manifest_json(
        br#"{"local_locs":[],"interfaces":[{"descriptor_id":1,"interface_name":"r8a","allowed_source_macs":[[2,0,0,0,0,1]],"local_delivery":false,"transit":true},{"descriptor_id":2,"interface_name":"r8b","allowed_source_macs":[[2,0,0,0,0,3]],"local_delivery":false,"transit":true}],"routes":[{"destination_prefix":{"network":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"prefix_length":128},"egress_descriptor_id":2,"next_hop_mac":[2,0,0,0,0,4]}]}"#,
        ["r8a", "r8b"],
    ).unwrap();
    let budgets = DescriptorBudgets::new(&manifest, [(1, 1280), (2, 48)]).unwrap();
    let mut runtime = NativeRuntime::new(
        manifest,
        budgets,
        vec![(1, LOCAL_MAC), (2, [2, 0, 0, 0, 0, 5])],
    )
    .unwrap();
    let header = Header::new(NH_CTL, [4; 16], [3; 16]);
    let packet = build_ctl_with_budget(&header, CTL_ECHO_REQUEST, 0, &[0, 0, 0, 0], 1280).unwrap();
    let frame = build_ethernet_frame(LOCAL_MAC, SOURCE, &packet).unwrap();
    let mut io = Io(Some(Ok(frame)));
    let mut events = NoEvent;
    let mut sessions = DropSessions::default();
    assert!(runtime.step(&mut io, &mut events, &mut sessions).is_ok());
    assert!(runtime.step(&mut io, &mut events, &mut sessions).is_ok());
    assert_eq!(runtime.telemetry().dropped(), 1);
}

#[test]
fn descriptor_fault_stops_runtime_permanently() {
    let mut runtime = runtime();
    let mut io = Io(Some(Err(NativeError::Receive)));
    let mut events = NoEvent;
    let mut sessions = DropSessions::default();
    assert_eq!(
        runtime.step(&mut io, &mut events, &mut sessions),
        Err(NativeError::Receive)
    );
    assert_eq!(
        runtime.step(&mut io, &mut events, &mut sessions),
        Err(NativeError::Invariant)
    );
    assert_eq!(runtime.telemetry().faults(), 1);
}
