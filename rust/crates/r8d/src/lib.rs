//! Immutable native-binding manifest validation.

pub mod forward;
pub mod linux;
pub mod manifest;
pub mod native;

pub use forward::{
    process_frame, DescriptorBudgetError, DescriptorBudgets, FrameAction, FrameDropReason,
};
pub use linux::{
    create_immutable_manifest, drop_privileges, has_ipv4_default_route, has_ipv6_default_route,
    open_filtered_descriptor, r8_bpf_program, read_immutable_manifest, set_nondumpable,
    validate_privilege_snapshot, verify_immutable_manifest, verify_isolated_namespace,
    FilteredDescriptor, LinuxError, PrivilegeSnapshot,
};
pub use manifest::{validate_manifest_json, Interface, ManifestError, NativeManifest, Route};
pub use native::{
    build_ethernet_frame, Clock, DropSessions, EventSource, NativeError, NativeIo, NativeRuntime,
    RuntimeTelemetry, SessionDelivery, ETHERNET_HEADER_LEN, RECEIVE_CAPACITY,
};
