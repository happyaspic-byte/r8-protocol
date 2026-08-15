use r8d::{
    create_immutable_manifest, has_ipv4_default_route, r8_bpf_program, read_immutable_manifest,
    validate_privilege_snapshot, verify_immutable_manifest, LinuxError, PrivilegeSnapshot,
};
use std::os::fd::AsRawFd;
#[test]
fn route_parsers_identify_default_and_malformed_records() {
    assert!(has_ipv4_default_route(
        "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 0100007F 0003 0 0 0 00000000 0 0 0\n"
    ));
    assert!(!has_ipv4_default_route(
        "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 0100007F 00000000 0001 0 0 0 FFFFFFFF 0 0 0\n"
    ));
    assert!(!has_ipv4_default_route(
        "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\nlo 00000000 00000000 0200 0 0 0 00000000 0 0 0\n"
    ));
    assert!(has_ipv4_default_route(
        "Iface Destination Gateway\neth0 malformed\n"
    ));
    assert!(has_ipv4_default_route(
        "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 0100007F 00000000 0001 0 nope 0 FFFFFFFF 0 0 0\n"
    ));
}

#[test]
fn bpf_requires_r8_ethertype_and_version_nibble() {
    let filter = r8_bpf_program();
    assert_eq!(filter.len(), 7);
    assert_eq!((filter[0].code, filter[0].k), (0x28, 12));
    assert_eq!(
        (filter[1].code, filter[1].jt, filter[1].jf, filter[1].k),
        (0x15, 0, 4, 0x88b5)
    );
    assert_eq!((filter[2].code, filter[2].k), (0x30, 14));
    assert_eq!((filter[3].code, filter[3].k), (0x54, 0xf0));
    assert_eq!(
        (filter[4].code, filter[4].jt, filter[4].jf, filter[4].k),
        (0x15, 0, 1, 0x80)
    );
    assert_eq!(filter[5].k, u32::MAX);
    assert_eq!(filter[6].k, 0);
}

#[test]
fn errors_are_redacted_and_finite() {
    for error in [
        LinuxError::Namespace,
        LinuxError::Network,
        LinuxError::DefaultRouteV4,
        LinuxError::Interface,
        LinuxError::Address,
        LinuxError::Socket,
        LinuxError::Privilege,
        LinuxError::Manifest,
    ] {
        assert_eq!(error.to_string(), "linux launcher rejected");
    }
}

#[test]
fn immutable_manifest_is_sealed_and_read_without_seek_side_effects() {
    let manifest = create_immutable_manifest(b"immutable manifest").expect("memfd");
    verify_immutable_manifest(&manifest).expect("required seals");
    assert_eq!(
        read_immutable_manifest(&manifest).expect("read sealed manifest"),
        b"immutable manifest"
    );
    assert_eq!(
        unsafe { libc::write(manifest.as_raw_fd(), b"x".as_ptr().cast(), 1) },
        -1
    );
}

#[test]
fn privilege_snapshot_validation_rejects_every_remaining_privilege() {
    let clean = PrivilegeSnapshot {
        uid: 1000,
        gid: 1000,
        groups: vec![],
        cap_eff: 0,
        no_new_privs: true,
    };
    assert_eq!(validate_privilege_snapshot(&clean, 1000, 1000), Ok(()));
    for dirty in [
        PrivilegeSnapshot {
            uid: 0,
            ..clean.clone()
        },
        PrivilegeSnapshot {
            gid: 0,
            ..clean.clone()
        },
        PrivilegeSnapshot {
            groups: vec![1000],
            ..clean.clone()
        },
        PrivilegeSnapshot {
            cap_eff: 1,
            ..clean.clone()
        },
        PrivilegeSnapshot {
            no_new_privs: false,
            ..clean.clone()
        },
        PrivilegeSnapshot {
            uid: 1001,
            ..clean.clone()
        },
    ] {
        assert_eq!(
            validate_privilege_snapshot(&dirty, 1000, 1000),
            Err(LinuxError::Privilege)
        );
    }
}
