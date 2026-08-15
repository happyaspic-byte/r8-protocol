//! Linux-only, fail-closed primitives used before the launcher starts forwarding.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

const ETH_P_R8: u16 = 0x88b5;
const R8_VERSION_MASK: u32 = 0xf0;
const R8_VERSION_NIBBLE: u32 = 0x80;
const SOL_PACKET: libc::c_int = 263;
const PACKET_IGNORE_OUTGOING: libc::c_int = 23;
const SO_ATTACH_FILTER: libc::c_int = 26;
const SO_DETACH_FILTER: libc::c_int = 27;
const SO_LOCK_FILTER: libc::c_int = 44;
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const PR_GET_NO_NEW_PRIVS: libc::c_int = 39;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
const PR_SET_DUMPABLE: libc::c_int = 4;
const PR_GET_DUMPABLE: libc::c_int = 3;
const CAPSET_VERSION_3: u32 = 0x2008_0522;
const REQUIRED_SEALS: libc::c_int =
    libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

/// Finite, redacted error categories for launcher safety checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxError {
    Namespace,
    Network,
    DefaultRouteV4,
    Interface,
    Address,
    Socket,
    Privilege,
    Manifest,
}

impl fmt::Display for LinuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("linux launcher rejected")
    }
}

impl std::error::Error for LinuxError {}

/// A packet socket restricted to one interface and the R8 ingress filter.
pub struct FilteredDescriptor {
    fd: OwnedFd,
    ifindex: libc::c_int,
    mtu: libc::c_int,
    local_mac: [u8; 6],
}

impl FilteredDescriptor {
    pub fn as_fd(&self) -> &OwnedFd {
        &self.fd
    }
    pub fn ifindex(&self) -> libc::c_int {
        self.ifindex
    }
    pub fn mtu(&self) -> libc::c_int {
        self.mtu
    }
    pub fn local_mac(&self) -> [u8; 6] {
        self.local_mac
    }
    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }
}
impl AsRawFd for FilteredDescriptor {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Require an isolated network namespace with only inert, explicitly allowlisted interfaces.
pub fn verify_isolated_namespace<I, S>(interface_names: I) -> Result<(), LinuxError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let requested: Vec<String> = interface_names
        .into_iter()
        .map(|name| name.as_ref().to_owned())
        .collect();
    let names: BTreeSet<String> = requested.iter().cloned().collect();
    if names.is_empty()
        || names.len() != requested.len()
        || names.iter().any(|name| !valid_interface_name(name))
    {
        return Err(LinuxError::Interface);
    }
    if namespace_matches_pid_one()? {
        return Err(LinuxError::Namespace);
    }
    verify_ipv6_disabled(&names)?;
    verify_no_default_route()?;
    let addresses = interface_addresses()?;
    let observed: BTreeSet<_> = addresses.iter().map(|entry| entry.name.as_str()).collect();
    let expected: BTreeSet<_> = std::iter::once("lo")
        .chain(names.iter().map(String::as_str))
        .collect();
    if observed != expected {
        return Err(LinuxError::Interface);
    }
    let loopback = addresses
        .iter()
        .find(|entry| entry.name == "lo")
        .ok_or(LinuxError::Address)?;
    if !loopback.loopback || loopback.up {
        return Err(LinuxError::Address);
    }
    for name in &names {
        let entry = addresses
            .iter()
            .find(|entry| entry.name == *name)
            .ok_or(LinuxError::Address)?;
        if entry.loopback
            || !entry.up
            || entry.ipv4
            || entry.global_ipv6
            || has_master_or_virtual_attachment(name)
        {
            return Err(LinuxError::Address);
        }
    }
    Ok(())
}

/// Open an owned, nonblocking R8-only packet socket on `name`.
pub fn open_filtered_descriptor(name: &str) -> Result<FilteredDescriptor, LinuxError> {
    if !valid_interface_name(name) {
        return Err(LinuxError::Interface);
    }
    let (ifindex, mtu, local_mac) = interface_details(name)?;
    if ifindex <= 0 || mtu <= 0 {
        return Err(LinuxError::Interface);
    }
    let protocol = ETH_P_R8.to_be() as libc::c_int;
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    if raw_fd < 0 {
        return Err(LinuxError::Socket);
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let address = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as libc::c_ushort,
        sll_protocol: ETH_P_R8.to_be(),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &address as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(LinuxError::Socket);
    }
    let filter = r8_bpf_program();
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    set_socket_option(fd.as_raw_fd(), libc::SOL_SOCKET, SO_ATTACH_FILTER, &program)?;
    let one: libc::c_int = 1;
    set_socket_option(fd.as_raw_fd(), SOL_PACKET, PACKET_IGNORE_OUTGOING, &one)?;
    set_socket_option(fd.as_raw_fd(), libc::SOL_SOCKET, SO_LOCK_FILTER, &one)?;
    let detach = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_DETACH_FILTER,
            &one as *const libc::c_int as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if detach == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
        return Err(LinuxError::Socket);
    }
    Ok(FilteredDescriptor {
        fd,
        ifindex,
        mtu,
        local_mac,
    })
}

/// Drop all privilege irreversibly and verify the resulting process credentials.
pub fn drop_privileges(uid: libc::uid_t, gid: libc::gid_t) -> Result<(), LinuxError> {
    if uid == 0 || gid == 0 {
        return Err(LinuxError::Privilege);
    }
    if drop_bounding_capabilities() != 0
        || unsafe { libc::setgroups(0, std::ptr::null()) } != 0
        || unsafe { libc::setresgid(gid, gid, gid) } != 0
        || unsafe { libc::setresuid(uid, uid, uid) } != 0
    {
        return Err(LinuxError::Privilege);
    }
    let mut header = CapUserHeader {
        version: CAPSET_VERSION_3,
        pid: 0,
    };
    let data = [CapUserData::default(), CapUserData::default()];
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) } != 0
        || unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) } != 0
        || unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(LinuxError::Privilege);
    }
    set_nondumpable()?;
    validate_full_privilege_snapshot(&current_full_privilege_snapshot()?, uid, gid)
}
/// Make process memory nondumpable and verify that kernel state immediately.
pub fn set_nondumpable() -> Result<(), LinuxError> {
    if unsafe { libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
        || unsafe { libc::prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0
    {
        return Err(LinuxError::Privilege);
    }
    Ok(())
}

/// A testable representation of the privilege state that must hold after dropping privilege.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivilegeSnapshot {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub groups: Vec<libc::gid_t>,
    pub cap_eff: u64,
    pub no_new_privs: bool,
}

pub fn validate_privilege_snapshot(
    snapshot: &PrivilegeSnapshot,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> Result<(), LinuxError> {
    if uid == 0
        || gid == 0
        || snapshot.uid != uid
        || snapshot.gid != gid
        || !snapshot.groups.is_empty()
        || snapshot.cap_eff != 0
        || !snapshot.no_new_privs
    {
        return Err(LinuxError::Privilege);
    }
    Ok(())
}

/// Create a sealed, close-on-exec manifest fd.
pub fn create_immutable_manifest(bytes: &[u8]) -> Result<OwnedFd, LinuxError> {
    let name = CString::new("r8-manifest").map_err(|_| LinuxError::Manifest)?;
    let raw_fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        ) as RawFd
    };
    if raw_fd < 0 {
        return Err(LinuxError::Manifest);
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let mut offset = 0;
    while offset < bytes.len() {
        let written = unsafe {
            libc::write(
                fd.as_raw_fd(),
                bytes[offset..].as_ptr() as *const libc::c_void,
                bytes.len() - offset,
            )
        };
        if written <= 0 {
            return Err(LinuxError::Manifest);
        }
        offset += written as usize;
    }
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, REQUIRED_SEALS) } != 0
        || verify_immutable_manifest(&fd).is_err()
    {
        return Err(LinuxError::Manifest);
    }
    Ok(fd)
}

/// Confirm an fd has every seal required for an immutable manifest.
pub fn verify_immutable_manifest(fd: &OwnedFd) -> Result<(), LinuxError> {
    let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    if seals < 0 || seals & REQUIRED_SEALS != REQUIRED_SEALS {
        return Err(LinuxError::Manifest);
    }
    Ok(())
}

/// Read a sealed manifest without changing its file position.
pub fn read_immutable_manifest(fd: &OwnedFd) -> Result<Vec<u8>, LinuxError> {
    verify_immutable_manifest(fd)?;
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(LinuxError::Manifest);
    }
    let length = unsafe { stat.assume_init() }.st_size;
    if length < 0 {
        return Err(LinuxError::Manifest);
    }
    let mut bytes = vec![0; length as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let read = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                bytes[offset..].as_mut_ptr() as *mut libc::c_void,
                bytes.len() - offset,
                offset as libc::off_t,
            )
        };
        if read <= 0 {
            return Err(LinuxError::Manifest);
        }
        offset += read as usize;
    }
    Ok(bytes)
}

/// The classic BPF instructions used on every packet descriptor.
pub fn r8_bpf_program() -> [libc::sock_filter; 7] {
    [
        libc::sock_filter {
            code: 0x28,
            jt: 0,
            jf: 0,
            k: 12,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 4,
            k: ETH_P_R8 as u32,
        },
        libc::sock_filter {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 14,
        },
        libc::sock_filter {
            code: 0x54,
            jt: 0,
            jf: 0,
            k: R8_VERSION_MASK,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: R8_VERSION_NIBBLE,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: u32::MAX,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ]
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name != "lo"
        && name.len() < libc::IFNAMSIZ
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn namespace_matches_pid_one() -> Result<bool, LinuxError> {
    let current = fs::metadata("/proc/self/ns/net").map_err(|_| LinuxError::Namespace)?;
    let init = fs::metadata("/proc/1/ns/net").map_err(|_| LinuxError::Namespace)?;
    use std::os::unix::fs::MetadataExt;
    Ok(current.ino() == init.ino() && current.dev() == init.dev())
}

fn verify_ipv6_disabled(names: &BTreeSet<String>) -> Result<(), LinuxError> {
    for scope in ["all", "default", "lo"]
        .into_iter()
        .chain(names.iter().map(String::as_str))
    {
        let path = format!("/proc/sys/net/ipv6/conf/{scope}/disable_ipv6");
        let value = fs::read_to_string(path).map_err(|_| LinuxError::Network)?;
        if value.trim() != "1" {
            return Err(LinuxError::Network);
        }
    }
    Ok(())
}

fn verify_no_default_route() -> Result<(), LinuxError> {
    let ipv4 = fs::read_to_string("/proc/net/route").map_err(|_| LinuxError::Network)?;
    if has_ipv4_default_route(&ipv4) {
        return Err(LinuxError::DefaultRouteV4);
    }
    Ok(())
}

/// Parse `/proc/net/route`; defaults and malformed records are unsafe.
pub fn has_ipv4_default_route(route_table: &str) -> bool {
    for line in route_table.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.first() == Some(&"Iface") {
            continue;
        }
        if fields.len() != 11
            || fields[0].is_empty()
            || !is_hex_field(fields[1], 8)
            || !is_hex_field(fields[2], 8)
            || fields[3].is_empty()
            || fields[3].len() > 8
            || !fields[3].bytes().all(|byte| byte.is_ascii_hexdigit())
            || ![4, 5, 6, 8, 9, 10]
                .iter()
                .all(|&index| fields[index].bytes().all(|byte| byte.is_ascii_digit()))
            || !is_hex_field(fields[7], 8)
        {
            return true;
        }
        if fields[1] == "00000000" && fields[7] == "00000000" && !route_is_reject(fields[3]) {
            return true;
        }
    }
    false
}

fn route_is_reject(flags: &str) -> bool {
    u32::from_str_radix(flags, 16)
        .map(|value| value & 0x0200 != 0)
        .unwrap_or(false)
}

fn is_hex_field(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

struct InterfaceAddress {
    name: String,
    loopback: bool,
    up: bool,
    ipv4: bool,
    global_ipv6: bool,
}

fn interface_addresses() -> Result<Vec<InterfaceAddress>, LinuxError> {
    let mut raw = MaybeUninit::<*mut libc::ifaddrs>::uninit();
    if unsafe { libc::getifaddrs(raw.as_mut_ptr()) } != 0 {
        return Err(LinuxError::Interface);
    }
    let mut result: Vec<InterfaceAddress> = Vec::new();
    let mut cursor = unsafe { raw.assume_init() };
    while !cursor.is_null() {
        let item = unsafe { &*cursor };
        if !item.ifa_name.is_null() {
            let name = unsafe { std::ffi::CStr::from_ptr(item.ifa_name) }
                .to_str()
                .map_err(|_| LinuxError::Interface)?
                .to_owned();
            let index = match result.iter().position(|entry| entry.name == name) {
                Some(index) => index,
                None => {
                    result.push(InterfaceAddress {
                        name,
                        loopback: false,
                        up: false,
                        ipv4: false,
                        global_ipv6: false,
                    });
                    result.len() - 1
                }
            };
            let entry = &mut result[index];
            entry.loopback |= item.ifa_flags & (libc::IFF_LOOPBACK as u32) != 0;
            entry.up |= item.ifa_flags & (libc::IFF_UP as u32) != 0;
            if !item.ifa_addr.is_null() {
                match unsafe { (*item.ifa_addr).sa_family as libc::c_int } {
                    libc::AF_INET => entry.ipv4 = true,
                    libc::AF_INET6 => {
                        let address = unsafe { &*(item.ifa_addr as *const libc::sockaddr_in6) }
                            .sin6_addr
                            .s6_addr;
                        if !is_non_global_ipv6(&address) {
                            entry.global_ipv6 = true;
                        }
                    }
                    _ => {}
                }
            }
        }
        cursor = item.ifa_next;
    }
    unsafe { libc::freeifaddrs(raw.assume_init()) };
    Ok(result)
}

fn is_non_global_ipv6(address: &[u8; 16]) -> bool {
    address == &[0; 16]
        || address == &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        || (address[0] == 0xfe && address[1] & 0xc0 == 0x80)
}

fn has_master_or_virtual_attachment(name: &str) -> bool {
    let base = Path::new("/sys/class/net").join(name);
    base.join("master").exists() || base.join("bridge").exists() || base.join("bonding").exists()
}

#[repr(C)]
union IfReqData {
    value: libc::c_int,
    hardware: libc::sockaddr,
}
#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    data: IfReqData,
}

fn interface_details(name: &str) -> Result<(libc::c_int, libc::c_int, [u8; 6]), LinuxError> {
    let control = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if control < 0 {
        return Err(LinuxError::Socket);
    }
    let control = unsafe { OwnedFd::from_raw_fd(control) };
    let mut request = IfReq {
        name: [0; libc::IFNAMSIZ],
        data: IfReqData { value: 0 },
    };
    for (slot, byte) in request.name.iter_mut().zip(name.bytes()) {
        *slot = byte as libc::c_char;
    }
    if unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCGIFINDEX, &mut request) } != 0 {
        return Err(LinuxError::Interface);
    }
    let ifindex = unsafe { request.data.value };
    if unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCGIFMTU, &mut request) } != 0 {
        return Err(LinuxError::Interface);
    }
    let mtu = unsafe { request.data.value };
    if unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCGIFHWADDR, &mut request) } != 0 {
        return Err(LinuxError::Interface);
    }
    let hardware = unsafe { request.data.hardware };
    let mut mac = [0; 6];
    for (slot, byte) in mac.iter_mut().zip(hardware.sa_data.iter()) {
        *slot = *byte as u8;
    }
    Ok((ifindex, mtu, mac))
}

fn set_socket_option<T>(
    fd: RawFd,
    level: libc::c_int,
    option: libc::c_int,
    value: &T,
) -> Result<(), LinuxError> {
    if unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            value as *const T as *const libc::c_void,
            mem::size_of::<T>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(LinuxError::Socket);
    }
    Ok(())
}

#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: libc::c_int,
}
#[repr(C)]
#[derive(Default)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn drop_bounding_capabilities() -> libc::c_int {
    let last = fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|value| value.trim().parse::<libc::c_ulong>().ok());
    let Some(last) = last else {
        return -1;
    };
    for capability in 0..=last {
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } != 0 {
            return -1;
        }
    }
    0
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FullPrivilegeSnapshot {
    uid: [libc::uid_t; 4],
    gid: [libc::gid_t; 4],
    groups: Vec<libc::gid_t>,
    capabilities: [u64; 5],
    no_new_privs: bool,
}

fn validate_full_privilege_snapshot(
    snapshot: &FullPrivilegeSnapshot,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> Result<(), LinuxError> {
    if uid == 0
        || gid == 0
        || snapshot.uid != [uid; 4]
        || snapshot.gid != [gid; 4]
        || !snapshot.groups.is_empty()
        || snapshot.capabilities != [0; 5]
        || !snapshot.no_new_privs
    {
        return Err(LinuxError::Privilege);
    }
    Ok(())
}

fn current_full_privilege_snapshot() -> Result<FullPrivilegeSnapshot, LinuxError> {
    let group_count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if group_count < 0 {
        return Err(LinuxError::Privilege);
    }
    let mut groups = vec![0; group_count as usize];
    if group_count != 0
        && unsafe { libc::getgroups(group_count, groups.as_mut_ptr()) } != group_count
    {
        return Err(LinuxError::Privilege);
    }
    let mut uid = [0; 4];
    let mut gid = [0; 4];
    if unsafe { libc::getresuid(&mut uid[0], &mut uid[1], &mut uid[2]) } != 0
        || unsafe { libc::getresgid(&mut gid[0], &mut gid[1], &mut gid[2]) } != 0
    {
        return Err(LinuxError::Privilege);
    }
    uid[3] = unsafe { libc::syscall(libc::SYS_setfsuid, !0 as libc::uid_t) as libc::uid_t };
    gid[3] = unsafe { libc::syscall(libc::SYS_setfsgid, !0 as libc::gid_t) as libc::gid_t };
    let status = fs::read_to_string("/proc/self/status").map_err(|_| LinuxError::Privilege)?;
    let mut capabilities = [0; 5];
    for (index, name) in [
        "CapEff:\t",
        "CapPrm:\t",
        "CapInh:\t",
        "CapAmb:\t",
        "CapBnd:\t",
    ]
    .iter()
    .enumerate()
    {
        capabilities[index] = status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
            .ok_or(LinuxError::Privilege)?;
    }
    let no_new_privs = unsafe { libc::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if no_new_privs < 0 {
        return Err(LinuxError::Privilege);
    }
    Ok(FullPrivilegeSnapshot {
        uid,
        gid,
        groups,
        capabilities,
        no_new_privs: no_new_privs == 1,
    })
}
