//! Linux-only strict native launcher. It has no UDP, IP, subprocess, or recovery path.
use r8d::{
    create_immutable_manifest, drop_privileges, open_filtered_descriptor, read_immutable_manifest,
    set_nondumpable, validate_manifest_json, verify_isolated_namespace, Clock, DescriptorBudgets,
    DropSessions, EventSource, NativeError, NativeIo, NativeRuntime,
};
use std::collections::BTreeSet;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

struct Args {
    manifest: String,
    interfaces: Vec<String>,
    uid: libc::uid_t,
    gid: libc::gid_t,
}
fn arguments() -> Result<Args, &'static str> {
    let mut manifest = None;
    let mut interfaces = Vec::new();
    let mut uid = None;
    let mut gid = None;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--manifest" if manifest.is_none() => manifest = Some(args.next().ok_or("manifest")?),
            "--interface" => {
                let value = args.next().ok_or("interface")?;
                if value.is_empty() || interfaces.contains(&value) {
                    return Err("interface");
                }
                interfaces.push(value);
            }
            "--uid" if uid.is_none() => {
                let value: u32 = args.next().ok_or("uid")?.parse().map_err(|_| "uid")?;
                if value == 0 {
                    return Err("uid");
                }
                uid = Some(value);
            }
            "--gid" if gid.is_none() => {
                let value: u32 = args.next().ok_or("gid")?.parse().map_err(|_| "gid")?;
                if value == 0 {
                    return Err("gid");
                }
                gid = Some(value);
            }
            _ => return Err("arguments"),
        }
    }
    Ok(Args {
        manifest: manifest.ok_or("manifest")?,
        interfaces: if interfaces.is_empty() {
            return Err("interface");
        } else {
            interfaces
        },
        uid: uid.ok_or("uid")?,
        gid: gid.ok_or("gid")?,
    })
}
struct LinuxIo {
    fds: Vec<(u32, OwnedFd)>,
}
impl NativeIo for LinuxIo {
    fn receive(&mut self, id: u32, buffer: &mut [u8]) -> Result<Option<usize>, NativeError> {
        let fd = self
            .fds
            .iter()
            .find(|(known, _)| *known == id)
            .ok_or(NativeError::Invariant)?
            .1
            .as_raw_fd();
        let n = unsafe {
            libc::recv(
                fd,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n >= 0 {
            Ok(Some(n as usize))
        } else if std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(NativeError::Receive)
        }
    }
    fn send(&mut self, id: u32, frame: &[u8]) -> Result<usize, NativeError> {
        let fd = self
            .fds
            .iter()
            .find(|(known, _)| *known == id)
            .ok_or(NativeError::Invariant)?
            .1
            .as_raw_fd();
        let n = unsafe { libc::send(fd, frame.as_ptr() as *const _, frame.len(), 0) };
        if n < 0 {
            Err(NativeError::Send)
        } else {
            Ok(n as usize)
        }
    }
}
struct Watch(OwnedFd, Vec<String>);
impl EventSource for Watch {
    fn event(&mut self) -> Result<bool, NativeError> {
        let mut byte = [0u8; 1];
        let n = unsafe {
            libc::recv(
                self.0.as_raw_fd(),
                byte.as_mut_ptr() as *mut _,
                1,
                libc::MSG_DONTWAIT,
            )
        };
        if n >= 0 {
            verify_isolated_namespace(&self.1).map_err(|_| NativeError::Revoked)?;
            Ok(true)
        } else if std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
            Ok(false)
        } else {
            Err(NativeError::Revoked)
        }
    }
}
fn route_watch(names: Vec<String>) -> Result<Watch, NativeError> {
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(NativeError::Invariant);
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    address.nl_pid = 0;
    address.nl_groups = (libc::RTMGRP_LINK
        | libc::RTMGRP_IPV4_IFADDR
        | libc::RTMGRP_IPV6_IFADDR
        | libc::RTMGRP_IPV4_ROUTE
        | libc::RTMGRP_IPV6_ROUTE) as u32;
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &address as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as _,
        )
    } != 0
    {
        return Err(NativeError::Invariant);
    }
    Ok(Watch(fd, names))
}
struct MonotonicClock;
impl Clock for MonotonicClock {
    fn now(&mut self) -> Result<(), NativeError> {
        let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } == 0 {
            Ok(())
        } else {
            Err(NativeError::Invariant)
        }
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("r8-native startup=arguments");
    let args = arguments().map_err(|_| "r8-native arguments rejected")?;
    eprintln!("r8-native startup=manifest");
    let raw = std::fs::read(&args.manifest).map_err(|_| "manifest rejected")?;
    let sealed = create_immutable_manifest(&raw)?;
    let manifest = validate_manifest_json(&read_immutable_manifest(&sealed)?, &args.interfaces)?;
    drop(sealed);
    drop(raw);
    let declared: BTreeSet<_> = manifest
        .interfaces()
        .iter()
        .map(|item| item.interface_name())
        .collect();
    let supplied: BTreeSet<_> = args.interfaces.iter().map(String::as_str).collect();
    if declared != supplied {
        return Err("manifest allowlist rejected".into());
    }
    eprintln!("r8-native startup=isolation");
    if let Err(error) = verify_isolated_namespace(&args.interfaces) {
        let category = match error {
            r8d::LinuxError::Namespace => "namespace",
            r8d::LinuxError::Network => "network",
            r8d::LinuxError::DefaultRoute => "default-route",
            r8d::LinuxError::Address => "address",
            r8d::LinuxError::Interface => "interface",
            _ => "internal",
        };
        eprintln!("r8-native isolation={category}");
        return Err(error.into());
    }
    eprintln!("r8-native startup=descriptors");
    let mut records = Vec::new();
    let mut budgets = Vec::new();
    let mut fds = Vec::new();
    for interface in manifest.interfaces() {
        let descriptor = open_filtered_descriptor(interface.interface_name())?;
        let budget = usize::min(1280, descriptor.mtu() as usize);
        records.push((interface.descriptor_id(), descriptor.local_mac()));
        budgets.push((interface.descriptor_id(), budget));
        fds.push((interface.descriptor_id(), descriptor.into_fd()));
    }
    let budgets = DescriptorBudgets::new(&manifest, budgets)?;
    eprintln!("r8-native startup=watch");
    let mut watch = route_watch(args.interfaces.clone())?;
    eprintln!("r8-native startup=privilege");
    drop_privileges(args.uid, args.gid)?;
    set_nondumpable()?;
    let descriptor_count = records.len();
    eprintln!("r8-native startup=runtime");
    let mut runtime = NativeRuntime::new(manifest, budgets, records)?;
    let mut io = LinuxIo { fds };
    let mut sessions = DropSessions::default();
    let mut clock = MonotonicClock;
    println!("r8-native ready descriptors={descriptor_count}");
    loop {
        let mut poll = io
            .fds
            .iter()
            .map(|(_, fd)| libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect::<Vec<_>>();
        poll.push(libc::pollfd {
            fd: watch.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        if unsafe { libc::poll(poll.as_mut_ptr(), poll.len() as _, -1) } <= 0
            || poll
                .iter()
                .any(|entry| entry.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0)
        {
            return Err("poll failed".into());
        }
        runtime.step_with_clock(&mut io, &mut watch, &mut sessions, &mut clock)?;
    }
}
