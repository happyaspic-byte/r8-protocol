//! Native closed-lab R8 protected-mobility UDP endpoint.
use std::{
    cell::RefCell,
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr, UdpSocket},
    process::ExitCode,
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use getrandom::getrandom;
use hmac::{Hmac, Mac};
use r8_mobility::{
    CandidateManager, CandidateManagerConfig, Control, MobilityError, ObservedBinding, Policy,
};
use r8_proto::{parse_loc, Header};
use r8_session::{
    ClientMachine, ClientMaterial, HandshakeConfig, Identity, PrevalidationLimiter,
    ServerHandshakeMaterial, ServerMachine, ServerMaterial, SessionError, UdpBinding,
};
use sha2::Sha256;

const BUDGET: usize = 1252;
const RECV_EXTRA: usize = 1;
#[derive(Clone, Copy)]
enum CliError {
    Session(SessionError),
    Mobility(MobilityError),
    Io,
    Config,
}
impl From<SessionError> for CliError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}
impl From<MobilityError> for CliError {
    fn from(error: MobilityError) -> Self {
        Self::Mobility(error)
    }
}
impl CliError {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Session(error) => error.as_str(),
            Self::Mobility(error) => error.as_str(),
            Self::Io => "IO",
            Self::Config => "CONFIG",
        }
    }
}
fn classify_send_result(result: std::io::Result<usize>, length: usize) -> Result<(), CliError> {
    match result {
        Ok(written) if written == length => Ok(()),
        Ok(_) => Err(CliError::Io),
        Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => {
            Err(CliError::Session(SessionError::Budget))
        }
        Err(_) => Err(CliError::Io),
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Command {
    Serve,
    Connect,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum MoveMode {
    Abrupt,
    Mbb,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum MovingRole {
    Role1,
    Role2,
}
struct Options {
    command: Command,
    seed: [u8; 32],
    peer_key: [u8; 32],
    service: u32,
    server_context: u32,
    old: [u8; 16],
    peer_loc: [u8; 16],
    new: [u8; 16],
    bind: SocketAddr,
    candidate_bind: SocketAddr,
    peer: Option<SocketAddr>,
    policy: u32,
    budget: usize,
    timeout: Duration,
    scid: Option<u64>,
    candidate: Option<[u8; 16]>,
    secret: Option<[u8; 32]>,
    message: Vec<u8>,
    mode: MoveMode,
    moving_role: MovingRole,
    stream_rate: u64,
    stream_start_ns: u64,
    stream_cutover_ns: u64,
    stream_end_ns: u64,
    fds: Fds,
    max_sessions: usize,
    expected_post_move: usize,
}
#[derive(Default)]
struct Fds {
    ready: Option<i32>,
    schedule: Option<i32>,
    gate: Option<i32>,
    cutover_gate: Option<i32>,
    scheduled: Option<i32>,
    attempt: Option<i32>,
    sent: Option<i32>,
    events: Option<i32>,
    cpu: Option<i32>,
}
struct StreamPlan {
    start_ns: u64,
    cutover_ns: u64,
    end_ns: u64,
    period_ns: u64,
    next_sequence: u64,
}
fn server_complete(complete: usize, expected: usize, stream_end: Option<u64>, now_ns: u64) -> bool {
    complete >= expected && stream_end.is_none_or(|end_ns| now_ns >= end_ns)
}
fn counts_post_move_packet(promoted: bool, endpoint: SocketAddr, target: SocketAddr) -> bool {
    promoted && endpoint == target
}
fn wait_for_stream_end(end_ns: u64) -> Result<(), CliError> {
    while monotonic_ns()? < end_ns {
        std::thread::sleep(Duration::from_micros(100));
    }
    Ok(())
}

fn err<T>() -> Result<T, CliError> {
    Err(CliError::Config)
}
fn hex(text: &str) -> Result<Vec<u8>, CliError> {
    if !text.len().is_multiple_of(2) {
        return err();
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| CliError::Config))
        .collect()
}
fn fixed<const N: usize>(text: &str) -> Result<[u8; N], CliError> {
    hex(text)?.try_into().map_err(|_| CliError::Config)
}
fn value(args: &[String], flag: &str) -> Result<String, CliError> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
        .ok_or(CliError::Config)
}
fn optional(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
}
fn number<T: std::str::FromStr>(args: &[String], flag: &str) -> Result<T, CliError> {
    value(args, flag)?.parse().map_err(|_| CliError::Config)
}
fn loc(args: &[String], flag: &str) -> Result<[u8; 16], CliError> {
    parse_loc(&value(args, flag)?).map_err(|_| CliError::Config)
}
fn endpoint(args: &[String], flag: &str, default: &str) -> Result<SocketAddr, CliError> {
    optional(args, flag)
        .unwrap_or_else(|| default.to_owned())
        .parse()
        .map_err(|_| CliError::Config)
}
fn validate_args(args: &[String], command: Command) -> Result<(), CliError> {
    const VALUE_FLAGS: &[&str] = &[
        "--local-seed-hex",
        "--peer-public-key-hex",
        "--service-context",
        "--server-context-id",
        "--address",
        "--peer-address",
        "--new-address",
        "--bind",
        "--candidate-bind",
        "--peer",
        "--policy",
        "--binding-budget",
        "--timeout",
        "--deterministic-scid",
        "--deterministic-candidate-hex",
        "--deterministic-secret-hex",
        "--message-hex",
        "--mode",
        "--moving-role",
        "--max-sessions",
        "--expected-post-move",
        "--stream-rate",
        "--stream-start-ns",
        "--stream-cutover-ns",
        "--stream-end-ns",
        "--ready-fd",
        "--schedule-fd",
        "--gate-fd",
        "--cutover-gate-fd",
        "--scheduled-fd",
        "--attempt-fd",
        "--sent-fd",
        "--events-fd",
        "--cpu-fd",
    ];
    let mut seen = std::collections::HashSet::new();
    let mut index = 2;
    while index < args.len() {
        let flag = &args[index];
        if flag == "--allow-isolated-underlay" {
            if !seen.insert(flag) {
                return err();
            }
            index += 1;
            continue;
        }
        if !VALUE_FLAGS.contains(&flag.as_str())
            || !seen.insert(flag)
            || index + 1 == args.len()
            || args[index + 1].starts_with("--")
            || (command == Command::Serve && (flag == "--peer" || flag == "--message-hex"))
        {
            return err();
        }
        index += 2;
    }
    Ok(())
}
fn allowed_underlay(address: SocketAddr, isolated: bool) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => ip.is_loopback() || (isolated && (ip.is_private() || ip.is_link_local())),
        IpAddr::V6(ip) => ip.is_loopback() || (isolated && ip.is_unicast_link_local()),
    }
}
fn options() -> Result<Options, CliError> {
    let args: Vec<String> = env::args().collect();
    let command = match args.get(1).map(String::as_str) {
        Some("serve") => Command::Serve,
        Some("connect") => Command::Connect,
        _ => return err(),
    };
    validate_args(&args, command)?;
    let isolated = args.iter().any(|arg| arg == "--allow-isolated-underlay");
    let budget = optional(&args, "--binding-budget")
        .map(|v| v.parse().map_err(|_| CliError::Config))
        .transpose()?
        .unwrap_or(BUDGET);
    let timeout = optional(&args, "--timeout")
        .map(|v| v.parse::<f64>().map_err(|_| CliError::Config))
        .transpose()?
        .unwrap_or(5.0);
    if !(48..=BUDGET).contains(&budget) || !timeout.is_finite() || timeout <= 0.0 {
        return err();
    }
    let bind = endpoint(
        &args,
        "--bind",
        if command == Command::Serve {
            "127.0.0.1:52818"
        } else {
            "127.0.0.1:0"
        },
    )?;
    let candidate_bind = endpoint(&args, "--candidate-bind", "127.0.0.1:0")?;
    let peer = if command == Command::Connect {
        Some(
            value(&args, "--peer")?
                .parse()
                .map_err(|_| CliError::Config)?,
        )
    } else {
        None
    };
    if !allowed_underlay(bind, isolated)
        || !allowed_underlay(candidate_bind, isolated)
        || peer.is_some_and(|address| !allowed_underlay(address, isolated))
    {
        return err();
    }
    let service = number(&args, "--service-context")?;
    let server_context = number(&args, "--server-context-id")?;
    let policy = optional(&args, "--policy")
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| CliError::Config)?
        .unwrap_or(1);
    let max_sessions = optional(&args, "--max-sessions")
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| CliError::Config)?
        .unwrap_or(1);
    let expected_post_move = optional(&args, "--expected-post-move")
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| CliError::Config)?
        .unwrap_or(1);
    let stream_rate = optional(&args, "--stream-rate")
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| CliError::Config)?
        .unwrap_or(0);
    let stream_start_ns = optional(&args, "--stream-start-ns")
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| CliError::Config)?
        .unwrap_or(0);
    let stream_cutover_ns = optional(&args, "--stream-cutover-ns")
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| CliError::Config)?
        .unwrap_or(0);
    let stream_end_ns = optional(&args, "--stream-end-ns")
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| CliError::Config)?
        .unwrap_or(0);
    let fd = |flag| {
        optional(&args, flag)
            .map(|value| value.parse::<i32>().map_err(|_| CliError::Config))
            .transpose()
    };
    let fds = Fds {
        ready: fd("--ready-fd")?,
        schedule: fd("--schedule-fd")?,
        gate: fd("--gate-fd")?,
        cutover_gate: fd("--cutover-gate-fd")?,
        scheduled: fd("--scheduled-fd")?,
        attempt: fd("--attempt-fd")?,
        sent: fd("--sent-fd")?,
        events: fd("--events-fd")?,
        cpu: fd("--cpu-fd")?,
    };
    let stream_fds = [
        fds.scheduled,
        fds.attempt,
        fds.sent,
        fds.events,
        fds.cpu,
        fds.schedule,
        fds.gate,
        fds.cutover_gate,
    ];
    let moving_role = match optional(&args, "--moving-role").as_deref().unwrap_or("1") {
        "1" => MovingRole::Role1,
        "2" => MovingRole::Role2,
        _ => return err(),
    };
    if service == 0
        || server_context == 0
        || max_sessions == 0
        || expected_post_move == 0
        || [
            fds.ready,
            fds.schedule,
            fds.gate,
            fds.cutover_gate,
            fds.scheduled,
            fds.attempt,
            fds.sent,
            fds.events,
            fds.cpu,
        ]
        .iter()
        .flatten()
        .any(|fd| *fd < 0)
        || (fds.schedule.is_some() != fds.gate.is_some())
        || (fds.cutover_gate.is_some()
            && (fds.schedule.is_none()
                || stream_rate == 0
                || !((command == Command::Connect && moving_role == MovingRole::Role1)
                    || (command == Command::Serve && moving_role == MovingRole::Role2))))
        || (stream_rate == 0 && stream_fds.iter().any(Option::is_some))
        || (stream_rate != 0
            && (1_000_000_000 % stream_rate != 0
                || (fds.schedule.is_some()
                    && (stream_start_ns != 0 || stream_cutover_ns != 0 || stream_end_ns != 0))
                || (fds.schedule.is_none()
                    && (stream_start_ns == 0
                        || stream_cutover_ns == 0
                        || stream_end_ns == 0
                        || stream_start_ns >= stream_cutover_ns
                        || stream_cutover_ns >= stream_end_ns))))
    {
        return err();
    }
    let message = optional(&args, "--message-hex").map_or_else(|| Ok(vec![0; 64]), |v| hex(&v))?;
    if command == Command::Connect
        && (message.is_empty() || message.len() > budget.saturating_sub(76))
    {
        return err();
    }
    let scid = optional(&args, "--deterministic-scid")
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| CliError::Config)?;
    if scid == Some(0) {
        return err();
    }
    if command == Command::Serve && moving_role == MovingRole::Role2 && max_sessions != 1 {
        return err();
    }
    let mode = match optional(&args, "--mode").as_deref().unwrap_or("mbb") {
        "abrupt" => MoveMode::Abrupt,
        "mbb" => MoveMode::Mbb,
        _ => return err(),
    };
    Ok(Options {
        command,
        seed: fixed(&value(&args, "--local-seed-hex")?)?,
        peer_key: fixed(&value(&args, "--peer-public-key-hex")?)?,
        service,
        server_context,
        old: loc(&args, "--address")?,
        peer_loc: loc(&args, "--peer-address")?,
        new: loc(&args, "--new-address")?,
        bind,
        candidate_bind,
        peer,
        policy,
        budget,
        timeout: Duration::from_secs_f64(timeout),
        scid,
        candidate: optional(&args, "--deterministic-candidate-hex")
            .map(|v| fixed(&v))
            .transpose()?,
        secret: optional(&args, "--deterministic-secret-hex")
            .map(|v| fixed(&v))
            .transpose()?,
        message,
        mode,
        moving_role,
        stream_rate,
        stream_start_ns,
        stream_cutover_ns,
        stream_end_ns,
        fds,
        max_sessions,
        expected_post_move,
    })
}
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
fn configure_df(socket: &UdpSocket) -> Result<(), CliError> {
    #[cfg(target_os = "linux")]
    {
        let value: libc::c_int = libc::IP_PMTUDISC_DO;
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(CliError::Io);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = socket;
    Ok(())
}
fn random<const N: usize>() -> Result<[u8; N], CliError> {
    let mut out = [0; N];
    getrandom(&mut out).map_err(|_| SessionError::RngFailure)?;
    Ok(out)
}
fn scid() -> Result<u64, CliError> {
    loop {
        let value = u64::from_be_bytes(random()?);
        if value != 0 {
            return Ok(value);
        }
    }
}
fn binding(endpoint: SocketAddr, selector: [u8; 16]) -> Result<UdpBinding, CliError> {
    match endpoint.ip() {
        IpAddr::V4(ip) => {
            UdpBinding::ipv4(ip.octets(), endpoint.port(), 1, selector).map_err(CliError::from)
        }
        IpAddr::V6(ip) => {
            UdpBinding::ipv6(ip.octets(), endpoint.port(), 1, selector).map_err(CliError::from)
        }
    }
}
fn opaque_source(endpoint: SocketAddr, key: &[u8; 32]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("fixed key");
    match endpoint.ip() {
        IpAddr::V4(ip) => {
            mac.update(&[4]);
            mac.update(&ip.octets());
        }
        IpAddr::V6(ip) => {
            mac.update(&[6]);
            mac.update(&ip.octets());
        }
    }
    mac.update(&endpoint.port().to_be_bytes());
    mac.finalize().into_bytes().into()
}
fn send(socket: &UdpSocket, packet: &[u8], peer: SocketAddr) -> Result<(), CliError> {
    if packet.len() > BUDGET {
        return Err(CliError::Session(SessionError::Budget));
    }
    classify_send_result(socket.send_to(packet, peer), packet.len())
}
fn receive(
    socket: &UdpSocket,
    timeout: Duration,
    budget: usize,
) -> Result<(Vec<u8>, SocketAddr), CliError> {
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|_| CliError::Io)?;
    let mut buffer = vec![
        0;
        budget
            .checked_add(RECV_EXTRA)
            .ok_or(CliError::Session(SessionError::Budget))?
    ];
    match socket.recv_from(&mut buffer) {
        Ok((length, peer)) if length <= budget => {
            buffer.truncate(length);
            Ok((buffer, peer))
        }
        Ok(_) => Err(CliError::Session(SessionError::Budget)),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Err(CliError::Session(SessionError::Timeout))
        }
        Err(_) => Err(CliError::Io),
    }
}
fn now_ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}
fn monotonic_ns() -> Result<u64, CliError> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0
        || value.tv_sec < 0
        || value.tv_nsec < 0
    {
        return Err(CliError::Io);
    }
    (value.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64))
        .ok_or(CliError::Io)
}
fn config(local: Identity, peer: Identity, options: &Options) -> HandshakeConfig {
    HandshakeConfig {
        local,
        peer,
        profile: 0,
        source: if options.command == Command::Connect {
            options.old
        } else {
            options.peer_loc
        },
        destination: if options.command == Command::Connect {
            options.peer_loc
        } else {
            options.old
        },
        budget: options.budget,
        pending_limit: 256,
        established_limit: options.max_sessions,
        server_context_id: options.server_context,
    }
}
fn identities(options: &Options) -> Result<(SigningKey, Identity, Identity), CliError> {
    let signing = SigningKey::from_bytes(&options.seed);
    let local = Identity::from_public_key(
        if options.command == Command::Connect {
            1
        } else {
            2
        },
        options.service,
        signing.verifying_key().to_bytes(),
    )?;
    let peer = Identity::from_public_key(
        if options.command == Command::Connect {
            2
        } else {
            1
        },
        options.service,
        options.peer_key,
    )?;
    Ok((signing, local, peer))
}
fn write_all(fd: i32, bytes: &[u8]) -> Result<(), CliError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let written =
            unsafe { libc::write(fd, bytes[offset..].as_ptr().cast(), bytes.len() - offset) };
        if written > 0 {
            offset += written as usize;
        } else if written < 0 && unsafe { *libc::__errno_location() } == libc::EINTR {
            continue;
        } else {
            return Err(CliError::Io);
        }
    }
    Ok(())
}
fn read_exact(fd: i32, bytes: &mut [u8]) -> Result<(), CliError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let read = unsafe {
            libc::read(
                fd,
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if read > 0 {
            offset += read as usize;
        } else if read < 0 && unsafe { *libc::__errno_location() } == libc::EINTR {
            continue;
        } else {
            return Err(CliError::Io);
        }
    }
    Ok(())
}
fn record(fd: Option<i32>, sequence: u64, timestamp: u64) -> Result<(), CliError> {
    if let Some(fd) = fd {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&sequence.to_be_bytes());
        bytes[8..].copy_from_slice(&timestamp.to_be_bytes());
        write_all(fd, &bytes)?;
    }
    Ok(())
}
#[derive(Clone, Copy)]
struct CpuUsage {
    timestamp_ns: u64,
    user_ns: u64,
    system_ns: u64,
}
fn timeval_ns(value: libc::timeval) -> Result<u64, CliError> {
    if value.tv_sec < 0 || value.tv_usec < 0 || value.tv_usec >= 1_000_000 {
        return Err(CliError::Io);
    }
    (value.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add((value.tv_usec as u64).checked_mul(1_000)?))
        .ok_or(CliError::Io)
}
fn cpu_usage() -> Result<CpuUsage, CliError> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return Err(CliError::Io);
    }
    let usage = unsafe { usage.assume_init() };
    Ok(CpuUsage {
        timestamp_ns: monotonic_ns()?,
        user_ns: timeval_ns(usage.ru_utime)?,
        system_ns: timeval_ns(usage.ru_stime)?,
    })
}
fn cpu_record(before: CpuUsage, after: CpuUsage) -> [u8; 48] {
    let mut bytes = [0; 48];
    bytes[..8].copy_from_slice(&before.timestamp_ns.to_be_bytes());
    bytes[8..16].copy_from_slice(&before.user_ns.to_be_bytes());
    bytes[16..24].copy_from_slice(&before.system_ns.to_be_bytes());
    bytes[24..32].copy_from_slice(&after.timestamp_ns.to_be_bytes());
    bytes[32..40].copy_from_slice(&after.user_ns.to_be_bytes());
    bytes[40..].copy_from_slice(&after.system_ns.to_be_bytes());
    bytes
}
fn write_cpu(fd: Option<i32>, before: CpuUsage) -> Result<(), CliError> {
    if let Some(fd) = fd {
        write_all(fd, &cpu_record(before, cpu_usage()?))?;
    }
    Ok(())
}
fn finish_cpu(options: &Options, before: Option<CpuUsage>) -> Result<(), CliError> {
    if let Some(before) = before {
        write_cpu(options.fds.cpu, before)?;
    }
    Ok(())
}
fn ready(fd: Option<i32>) -> Result<(), CliError> {
    if let Some(fd) = fd {
        write_all(fd, &monotonic_ns()?.to_be_bytes())?;
    }
    Ok(())
}
fn read_stream_plan(options: &Options) -> Result<Option<StreamPlan>, CliError> {
    if options.stream_rate == 0 {
        return Ok(None);
    }
    let (start_ns, cutover_ns, end_ns) = match (options.fds.schedule, options.fds.gate) {
        (Some(schedule), Some(gate)) => {
            let mut bytes = [0; 24];
            read_exact(schedule, &mut bytes)?;
            let mut released = [0; 1];
            read_exact(gate, &mut released)?;
            (
                u64::from_be_bytes(bytes[..8].try_into().map_err(|_| CliError::Io)?),
                u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| CliError::Io)?),
                u64::from_be_bytes(bytes[16..].try_into().map_err(|_| CliError::Io)?),
            )
        }
        (None, None) => (
            options.stream_start_ns,
            options.stream_cutover_ns,
            options.stream_end_ns,
        ),
        _ => return err(),
    };
    if start_ns >= cutover_ns || cutover_ns >= end_ns {
        return err();
    }
    Ok(Some(StreamPlan {
        start_ns,
        cutover_ns,
        end_ns,
        period_ns: 1_000_000_000 / options.stream_rate,
        next_sequence: 0,
    }))
}
fn receive_timeout(deadline: Instant, cap: Duration) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        None
    } else {
        Some(remaining.min(cap).max(Duration::from_micros(1)))
    }
}
fn await_cutover_gate(options: &Options, plan: &StreamPlan) -> Result<(), CliError> {
    if let Some(fd) = options.fds.cutover_gate {
        while monotonic_ns()? < plan.cutover_ns {
            std::thread::sleep(Duration::from_micros(100));
        }
        let mut released = [0; 1];
        read_exact(fd, &mut released)?;
    }
    Ok(())
}
fn handshake(
    options: &Options,
    signing: SigningKey,
    local: Identity,
    peer: Identity,
    start: Instant,
) -> Result<(ClientMachine, UdpSocket, u64), CliError> {
    let target = options.peer.ok_or(CliError::Config)?;
    let mut client = ClientMachine::new(config(local, peer, options), signing)?;
    let socket = UdpSocket::bind(options.bind).map_err(|_| CliError::Io)?;
    configure_df(&socket)?;
    let id = options.scid.unwrap_or(scid()?);
    let mut packet = client.start(
        id,
        ClientMaterial {
            ephemeral_secret: random()?,
            nonce: random()?,
        },
        now_ms(start),
    )?;
    let deadline = Instant::now() + options.timeout;
    let mut phase = 0;
    while Instant::now() < deadline && phase < 3 {
        send(&socket, &packet, target)?;
        match receive(
            &socket,
            match receive_timeout(deadline, Duration::from_millis(500)) {
                Some(timeout) => timeout,
                None => break,
            },
            options.budget,
        ) {
            Ok((incoming, source)) if source == target => match phase {
                0 => {
                    if let Ok(next) = client.receive_verify(&incoming, now_ms(start)) {
                        packet = next;
                        phase = 1;
                    }
                }
                1 => {
                    if let Ok(next) = client.receive_ack(&incoming, now_ms(start)) {
                        packet = next;
                        phase = 2;
                    }
                }
                _ => {}
            },
            Err(CliError::Session(SessionError::Timeout)) => continue,
            Err(CliError::Io) => return Err(CliError::Io),
            _ => continue,
        }
        if phase == 2 {
            send(&socket, &packet, target)?;
            phase = 3;
        }
    }
    if phase == 3 {
        Ok((client, socket, id))
    } else {
        Err(CliError::Session(SessionError::Timeout))
    }
}
fn exchange(
    client: &mut ClientMachine,
    socket: &UdpSocket,
    target: SocketAddr,
    payload: &[u8],
    options: &Options,
    event: bool,
    timeout: Duration,
) -> Result<(), CliError> {
    let sequence = event
        .then(|| {
            payload[..8]
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| CliError::Io)
        })
        .transpose()?;
    if let Some(sequence) = sequence {
        record(options.fds.attempt, sequence, monotonic_ns()?)?;
    }
    send(socket, &client.send_data(payload)?, target)?;
    if let Some(sequence) = sequence {
        record(options.fds.sent, sequence, monotonic_ns()?)?;
    }
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let (packet, source) = receive(
            socket,
            match receive_timeout(deadline, timeout) {
                Some(timeout) => timeout,
                None => break,
            },
            options.budget,
        )?;
        if source != target {
            continue;
        }
        if client.receive_data(&packet)? == payload {
            if event && payload.len() == 64 {
                let sequence =
                    u64::from_be_bytes(payload[..8].try_into().map_err(|_| CliError::Io)?);
                record(options.fds.events, sequence, monotonic_ns()?)?;
            }
            return Ok(());
        }
    }
    Err(CliError::Session(SessionError::Timeout))
}
fn move_client(
    options: &Options,
    client: &mut ClientMachine,
    old_socket: UdpSocket,
    target: SocketAddr,
    manager: &CandidateManager,
    start: Instant,
) -> Result<UdpSocket, CliError> {
    let candidate_socket = UdpSocket::bind(options.candidate_bind).map_err(|_| CliError::Io)?;
    configure_df(&candidate_socket)?;
    let candidate_id = options.candidate.unwrap_or(random()?);
    let update = manager.propose_local(candidate_id, options.new, 1, 0, now_ms(start))?;
    let carrier = ObservedBinding::Udp(binding(target, random()?)?);
    let probe = manager.make_probe(candidate_id, carrier.clone(), random()?, now_ms(start))?;
    let update_bytes = update.encode()?;
    let probe_bytes = probe.encode()?;
    let old_socket = (options.mode == MoveMode::Mbb).then_some(old_socket);
    let update_socket = old_socket.as_ref().unwrap_or(&candidate_socket);
    send(
        update_socket,
        &client.send_data_with_locs(&update_bytes, options.old, options.peer_loc)?,
        target,
    )?;
    send(
        &candidate_socket,
        &client.send_data_with_locs(&probe_bytes, options.new, options.peer_loc)?,
        target,
    )?;
    let deadline = Instant::now() + options.timeout;
    let mut retry = Instant::now() + Duration::from_millis(400);
    while Instant::now() < deadline {
        match receive(
            &candidate_socket,
            match receive_timeout(retry.min(deadline), Duration::from_millis(400)) {
                Some(timeout) => timeout,
                None => continue,
            },
            options.budget,
        ) {
            Ok((packet, source)) if source == target => {
                let preview = match client.preview_data_with_locs(
                    &packet,
                    &[options.peer_loc],
                    &[options.new],
                ) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let plain = preview.plaintext().to_vec();
                let control = match Control::parse(&plain) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let transition =
                    match manager.preview(&plain, &carrier, now_ms(start) + 1, now_ms(start)) {
                        Ok(value) => value,
                        Err(_) => continue,
                    };
                let reply = manager.response_for(&transition)?;
                let session_error = RefCell::new(None);
                if manager
                    .commit(transition, || match client.commit_data(preview) {
                        Ok(_) => Ok(()),
                        Err(error) => {
                            *session_error.borrow_mut() = Some(error);
                            Err(MobilityError::Candidate)
                        }
                    })
                    .is_err()
                {
                    if let Some(error) = session_error.into_inner() {
                        return Err(error.into());
                    }
                    continue;
                }
                if let Some(reply) = reply {
                    send(
                        &candidate_socket,
                        &client.send_data_with_locs(
                            &reply.encode()?,
                            options.new,
                            options.peer_loc,
                        )?,
                        target,
                    )?;
                }
                for result in manager.take_results() {
                    send(
                        &candidate_socket,
                        &client.send_data_with_locs(
                            &result.encode()?,
                            options.new,
                            options.peer_loc,
                        )?,
                        target,
                    )?;
                }
                if matches!(control, Control::CandidateResult { result: 1, .. }) {
                    client.promote_local_loc(manager.local_loc());
                    return Ok(candidate_socket);
                }
            }
            Err(CliError::Session(SessionError::Timeout)) => {
                let update_packet =
                    client.send_data_with_locs(&update_bytes, options.old, options.peer_loc)?;
                send(
                    old_socket.as_ref().unwrap_or(&candidate_socket),
                    &update_packet,
                    target,
                )?;
                send(
                    &candidate_socket,
                    &client.send_data_with_locs(&probe_bytes, options.new, options.peer_loc)?,
                    target,
                )?;
                retry = Instant::now() + Duration::from_millis(400);
            }
            Err(CliError::Io) => return Err(CliError::Io),
            _ => {}
        }
    }
    Err(CliError::Session(SessionError::Timeout))
}
struct ClientResponderPath<'a> {
    client: &'a mut ClientMachine,
    socket: &'a UdpSocket,
    target: SocketAddr,
    manager: &'a CandidateManager,
    old_binding: ObservedBinding,
    selector: [u8; 16],
    start: Instant,
    cpu_before: Option<CpuUsage>,
}
struct ResponderCompletion {
    initial_echoed: bool,
    post_echoes: usize,
    pending_post_sequences: Vec<u64>,
}
impl ResponderCompletion {
    fn record_stream_send(&mut self, sequence: u64, promoted: bool) {
        if promoted {
            self.pending_post_sequences.push(sequence);
        }
    }
    fn record_stream_echo(&mut self, sequence: u64) {
        if let Some(index) = self
            .pending_post_sequences
            .iter()
            .position(|pending| *pending == sequence)
        {
            self.pending_post_sequences.swap_remove(index);
            self.post_echoes = self.post_echoes.saturating_add(1);
        }
    }
    fn complete(&self, expected: usize) -> bool {
        self.post_echoes >= expected
    }
}
fn connect_role1_responder(
    options: &Options,
    path: ClientResponderPath<'_>,
    mut plan: Option<StreamPlan>,
) -> Result<(), CliError> {
    let ClientResponderPath {
        client,
        socket,
        mut target,
        manager,
        old_binding,
        selector,
        start,
        cpu_before,
    } = path;
    let deadline = Instant::now() + options.timeout;
    let mut initial_sent = false;
    let mut post_sent = false;
    let mut completion = ResponderCompletion {
        initial_echoed: false,
        post_echoes: 0,
        pending_post_sequences: Vec::new(),
    };
    let mut promoted = false;

    loop {
        let now_ns = monotonic_ns()?;
        if !(Instant::now() < deadline
            || plan.as_ref().is_some_and(|stream| now_ns < stream.end_ns))
        {
            break;
        }
        if plan.as_ref().is_some_and(|stream| now_ns >= stream.end_ns)
            && promoted
            && completion.complete(options.expected_post_move)
        {
            finish_cpu(options, cpu_before)?;
            return Ok(());
        }
        if !promoted && Instant::now() >= deadline {
            return Err(CliError::Session(SessionError::Timeout));
        }
        manager.expire(now_ms(start));
        if let Some(stream) = plan.as_mut() {
            let due = stream
                .start_ns
                .saturating_add(stream.next_sequence.saturating_mul(stream.period_ns));
            if due < stream.end_ns && now_ns >= due {
                record(options.fds.scheduled, stream.next_sequence, due)?;
                if now_ns < due.saturating_add(stream.period_ns) {
                    let mut payload = [0; 64];
                    payload[..8].copy_from_slice(&stream.next_sequence.to_be_bytes());
                    record(options.fds.attempt, stream.next_sequence, now_ns)?;
                    let packet = client.send_data(&payload)?;
                    send(socket, &packet, target)?;
                    completion.record_stream_send(stream.next_sequence, promoted);
                    record(options.fds.sent, stream.next_sequence, monotonic_ns()?)?;
                }
                stream.next_sequence = stream.next_sequence.saturating_add(1);
                continue;
            }
        } else if !initial_sent {
            send(socket, &client.send_data(&options.message)?, target)?;
            initial_sent = true;
        } else if promoted && !post_sent {
            send(socket, &client.send_data(&options.message)?, target)?;
            post_sent = true;
        }

        let until = plan.as_ref().map_or(deadline, |stream| {
            deadline.min(
                Instant::now()
                    + Duration::from_nanos(
                        stream
                            .start_ns
                            .saturating_add(stream.next_sequence.saturating_mul(stream.period_ns))
                            .saturating_sub(now_ns),
                    ),
            )
        });
        let (packet, endpoint) = match receive(
            socket,
            match receive_timeout(until, Duration::from_millis(20)) {
                Some(timeout) => timeout,
                None => continue,
            },
            options.budget,
        ) {
            Ok(value) => value,
            Err(CliError::Session(SessionError::Timeout)) => continue,
            Err(error) => return Err(error),
        };
        let observed = ObservedBinding::Udp(binding(endpoint, selector)?);
        let preview = match client.preview_data_with_locs(
            &packet,
            &[options.peer_loc, options.new],
            &[options.old],
        ) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let plaintext = preview.plaintext().to_vec();
        if plaintext.starts_with(b"R8M1") {
            let header = match Header::unpack_with_budget(&packet, options.budget) {
                Ok((header, _)) => header,
                Err(_) => continue,
            };
            let control = match Control::parse(&plaintext) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let transition =
                match manager.preview(&plaintext, &observed, now_ms(start) + 1, now_ms(start)) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
            let reply = match manager.response_for(&transition) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let session_error = RefCell::new(None);
            if manager
                .commit(transition, || match client.commit_data(preview) {
                    Ok(_) => Ok(()),
                    Err(error) => {
                        *session_error.borrow_mut() = Some(error);
                        Err(MobilityError::Candidate)
                    }
                })
                .is_err()
            {
                if let Some(error) = session_error.into_inner() {
                    return Err(error.into());
                }
                continue;
            }
            if matches!(control, Control::BindResponse { .. })
                && manager.peer_loc() != options.peer_loc
            {
                client.promote_peer_loc(manager.peer_loc());
                target = endpoint;
                promoted = true;
            }
            if let Some(reply) = reply {
                send(
                    socket,
                    &client.send_data_with_locs(&reply.encode()?, options.old, header.src)?,
                    endpoint,
                )?;
            }
            for result in manager.take_results() {
                send(
                    socket,
                    &client.send_data_with_locs(
                        &result.encode()?,
                        options.old,
                        manager.peer_loc(),
                    )?,
                    endpoint,
                )?;
            }
            continue;
        }

        if !promoted && (endpoint != target || observed != old_binding) {
            continue;
        }
        if endpoint != target {
            continue;
        }
        let received = client.commit_data(preview)?;
        if plan.is_some() && received.len() == 64 {
            let sequence = u64::from_be_bytes(received[..8].try_into().map_err(|_| CliError::Io)?);
            record(options.fds.events, sequence, monotonic_ns()?)?;
            completion.record_stream_echo(sequence);
        } else if received == options.message {
            if !promoted {
                completion.initial_echoed = true;
            } else if post_sent {
                completion.post_echoes = completion.post_echoes.saturating_add(1);
            }
        }
        if plan.is_none()
            && completion.initial_echoed
            && promoted
            && completion.complete(options.expected_post_move)
        {
            finish_cpu(options, cpu_before)?;
            return Ok(());
        }
        if let Some(stream) = &plan {
            if monotonic_ns()? >= stream.end_ns
                && promoted
                && completion.complete(options.expected_post_move)
            {
                finish_cpu(options, cpu_before)?;
                return Ok(());
            }
        }
    }
    Err(CliError::Session(SessionError::Timeout))
}
fn connect(
    options: Options,
    signing: SigningKey,
    local: Identity,
    peer: Identity,
) -> Result<(), CliError> {
    let start = Instant::now();
    let target = options.peer.ok_or(CliError::Config)?;
    let (mut client, old_socket, id) = handshake(
        &options,
        signing.clone(),
        local.clone(),
        peer.clone(),
        start,
    )?;
    ready(options.fds.ready)?;
    let plan = read_stream_plan(&options)?;
    let cpu_before = (options.stream_rate != 0).then(cpu_usage).transpose()?;
    let selector = random()?;
    let carrier = ObservedBinding::Udp(binding(target, selector)?);
    let manager = CandidateManager::new(CandidateManagerConfig {
        signing,
        local,
        peer,
        profile: 0,
        scid: id,
        policy: Policy {
            policy_id: options.policy,
        },
        local_loc: options.old,
        peer_loc: options.peer_loc,
        initial_peer_binding: carrier.clone(),
        candidate_secret: options.secret.unwrap_or(random()?),
    })
    .map_err(|_| CliError::Config)?;
    if options.moving_role == MovingRole::Role2 {
        return connect_role1_responder(
            &options,
            ClientResponderPath {
                client: &mut client,
                socket: &old_socket,
                target,
                manager: &manager,
                old_binding: carrier,
                selector,
                start,
                cpu_before,
            },
            plan,
        );
    }
    if options.stream_rate == 0 {
        exchange(
            &mut client,
            &old_socket,
            target,
            &options.message,
            &options,
            false,
            options.timeout,
        )?;
        let candidate = move_client(&options, &mut client, old_socket, target, &manager, start)?;
        return exchange(
            &mut client,
            &candidate,
            target,
            &options.message,
            &options,
            false,
            options.timeout,
        );
    }
    let mut plan = plan.ok_or(CliError::Config)?;
    let mut old_socket = Some(old_socket);
    let mut candidate = None;
    while plan
        .start_ns
        .saturating_add(plan.next_sequence.saturating_mul(plan.period_ns))
        < plan.end_ns
    {
        let sequence = plan.next_sequence;
        let due = plan
            .start_ns
            .saturating_add(sequence.saturating_mul(plan.period_ns));
        record(options.fds.scheduled, sequence, due)?;
        while monotonic_ns()? < due {
            std::thread::sleep(Duration::from_micros(100));
        }
        if candidate.is_none() && monotonic_ns()? >= plan.cutover_ns {
            await_cutover_gate(&options, &plan)?;
            candidate = Some(move_client(
                &options,
                &mut client,
                old_socket
                    .take()
                    .ok_or(CliError::Session(SessionError::Timeout))?,
                target,
                &manager,
                start,
            )?);
        }
        let now = monotonic_ns()?;
        if now >= due.saturating_add(plan.period_ns) {
            plan.next_sequence = plan
                .next_sequence
                .saturating_add((now - due) / plan.period_ns);
            continue;
        }
        let mut payload = [0u8; 64];
        payload[..8].copy_from_slice(&sequence.to_be_bytes());
        let socket = candidate
            .as_ref()
            .or(old_socket.as_ref())
            .ok_or(CliError::Session(SessionError::Timeout))?;
        let result = exchange(
            &mut client,
            socket,
            target,
            &payload,
            &options,
            true,
            Duration::from_nanos(plan.period_ns),
        );
        match result {
            Ok(()) | Err(CliError::Session(SessionError::Timeout)) => {}
            Err(error) => return Err(error),
        }
        plan.next_sequence = plan.next_sequence.saturating_add(1);
    }
    if candidate.is_none() {
        let _ = move_client(
            &options,
            &mut client,
            old_socket
                .take()
                .ok_or(CliError::Session(SessionError::Timeout))?,
            target,
            &manager,
            start,
        )?;
    }
    wait_for_stream_end(plan.end_ns)?;
    finish_cpu(&options, cpu_before)?;
    Ok(())
}
struct Association {
    endpoint: SocketAddr,
    binding: ObservedBinding,
    manager: Option<CandidateManager>,
    proposals: Vec<[u8; 16]>,
    established: bool,
    promoted: bool,
    post: usize,
    cpu_before: Option<CpuUsage>,
    plan: Option<StreamPlan>,
}
struct ServerMoverPath<'a> {
    server: &'a mut ServerMachine,
    old_socket: &'a UdpSocket,
    scid: u64,
    target: SocketAddr,
    old_binding: ObservedBinding,
    manager: CandidateManager,
    selector: [u8; 16],
    start: Instant,
    plan: Option<StreamPlan>,
    cpu_before: Option<CpuUsage>,
}
fn serve_role2_mover(options: &Options, path: ServerMoverPath<'_>) -> Result<(), CliError> {
    let ServerMoverPath {
        server,
        old_socket,
        scid,
        mut target,
        old_binding,
        manager,
        selector,
        start,
        plan,
        cpu_before,
    } = path;
    if let Some(plan) = &plan {
        await_cutover_gate(options, plan)?;
    }
    let candidate_socket = UdpSocket::bind(options.candidate_bind).map_err(|_| CliError::Io)?;
    configure_df(&candidate_socket)?;
    let candidate_id = options.candidate.unwrap_or(random()?);
    let update = manager.propose_local(candidate_id, options.new, 1, 0, now_ms(start))?;
    let carrier = ObservedBinding::Udp(binding(target, selector)?);
    let probe = manager.make_probe(candidate_id, carrier, selector, now_ms(start))?;
    let update = update.encode()?;
    let probe = probe.encode()?;
    let deadline = Instant::now() + options.timeout;
    let mut retry = Instant::now();
    let mut promoted = false;
    let mut post = 0usize;

    loop {
        let now_ns = monotonic_ns()?;
        if !(Instant::now() < deadline
            || plan.as_ref().is_some_and(|stream| now_ns < stream.end_ns))
        {
            break;
        }
        if plan.as_ref().is_some_and(|stream| now_ns >= stream.end_ns)
            && promoted
            && post >= options.expected_post_move
        {
            finish_cpu(options, cpu_before)?;
            return Ok(());
        }
        let now = now_ms(start);
        manager.expire(now);
        if !promoted && Instant::now() >= deadline {
            return Err(CliError::Session(SessionError::Timeout));
        }
        if !promoted && Instant::now() >= retry {
            let update_socket = if options.mode == MoveMode::Mbb {
                old_socket
            } else {
                &candidate_socket
            };
            send(
                update_socket,
                &server.send_data_with_locs(scid, &update, options.old, options.peer_loc)?,
                target,
            )?;
            send(
                &candidate_socket,
                &server.send_data_with_locs(scid, &probe, options.new, options.peer_loc)?,
                target,
            )?;
            retry = Instant::now() + Duration::from_millis(400);
        }
        if promoted && options.mode == MoveMode::Mbb {
            match receive(old_socket, Duration::from_micros(1), options.budget) {
                Ok((packet, endpoint)) => {
                    let observed = ObservedBinding::Udp(binding(endpoint, selector)?);
                    if observed == old_binding && manager.binding_allowed_inbound(&observed, now) {
                        if let Ok(preview) = server.preview_data_with_locs(
                            &packet,
                            &[options.peer_loc],
                            &[options.old],
                            now,
                        ) {
                            let plain = preview.plaintext().to_vec();
                            if !plain.starts_with(b"R8M1") {
                                let payload = server.commit_data(preview, now)?;
                                let output = server.send_data(scid, &payload)?;
                                send(&candidate_socket, &output, target)?;
                            }
                        }
                    }
                }
                Err(CliError::Io) => return Err(CliError::Io),
                Err(_) => {}
            }
        }
        if plan.as_ref().is_some_and(|stream| now_ns >= stream.end_ns)
            && promoted
            && post >= options.expected_post_move
        {
            finish_cpu(options, cpu_before)?;
            return Ok(());
        }

        let (packet, endpoint) =
            match receive(&candidate_socket, Duration::from_millis(20), options.budget) {
                Ok(value) => value,
                Err(CliError::Session(SessionError::Timeout)) => {
                    if plan.as_ref().is_some_and(|stream| now_ns >= stream.end_ns)
                        && promoted
                        && post >= options.expected_post_move
                    {
                        finish_cpu(options, cpu_before)?;
                        return Ok(());
                    }
                    continue;
                }
                Err(error) => return Err(error),
            };
        let observed = ObservedBinding::Udp(binding(endpoint, selector)?);
        let preview = match server.preview_data_with_locs(
            &packet,
            &[options.peer_loc],
            &[options.new],
            now,
        ) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let plain = preview.plaintext().to_vec();
        if plain.starts_with(b"R8M1") {
            let control = match Control::parse(&plain) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let transition = match manager.preview(&plain, &observed, now + 1, now) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let reply = match manager.response_for(&transition) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let session_error = RefCell::new(None);
            if manager
                .commit(transition, || match server.commit_data(preview, now) {
                    Ok(_) => Ok(()),
                    Err(error) => {
                        *session_error.borrow_mut() = Some(error);
                        Err(MobilityError::Candidate)
                    }
                })
                .is_err()
            {
                let _ = session_error.into_inner();
                continue;
            }
            if let Some(reply) = reply {
                send(
                    &candidate_socket,
                    &server.send_data_with_locs(
                        scid,
                        &reply.encode()?,
                        options.new,
                        options.peer_loc,
                    )?,
                    endpoint,
                )?;
            }
            if matches!(control, Control::CandidateResult { result: 0, .. }) {
                continue;
            }
            if matches!(control, Control::CandidateResult { result: 1, .. }) {
                server.promote_local_loc(manager.local_loc());
                target = endpoint;
                promoted = true;
            }
            continue;
        }

        if !counts_post_move_packet(promoted, endpoint, target) {
            continue;
        }
        let payload = server.commit_data(preview, now)?;
        let output = server.send_data(scid, &payload)?;
        send(&candidate_socket, &output, target)?;
        post = post.saturating_add(1);
        if plan.is_none() && post >= options.expected_post_move {
            finish_cpu(options, cpu_before)?;
            return Ok(());
        }
        if let Some(stream) = &plan {
            if monotonic_ns()? >= stream.end_ns && promoted && post >= options.expected_post_move {
                finish_cpu(options, cpu_before)?;
                return Ok(());
            }
        }
    }
    if let Some(stream) = &plan {
        if monotonic_ns()? >= stream.end_ns && promoted && post >= options.expected_post_move {
            finish_cpu(options, cpu_before)?;
            return Ok(());
        }
    }
    let _ = old_binding;
    Err(CliError::Session(SessionError::Timeout))
}
fn serve(
    options: Options,
    signing: SigningKey,
    local: Identity,
    peer: Identity,
) -> Result<(), CliError> {
    let start = Instant::now();
    let socket = UdpSocket::bind(options.bind).map_err(|_| CliError::Io)?;
    configure_df(&socket)?;
    let selector = random()?;
    let mut server = ServerMachine::new(
        config(local.clone(), peer.clone(), &options),
        signing.clone(),
        ServerMaterial {
            boot_instance: random()?,
            current_cookie_key: random()?,
            previous_cookie_key: random()?,
            previous_key_rotated_ms: 0,
        },
    )?;
    let mut limiter = PrevalidationLimiter::new();
    let source_key = random()?;
    let mut associations: HashMap<u64, Association> = HashMap::new();
    let deadline = Instant::now() + options.timeout;
    let mut complete = 0usize;
    loop {
        let stream_end = associations
            .values()
            .find_map(|association| association.plan.as_ref().map(|plan| plan.end_ns));
        let now_ns = monotonic_ns()?;
        if server_complete(complete, options.max_sessions, stream_end, now_ns)
            || stream_end.is_some_and(|end_ns| now_ns >= end_ns)
            || (stream_end.is_none() && Instant::now() >= deadline)
        {
            break;
        }
        let cap = stream_end
            .map(|end_ns| Duration::from_nanos(end_ns.saturating_sub(now_ns)))
            .unwrap_or(options.timeout);
        let receive_timeout = match receive_timeout(
            if stream_end.is_some() {
                Instant::now() + cap
            } else {
                deadline
            },
            cap,
        ) {
            Some(timeout) => timeout,
            None => continue,
        };
        let (packet, endpoint) = match receive(&socket, receive_timeout, options.budget) {
            Ok(value) => value,
            Err(CliError::Session(SessionError::Timeout)) => break,
            Err(CliError::Io) => return Err(CliError::Io),
            Err(_) => continue,
        };
        let observed = ObservedBinding::Udp(binding(endpoint, selector)?);
        let (header, payload) = match Header::unpack_with_budget(&packet, options.budget) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let typ = match r8_session::SessionMessage::decode(payload, 0, options.budget) {
            Ok(message) => message.typ,
            Err(_) => continue,
        };
        let now = now_ms(start);
        let output = match typ {
            1 => server.receive_open_limited(
                &packet,
                match &observed {
                    ObservedBinding::Udp(value) => value,
                    _ => unreachable!(),
                },
                opaque_source(endpoint, &source_key),
                now,
                now / 10_000,
                &mut limiter,
            ),
            3 => {
                let output = match server.receive_open_auth(
                    &packet,
                    match &observed {
                        ObservedBinding::Udp(value) => value,
                        _ => unreachable!(),
                    },
                    now,
                    now / 10_000,
                    Some(ServerHandshakeMaterial {
                        ephemeral_secret: random()?,
                        nonce: random()?,
                    }),
                ) {
                    Ok(output) => output,
                    Err(_) => continue,
                };
                associations.entry(header.scid).or_insert(Association {
                    endpoint,
                    binding: observed.clone(),
                    manager: None,
                    proposals: Vec::new(),
                    established: false,
                    promoted: false,
                    post: 0,
                    cpu_before: None,
                    plan: None,
                });
                Ok(output)
            }
            5 => {
                let record = match associations.get_mut(&header.scid) {
                    Some(record) => record,
                    None => continue,
                };
                if record.endpoint != endpoint || record.binding != observed {
                    continue;
                }
                if server.receive_accept(&packet, now).is_err() {
                    continue;
                }
                if !record.established {
                    ready(options.fds.ready)?;
                    if options.stream_rate != 0 {
                        record.plan = read_stream_plan(&options)?;
                        record.cpu_before = Some(cpu_usage()?);
                    }
                }
                record.established = true;
                continue;
            }
            6 => {
                let record = match associations.get_mut(&header.scid) {
                    Some(value) if value.established => value,
                    _ => continue,
                };
                let initial = record.manager.is_none();
                if initial && (record.endpoint != endpoint || record.binding != observed) {
                    continue;
                }
                let mut allowed = Vec::new();
                if !initial {
                    let manager = record
                        .manager
                        .as_ref()
                        .ok_or(CliError::Session(SessionError::AuthFailed))?;
                    manager.expire(now);
                    let old_binding = observed != record.binding
                        && manager.binding_allowed_inbound(&observed, now);
                    if record.promoted && observed != record.binding && !old_binding {
                        continue;
                    }
                    allowed.extend_from_slice(&record.proposals);
                    if record.promoted && old_binding {
                        allowed.push(options.peer_loc);
                    }
                }
                let preview = match server.preview_data_with_locs(&packet, &allowed, &[], now) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let plain = preview.plaintext().to_vec();
                if initial {
                    record.manager = Some(
                        CandidateManager::new(CandidateManagerConfig {
                            signing: signing.clone(),
                            local: local.clone(),
                            peer: peer.clone(),
                            profile: 0,
                            scid: header.scid,
                            policy: Policy {
                                policy_id: options.policy,
                            },
                            local_loc: options.old,
                            peer_loc: options.peer_loc,
                            initial_peer_binding: record.binding.clone(),
                            candidate_secret: options.secret.unwrap_or(random()?),
                        })
                        .map_err(|_| CliError::Config)?,
                    );
                }
                if plain.starts_with(b"R8M1") {
                    let control = match Control::parse(&plain) {
                        Ok(value) => value,
                        Err(_) => continue,
                    };
                    let manager = record
                        .manager
                        .as_ref()
                        .ok_or(CliError::Session(SessionError::AuthFailed))?;
                    let transition = match manager.preview(&plain, &observed, now + 1, now) {
                        Ok(value) => value,
                        Err(_) => continue,
                    };
                    let reply = match manager.response_for(&transition) {
                        Ok(reply) => reply,
                        Err(_) => continue,
                    };
                    let session_error = RefCell::new(None);
                    if manager
                        .commit(transition, || match server.commit_data(preview, now) {
                            Ok(_) => Ok(()),
                            Err(error) => {
                                *session_error.borrow_mut() = Some(error);
                                Err(MobilityError::Candidate)
                            }
                        })
                        .is_err()
                    {
                        let _ = session_error.into_inner();
                        continue;
                    }
                    if let Control::LocUpdate { new_loc, .. } = control {
                        if !record.proposals.contains(&new_loc) {
                            record.proposals.push(new_loc);
                        }
                    }
                    if let Some(reply) = reply {
                        send(
                            &socket,
                            &server.send_data_with_locs(
                                header.scid,
                                &reply.encode()?,
                                options.old,
                                header.src,
                            )?,
                            endpoint,
                        )?;
                    }
                    for result in manager.take_results() {
                        send(
                            &socket,
                            &server.send_data_with_locs(
                                header.scid,
                                &result.encode()?,
                                options.old,
                                manager.peer_loc(),
                            )?,
                            endpoint,
                        )?;
                    }
                    if manager.peer_loc() != options.peer_loc {
                        server.promote_peer_loc(manager.peer_loc());
                        record.endpoint = endpoint;
                        record.binding = observed;
                        record.promoted = true;
                    }
                    continue;
                }
                if !initial
                    && !record.promoted
                    && (record.endpoint != endpoint || record.binding != observed)
                {
                    continue;
                }
                if server.commit_data(preview, now).is_err() {
                    continue;
                }
                if counts_post_move_packet(record.promoted, endpoint, record.endpoint) {
                    record.post += 1;
                    if record.post == options.expected_post_move {
                        complete += 1;
                    }
                }
                let reply_endpoint = record.endpoint;
                let output = server.send_data(header.scid, &plain)?;
                send(&socket, &output, reply_endpoint)?;
                if initial && options.moving_role == MovingRole::Role2 {
                    let manager = record
                        .manager
                        .take()
                        .ok_or(CliError::Session(SessionError::AuthFailed))?;
                    let old_binding = record.binding.clone();
                    let old_endpoint = record.endpoint;
                    let plan = record.plan.take();
                    let cpu_before = record.cpu_before.take();
                    return serve_role2_mover(
                        &options,
                        ServerMoverPath {
                            server: &mut server,
                            old_socket: &socket,
                            scid: header.scid,
                            target: old_endpoint,
                            old_binding,
                            manager,
                            selector,
                            start,
                            plan,
                            cpu_before,
                        },
                    );
                }
                continue;
            }
            _ => continue,
        };
        if let Ok(output) = output {
            send(&socket, &output, endpoint)?;
        }
    }
    if complete == options.max_sessions {
        if options.stream_rate != 0 {
            let before = associations
                .values()
                .find_map(|association| association.cpu_before)
                .ok_or(CliError::Session(SessionError::AuthFailed))?;
            finish_cpu(&options, Some(before))?;
        }
        Ok(())
    } else {
        Err(CliError::Session(SessionError::Timeout))
    }
}
fn main() -> ExitCode {
    let result = options().and_then(|options| {
        let (signing, local, peer) = identities(&options)?;
        match options.command {
            Command::Connect => connect(options, signing, local, peer),
            Command::Serve => serve(options, signing, local, peer),
        }
    });
    match result {
        Ok(()) => {
            println!("[r8move] complete");
            ExitCode::SUCCESS
        }
        Err(CliError::Config) => {
            eprintln!("[r8move] error CONFIG");
            ExitCode::from(1)
        }
        Err(error) => {
            eprintln!("[r8move] error {}", error.as_str());
            ExitCode::from(1)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::{
        classify_send_result, counts_post_move_packet, cpu_record, server_complete,
        wait_for_stream_end, CliError, CpuUsage, ResponderCompletion,
    };
    use super::{validate_args, Command};
    use std::net::SocketAddr;

    #[test]
    fn post_stream_echoes_require_a_sent_sequence() {
        let mut completion = ResponderCompletion {
            initial_echoed: false,
            post_echoes: 0,
            pending_post_sequences: Vec::new(),
        };
        completion.record_stream_echo(7);
        assert_eq!(completion.post_echoes, 0);
        completion.record_stream_send(7, true);
        completion.record_stream_echo(7);
        assert!(completion.complete(1));
    }

    #[test]
    fn pre_promotion_stream_send_is_not_post_move_work() {
        let mut completion = ResponderCompletion {
            initial_echoed: false,
            post_echoes: 0,
            pending_post_sequences: Vec::new(),
        };
        completion.record_stream_send(3, false);
        completion.record_stream_echo(3);
        assert!(!completion.complete(1));
    }
    #[test]
    fn send_classifier_redacts_transport_errors() {
        for error in [libc::EACCES, libc::ENETUNREACH] {
            assert_eq!(
                classify_send_result(Err(std::io::Error::from_raw_os_error(error)), 12)
                    .unwrap_err()
                    .as_str(),
                "IO"
            );
        }
        assert_eq!(
            classify_send_result(Err(std::io::Error::from_raw_os_error(libc::EMSGSIZE)), 12)
                .unwrap_err()
                .as_str(),
            "BUDGET"
        );
        assert_eq!(classify_send_result(Ok(11), 12).unwrap_err().as_str(), "IO");
    }

    #[test]
    fn send_classifier_is_direction_independent() {
        let client = classify_send_result(Ok(7), 8).unwrap_err();
        let server = classify_send_result(Ok(7), 8).unwrap_err();
        assert_eq!(client.as_str(), server.as_str());
        assert_eq!(client.as_str(), CliError::Io.as_str());
    }
    #[test]
    fn scheduled_fd_is_accepted_by_strict_cli_validation() {
        let args = vec![
            "r8-mobility".to_owned(),
            "connect".to_owned(),
            "--scheduled-fd".to_owned(),
            "7".to_owned(),
        ];
        assert!(validate_args(&args, Command::Connect).is_ok());
    }
    #[test]
    fn stream_server_completion_waits_for_authoritative_end() {
        assert!(!server_complete(1, 1, Some(20), 19));
        assert!(server_complete(1, 1, Some(20), 20));
        assert!(server_complete(1, 1, None, 0));
    }

    #[test]
    fn cpu_record_has_six_network_order_words() {
        let record = cpu_record(
            CpuUsage {
                timestamp_ns: 1,
                user_ns: 2,
                system_ns: 3,
            },
            CpuUsage {
                timestamp_ns: 4,
                user_ns: 5,
                system_ns: 6,
            },
        );
        assert_eq!(record.len(), 48);
        assert_eq!(record[24..32], 4u64.to_be_bytes());
        assert_eq!(record[40..], 6u64.to_be_bytes());
    }
    #[test]
    fn old_grace_packet_never_counts_as_post_move() {
        let old: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let candidate: SocketAddr = "127.0.0.1:2".parse().unwrap();
        assert!(!counts_post_move_packet(true, old, candidate));
        assert!(counts_post_move_packet(true, candidate, candidate));
    }
    #[test]
    fn stream_end_wait_returns_after_a_past_deadline() {
        assert!(wait_for_stream_end(0).is_ok());
    }
}
