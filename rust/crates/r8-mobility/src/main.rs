//! Native closed-lab R8 protected-mobility UDP endpoint.
use std::{
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
    stream_rate: u64,
    stream_start_ns: u64,
    stream_cutover_ns: u64,
    stream_end_ns: u64,
    events_fd: Option<i32>,
    max_sessions: usize,
    expected_post_move: usize,
}

fn err<T>() -> Result<T, SessionError> {
    Err(SessionError::ConfigError)
}
fn hex(text: &str) -> Result<Vec<u8>, SessionError> {
    if !text.len().is_multiple_of(2) {
        return err();
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| SessionError::ConfigError))
        .collect()
}
fn fixed<const N: usize>(text: &str) -> Result<[u8; N], SessionError> {
    hex(text)?.try_into().map_err(|_| SessionError::ConfigError)
}
fn value(args: &[String], flag: &str) -> Result<String, SessionError> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
        .ok_or(SessionError::ConfigError)
}
fn optional(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
}
fn number<T: std::str::FromStr>(args: &[String], flag: &str) -> Result<T, SessionError> {
    value(args, flag)?
        .parse()
        .map_err(|_| SessionError::ConfigError)
}
fn loc(args: &[String], flag: &str) -> Result<[u8; 16], SessionError> {
    parse_loc(&value(args, flag)?).map_err(|_| SessionError::ConfigError)
}
fn endpoint(args: &[String], flag: &str, default: &str) -> Result<SocketAddr, SessionError> {
    optional(args, flag)
        .unwrap_or_else(|| default.to_owned())
        .parse()
        .map_err(|_| SessionError::ConfigError)
}
fn allowed_underlay(address: SocketAddr, isolated: bool) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => ip.is_loopback() || (isolated && (ip.is_private() || ip.is_link_local())),
        IpAddr::V6(ip) => ip.is_loopback() || (isolated && ip.is_unicast_link_local()),
    }
}
fn options() -> Result<Options, SessionError> {
    let args: Vec<String> = env::args().collect();
    let command = match args.get(1).map(String::as_str) {
        Some("serve") => Command::Serve,
        Some("connect") => Command::Connect,
        _ => return err(),
    };
    let isolated = args.iter().any(|arg| arg == "--allow-isolated-underlay");
    let budget = optional(&args, "--binding-budget")
        .map(|v| v.parse().map_err(|_| SessionError::ConfigError))
        .transpose()?
        .unwrap_or(BUDGET);
    let timeout = optional(&args, "--timeout")
        .map(|v| v.parse::<f64>().map_err(|_| SessionError::ConfigError))
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
                .map_err(|_| SessionError::ConfigError)?,
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
        .map_err(|_| SessionError::ConfigError)?
        .unwrap_or(1);
    let max_sessions = optional(&args, "--max-sessions")
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| SessionError::ConfigError)?
        .unwrap_or(1);
    let expected_post_move = optional(&args, "--expected-post-move")
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| SessionError::ConfigError)?
        .unwrap_or(1);
    let stream_rate = optional(&args, "--stream-rate")
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| SessionError::ConfigError)?
        .unwrap_or(0);
    let stream_start_ns = optional(&args, "--stream-start-ns")
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| SessionError::ConfigError)?
        .unwrap_or(0);
    let stream_cutover_ns = optional(&args, "--stream-cutover-ns")
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| SessionError::ConfigError)?
        .unwrap_or(0);
    let stream_end_ns = optional(&args, "--stream-end-ns")
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| SessionError::ConfigError)?
        .unwrap_or(0);
    let events_fd = optional(&args, "--events-fd")
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| SessionError::ConfigError)?;
    if service == 0
        || server_context == 0
        || max_sessions == 0
        || expected_post_move == 0
        || (stream_rate != 0
            && (stream_start_ns == 0
                || stream_start_ns > stream_cutover_ns
                || stream_cutover_ns >= stream_end_ns))
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
        .map_err(|_| SessionError::ConfigError)?;
    if scid == Some(0) {
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
        stream_rate,
        stream_start_ns,
        stream_cutover_ns,
        stream_end_ns,
        events_fd,
        max_sessions,
        expected_post_move,
    })
}
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
fn configure_df(socket: &UdpSocket) -> Result<(), SessionError> {
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
            return err();
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = socket;
    Ok(())
}
fn random<const N: usize>() -> Result<[u8; N], SessionError> {
    let mut out = [0; N];
    getrandom(&mut out).map_err(|_| SessionError::RngFailure)?;
    Ok(out)
}
fn scid() -> Result<u64, SessionError> {
    loop {
        let value = u64::from_be_bytes(random()?);
        if value != 0 {
            return Ok(value);
        }
    }
}
fn binding(endpoint: SocketAddr, selector: [u8; 16]) -> Result<UdpBinding, SessionError> {
    match endpoint.ip() {
        IpAddr::V4(ip) => UdpBinding::ipv4(ip.octets(), endpoint.port(), 1, selector),
        IpAddr::V6(ip) => UdpBinding::ipv6(ip.octets(), endpoint.port(), 1, selector),
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
fn send(socket: &UdpSocket, packet: &[u8], peer: SocketAddr) -> Result<(), SessionError> {
    if packet.len() > BUDGET {
        return Err(SessionError::Budget);
    }
    match socket.send_to(packet, peer) {
        Ok(written) if written == packet.len() => Ok(()),
        Ok(_) => Err(SessionError::Budget),
        Err(error) if error.raw_os_error() == Some(libc::EMSGSIZE) => Err(SessionError::Budget),
        Err(_) => Err(SessionError::AuthFailed),
    }
}
fn receive(
    socket: &UdpSocket,
    timeout: Duration,
    budget: usize,
) -> Result<(Vec<u8>, SocketAddr), SessionError> {
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|_| SessionError::ConfigError)?;
    let mut buffer = vec![0; budget.checked_add(RECV_EXTRA).ok_or(SessionError::Budget)?];
    match socket.recv_from(&mut buffer) {
        Ok((length, peer)) if length <= budget => {
            buffer.truncate(length);
            Ok((buffer, peer))
        }
        Ok(_) => Err(SessionError::Budget),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Err(SessionError::Timeout)
        }
        Err(_) => Err(SessionError::AuthFailed),
    }
}
fn now_ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}
fn monotonic_ns() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) };
    if result == 0 {
        (value.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(value.tv_nsec as u64)
    } else {
        0
    }
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
fn identities(options: &Options) -> Result<(SigningKey, Identity, Identity), SessionError> {
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
fn map_mobility(_: SessionError) -> MobilityError {
    MobilityError::Replay
}
fn handshake(
    options: &Options,
    signing: SigningKey,
    local: Identity,
    peer: Identity,
    start: Instant,
) -> Result<(ClientMachine, UdpSocket, u64), SessionError> {
    let target = options.peer.ok_or(SessionError::ConfigError)?;
    let mut client = ClientMachine::new(config(local, peer, options), signing)?;
    let socket = UdpSocket::bind(options.bind).map_err(|_| SessionError::ConfigError)?;
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
            Duration::from_millis(500).min(deadline.saturating_duration_since(Instant::now())),
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
            Err(SessionError::Timeout) => continue,
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
        Err(SessionError::Timeout)
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
) -> Result<(), SessionError> {
    send(socket, &client.send_data(payload)?, target)?;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let (packet, source) = receive(
            socket,
            deadline.saturating_duration_since(Instant::now()),
            options.budget,
        )?;
        if source != target {
            continue;
        }
        if client.receive_data(&packet)? == payload {
            if event && payload.len() == 64 {
                if let Some(fd) = options.events_fd {
                    let sequence = u64::from_be_bytes(
                        payload[..8]
                            .try_into()
                            .map_err(|_| SessionError::AuthFailed)?,
                    );
                    let mut record = [0u8; 16];
                    record[..8].copy_from_slice(&sequence.to_be_bytes());
                    record[8..].copy_from_slice(&monotonic_ns().to_be_bytes());
                    let written = unsafe { libc::write(fd, record.as_ptr().cast(), record.len()) };
                    if written != record.len() as isize {
                        return Err(SessionError::AuthFailed);
                    }
                }
            }
            return Ok(());
        }
    }
    Err(SessionError::Timeout)
}
fn move_client(
    options: &Options,
    client: &mut ClientMachine,
    old_socket: UdpSocket,
    target: SocketAddr,
    manager: &CandidateManager,
    start: Instant,
) -> Result<UdpSocket, SessionError> {
    let candidate_socket =
        UdpSocket::bind(options.candidate_bind).map_err(|_| SessionError::ConfigError)?;
    configure_df(&candidate_socket)?;
    let candidate_id = options.candidate.unwrap_or(random()?);
    let update = manager
        .propose_local(candidate_id, options.new, 1, 0, now_ms(start))
        .map_err(|_| SessionError::AuthFailed)?;
    let carrier =
        ObservedBinding::Udp(binding(target, random()?).map_err(|_| SessionError::AuthFailed)?);
    let probe = manager
        .make_probe(candidate_id, carrier.clone(), random()?, now_ms(start))
        .map_err(|_| SessionError::AuthFailed)?;
    let update_bytes = update.encode().map_err(|_| SessionError::AuthFailed)?;
    let probe_bytes = probe.encode().map_err(|_| SessionError::AuthFailed)?;
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
            retry
                .min(deadline)
                .saturating_duration_since(Instant::now()),
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
                let reply = manager
                    .response_for(&transition)
                    .map_err(|_| SessionError::AuthFailed)?;
                if manager
                    .commit(
                        transition,
                        || {
                            client
                                .commit_data(preview)
                                .map(|_| ())
                                .map_err(map_mobility)
                        },
                        || {},
                    )
                    .is_err()
                {
                    continue;
                }
                if let Some(reply) = reply {
                    send(
                        &candidate_socket,
                        &client.send_data_with_locs(
                            &reply.encode().map_err(|_| SessionError::AuthFailed)?,
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
                            &result.encode().map_err(|_| SessionError::AuthFailed)?,
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
            Err(SessionError::Timeout) => {
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
            _ => {}
        }
    }
    Err(SessionError::Timeout)
}
fn connect(
    options: Options,
    signing: SigningKey,
    local: Identity,
    peer: Identity,
) -> Result<(), SessionError> {
    let start = Instant::now();
    let target = options.peer.ok_or(SessionError::ConfigError)?;
    let (mut client, old_socket, id) = handshake(
        &options,
        signing.clone(),
        local.clone(),
        peer.clone(),
        start,
    )?;
    let carrier =
        ObservedBinding::Udp(binding(target, random()?).map_err(|_| SessionError::AuthFailed)?);
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
        initial_peer_binding: carrier,
        candidate_secret: options.secret.unwrap_or(random()?),
    })
    .map_err(|_| SessionError::ConfigError)?;
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
    let period = 1_000_000_000 / options.stream_rate;
    if period == 0 {
        return Err(SessionError::ConfigError);
    }
    let mut sequence = 0u64;
    let mut old_socket = Some(old_socket);
    let mut candidate = None;
    while options
        .stream_start_ns
        .saturating_add(sequence.saturating_mul(period))
        < options.stream_end_ns
    {
        let due = options
            .stream_start_ns
            .saturating_add(sequence.saturating_mul(period));
        while monotonic_ns() < due {
            std::thread::sleep(Duration::from_micros(100));
        }
        if candidate.is_none() && monotonic_ns() >= options.stream_cutover_ns {
            candidate = Some(move_client(
                &options,
                &mut client,
                old_socket.take().ok_or(SessionError::Timeout)?,
                target,
                &manager,
                start,
            )?);
        }
        let now = monotonic_ns();
        if now >= due.saturating_add(period) {
            sequence = sequence.saturating_add((now - due) / period);
            continue;
        }
        let mut payload = [0u8; 64];
        payload[..8].copy_from_slice(&sequence.to_be_bytes());
        let socket = candidate
            .as_ref()
            .or(old_socket.as_ref())
            .ok_or(SessionError::Timeout)?;
        let _ = exchange(
            &mut client,
            socket,
            target,
            &payload,
            &options,
            true,
            Duration::from_nanos(period),
        );
        sequence = sequence.saturating_add(1);
    }
    if candidate.is_none() {
        let _ = move_client(
            &options,
            &mut client,
            old_socket.take().ok_or(SessionError::Timeout)?,
            target,
            &manager,
            start,
        )?;
    }
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
}
fn serve(
    options: Options,
    signing: SigningKey,
    local: Identity,
    peer: Identity,
) -> Result<(), SessionError> {
    let start = Instant::now();
    let socket = UdpSocket::bind(options.bind).map_err(|_| SessionError::ConfigError)?;
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
    let deadline = if options.stream_rate == 0 {
        Instant::now() + options.timeout
    } else {
        let until = options
            .stream_end_ns
            .saturating_add(options.timeout.as_nanos().min(u128::from(u64::MAX)) as u64)
            .saturating_sub(monotonic_ns());
        Instant::now() + Duration::from_nanos(until)
    };
    let mut complete = 0usize;
    while Instant::now() < deadline
        && (complete < options.max_sessions
            || (options.stream_rate != 0 && monotonic_ns() < options.stream_end_ns))
    {
        let receive_timeout = if options.stream_rate == 0 {
            deadline.saturating_duration_since(Instant::now())
        } else {
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_nanos(
                    options.stream_end_ns.saturating_sub(monotonic_ns()),
                ))
        };
        let (packet, endpoint) = match receive(&socket, receive_timeout, options.budget) {
            Ok(value) => value,
            Err(SessionError::Timeout) => break,
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
                let output = server.receive_open_auth(
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
                )?;
                associations.entry(header.scid).or_insert(Association {
                    endpoint,
                    binding: observed.clone(),
                    manager: None,
                    proposals: Vec::new(),
                    established: false,
                    promoted: false,
                    post: 0,
                });
                Ok(output)
            }
            5 => {
                let record = associations
                    .get_mut(&header.scid)
                    .ok_or(SessionError::AuthFailed)?;
                if record.endpoint != endpoint || record.binding != observed {
                    continue;
                }
                server.receive_accept(&packet, now)?;
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
                    let manager = record.manager.as_ref().ok_or(SessionError::AuthFailed)?;
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
                let preview = match server.preview_data_with_locs(&packet, &allowed, &[]) {
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
                        .map_err(|_| SessionError::ConfigError)?,
                    );
                }
                if plain.starts_with(b"R8M1") {
                    let control = match Control::parse(&plain) {
                        Ok(value) => value,
                        Err(_) => continue,
                    };
                    let manager = record.manager.as_ref().ok_or(SessionError::AuthFailed)?;
                    let transition = match manager.preview(&plain, &observed, now + 1, now) {
                        Ok(value) => value,
                        Err(_) => continue,
                    };
                    let reply = manager
                        .response_for(&transition)
                        .map_err(|_| SessionError::AuthFailed)?;
                    if manager
                        .commit(
                            transition,
                            || {
                                server
                                    .commit_data(preview, now)
                                    .map(|_| ())
                                    .map_err(map_mobility)
                            },
                            || {},
                        )
                        .is_err()
                    {
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
                                &reply.encode().map_err(|_| SessionError::AuthFailed)?,
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
                                &result.encode().map_err(|_| SessionError::AuthFailed)?,
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
                server.commit_data(preview, now)?;
                if record.promoted {
                    record.post += 1;
                    if record.post == options.expected_post_move {
                        complete += 1;
                    }
                }
                let reply_endpoint = record.endpoint;
                let output = server.send_data(header.scid, &plain)?;
                send(&socket, &output, reply_endpoint)?;
                continue;
            }
            _ => continue,
        };
        if let Ok(output) = output {
            send(&socket, &output, endpoint)?;
        }
    }
    if complete == options.max_sessions {
        Ok(())
    } else {
        Err(SessionError::Timeout)
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
        Err(SessionError::ConfigError) => {
            eprintln!("[r8move] error USAGE");
            ExitCode::from(1)
        }
        Err(error) => {
            eprintln!("[r8move] error {}", error.as_str());
            ExitCode::from(1)
        }
    }
}
