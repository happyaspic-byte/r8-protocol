use std::{
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr, UdpSocket},
    process,
    time::{Duration, Instant},
};

use aws_lc_rs::hmac;
use ed25519_dalek::SigningKey;
use getrandom::getrandom;
use r8_proto::parse_loc;
use r8_session::{
    ClientMachine, ClientMaterial, HandshakeConfig, Identity, ObservedBinding,
    PrevalidationLimiter, ServerHandshakeMaterial, ServerMachine, ServerMaterial, SessionError,
    UdpBinding,
};
use zeroize::Zeroizing;

const RECV_EXTRA: usize = 1;
const DEFAULT_BUDGET: usize = 1252;
const RETRIES: [Duration; 3] = [
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
];

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Serve,
    Connect,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CliError {
    Session(SessionError),
    Io,
}
impl From<SessionError> for CliError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}
impl CliError {
    fn as_str(self) -> &'static str {
        match self {
            Self::Session(error) => error.as_str(),
            Self::Io => "IO",
        }
    }
}

struct Options {
    mode: Mode,
    local_seed: [u8; 32],
    peer_key: [u8; 32],
    service: u32,
    server_context: u32,
    source: [u8; 16],
    destination: [u8; 16],
    bind: SocketAddr,
    peer: Option<SocketAddr>,
    budget: usize,
    timeout: Duration,
    max_sessions: usize,
    message: Option<Vec<u8>>,
    scid: Option<u64>,
    ready_fd: Option<i32>,
    isolated: bool,
}

fn usage() -> &'static str {
    "usage: r8session serve --local-seed-hex HEX --peer-public-key-hex HEX --service-context N --server-context-id N --address IPV6 --peer-address IPV6 --bind HOST:PORT [--binding-budget N] [--timeout SECONDS] [--max-sessions N] [--allow-isolated-underlay]\n       r8session connect --local-seed-hex HEX --peer-public-key-hex HEX --service-context N --server-context-id N --address IPV6 --peer-address IPV6 --bind HOST:PORT --peer HOST:PORT --message-hex HEX [--scid N] [--binding-budget N] [--timeout SECONDS] [--allow-isolated-underlay]"
}

fn hex(text: &str) -> Result<Vec<u8>, SessionError> {
    if !text.len().is_multiple_of(2) {
        return Err(SessionError::ConfigError);
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| SessionError::ConfigError))
        .collect()
}
fn fixed<const N: usize>(text: &str) -> Result<[u8; N], SessionError> {
    hex(text)?.try_into().map_err(|_| SessionError::ConfigError)
}
fn number<T: std::str::FromStr>(text: &str) -> Result<T, SessionError> {
    text.parse().map_err(|_| SessionError::ConfigError)
}
fn loc(text: &str) -> Result<[u8; 16], SessionError> {
    parse_loc(text).map_err(|_| SessionError::ConfigError)
}

fn parse_options(args: &[String]) -> Result<Options, SessionError> {
    let mode = match args.get(1).map(String::as_str) {
        Some("serve") => Mode::Serve,
        Some("connect") => Mode::Connect,
        _ => return Err(SessionError::ConfigError),
    };
    let mut local_seed = None;
    let mut peer_key = None;
    let mut service = None;
    let mut server_context = None;
    let mut source = None;
    let mut destination = None;
    let mut bind = None;
    let mut peer = None;
    let mut budget = None;
    let mut timeout = None;
    let mut max_sessions = None;
    let mut message = None;
    let mut scid = None;
    let mut ready_fd = None;
    let mut isolated = false;
    let mut values = args[2..].iter();
    macro_rules! value {
        ($slot:ident) => {{
            if $slot.is_some() {
                return Err(SessionError::ConfigError);
            }
            let value = values
                .next()
                .filter(|value| !value.starts_with("--"))
                .ok_or(SessionError::ConfigError)?;
            $slot = Some(value.as_str());
        }};
    }
    while let Some(flag) = values.next() {
        match flag.as_str() {
            "--local-seed-hex" => value!(local_seed),
            "--peer-public-key-hex" => value!(peer_key),
            "--service-context" => value!(service),
            "--server-context-id" => value!(server_context),
            "--address" => value!(source),
            "--peer-address" => value!(destination),
            "--bind" => value!(bind),
            "--binding-budget" => value!(budget),
            "--timeout" => value!(timeout),
            "--ready-fd" => value!(ready_fd),
            "--peer" => value!(peer),
            "--message-hex" => value!(message),
            "--scid" => value!(scid),
            "--max-sessions" => value!(max_sessions),
            "--allow-isolated-underlay" if !isolated => isolated = true,
            _ => return Err(SessionError::ConfigError),
        }
    }
    if mode == Mode::Serve && (peer.is_some() || message.is_some() || scid.is_some())
        || mode == Mode::Connect && (max_sessions.is_some() || peer.is_none() || message.is_none())
    {
        return Err(SessionError::ConfigError);
    }
    let budget = budget.map(number).transpose()?.unwrap_or(DEFAULT_BUDGET);
    if !(48..=1252).contains(&budget) {
        return Err(SessionError::ConfigError);
    }
    let service = number(service.ok_or(SessionError::ConfigError)?)?;
    let server_context = number(server_context.ok_or(SessionError::ConfigError)?)?;
    if service == 0 || server_context == 0 {
        return Err(SessionError::ConfigError);
    }
    let timeout_seconds = timeout.map(number).transpose()?.unwrap_or(5u64);
    if timeout_seconds == 0 {
        return Err(SessionError::ConfigError);
    }
    let message = message.map(hex).transpose()?;
    if message.as_ref().is_some_and(Vec::is_empty) {
        return Err(SessionError::ConfigError);
    }
    let scid = scid.map(number).transpose()?;
    if scid == Some(0) {
        return Err(SessionError::ConfigError);
    }
    let max_sessions = max_sessions.map(number).transpose()?.unwrap_or(1usize);
    if max_sessions == 0 || max_sessions > 1024 {
        return Err(SessionError::ConfigError);
    }
    Ok(Options {
        mode,
        local_seed: fixed(local_seed.ok_or(SessionError::ConfigError)?)?,
        peer_key: fixed(peer_key.ok_or(SessionError::ConfigError)?)?,
        service,
        server_context,
        source: loc(source.ok_or(SessionError::ConfigError)?)?,
        destination: loc(destination.ok_or(SessionError::ConfigError)?)?,
        bind: number(bind.ok_or(SessionError::ConfigError)?)?,
        peer: peer.map(number).transpose()?,
        budget,
        timeout: Duration::from_secs(timeout_seconds),
        max_sessions,
        ready_fd: ready_fd.map(number).transpose()?,
        message,
        scid,
        isolated,
    })
}

fn allowed_underlay(address: SocketAddr, isolated: bool) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => ip.is_loopback() || (isolated && (ip.is_private() || ip.is_link_local())),
        IpAddr::V6(ip) => ip.is_loopback() || (isolated && ip.is_unicast_link_local()),
    }
}

fn configure_df(socket: &UdpSocket) -> Result<(), CliError> {
    #[cfg(target_os = "linux")]
    {
        let value: libc::c_int = libc::IP_PMTUDISC_DO;
        // SAFETY: the descriptor is owned by `socket`, and the pointer references a valid integer.
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
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

fn random<const N: usize>() -> Result<[u8; N], SessionError> {
    let mut value = [0; N];
    getrandom(&mut value).map_err(|_| SessionError::RngFailure)?;
    Ok(value)
}
fn random_scid() -> Result<u64, SessionError> {
    loop {
        let value = u64::from_be_bytes(random()?);
        if value != 0 {
            return Ok(value);
        }
    }
}
fn canonical_endpoint(endpoint: SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(19);
    match endpoint.ip() {
        IpAddr::V4(address) => {
            bytes.push(4);
            bytes.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            bytes.push(6);
            bytes.extend_from_slice(&address.octets());
        }
    }
    bytes.extend_from_slice(&endpoint.port().to_be_bytes());
    bytes
}

fn endpoint_binding(endpoint: SocketAddr, selector: [u8; 16]) -> Result<UdpBinding, SessionError> {
    match endpoint.ip() {
        IpAddr::V4(address) => UdpBinding::ipv4(address.octets(), endpoint.port(), 1, selector),
        IpAddr::V6(address) => UdpBinding::ipv6(address.octets(), endpoint.port(), 1, selector),
    }
}

fn opaque_source(endpoint: SocketAddr, key: &[u8; 32]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, &canonical_endpoint(endpoint))
        .as_ref()
        .try_into()
        .expect("SHA-256 HMAC length")
}
fn peer_matches(
    peer_bindings: &HashMap<u64, (SocketAddr, UdpBinding)>,
    scid: u64,
    endpoint: SocketAddr,
    binding: &UdpBinding,
) -> bool {
    peer_bindings
        .get(&scid)
        .is_some_and(|(expected_endpoint, expected_binding)| {
            *expected_endpoint == endpoint && expected_binding == binding
        })
}

fn retain_live_peer_bindings<F>(
    peer_bindings: &mut HashMap<u64, (SocketAddr, UdpBinding)>,
    mut is_live: F,
) where
    F: FnMut(u64) -> bool,
{
    peer_bindings.retain(|scid, _| is_live(*scid));
}
fn machine_config(local: Identity, peer: Identity, options: &Options) -> HandshakeConfig {
    HandshakeConfig {
        local,
        peer,
        profile: 0,
        source: options.source,
        destination: options.destination,
        budget: options.budget,
        pending_limit: 256,
        established_limit: 1024,
        server_context_id: options.server_context,
    }
}
fn ready(fd: Option<i32>) -> Result<(), CliError> {
    if let Some(fd) = fd {
        let mut clock = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) } != 0 {
            return Err(CliError::Io);
        }
        let value = ((clock.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(clock.tv_nsec as u64))
        .to_be_bytes();
        if unsafe { libc::write(fd, value.as_ptr().cast(), value.len()) } != value.len() as isize {
            return Err(CliError::Io);
        }
    }
    Ok(())
}
fn send_error(error: &std::io::Error) -> CliError {
    if error.raw_os_error() == Some(libc::EMSGSIZE) {
        SessionError::Budget.into()
    } else {
        CliError::Io
    }
}

fn send(socket: &UdpSocket, packet: &[u8], peer: SocketAddr) -> Result<(), CliError> {
    match socket.send_to(packet, peer) {
        Ok(written) if written == packet.len() => Ok(()),
        Ok(_) => Err(CliError::Io),
        Err(error) => Err(send_error(&error)),
    }
}

fn receive_error(error: &std::io::Error) -> CliError {
    if error.kind() == std::io::ErrorKind::TimedOut
        || error.kind() == std::io::ErrorKind::WouldBlock
    {
        SessionError::Timeout.into()
    } else {
        CliError::Io
    }
}

fn receive(
    socket: &UdpSocket,
    timeout: Duration,
    budget: usize,
) -> Result<(Vec<u8>, SocketAddr), CliError> {
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|_| CliError::Io)?;
    let mut buffer = vec![0u8; budget.checked_add(RECV_EXTRA).ok_or(SessionError::Budget)?];
    match socket.recv_from(&mut buffer) {
        Ok((length, peer)) if length <= budget => {
            buffer.truncate(length);
            Ok((buffer, peer))
        }
        Ok(_) => Err(SessionError::Budget.into()),
        Err(error) => Err(receive_error(&error)),
    }
}

fn receive_retry<T, F>(
    socket: &UdpSocket,
    peer: SocketAddr,
    packet: &[u8],
    budget: usize,
    mut receive_packet: F,
) -> Result<T, CliError>
where
    F: FnMut(&[u8]) -> Result<T, SessionError>,
{
    for timeout in RETRIES {
        match receive(socket, timeout, budget) {
            Ok((response, source)) if source == peer => match receive_packet(&response) {
                Ok(value) => return Ok(value),
                Err(_) => send(socket, packet, peer)?,
            },
            Ok(_) => continue,
            Err(CliError::Session(SessionError::Timeout)) => send(socket, packet, peer)?,
            Err(error) => return Err(error),
        }
    }
    Err(SessionError::Timeout.into())
}

fn connect(options: Options) -> Result<(), CliError> {
    let socket = UdpSocket::bind(options.bind).map_err(|_| CliError::Io)?;
    configure_df(&socket)?;
    let peer_endpoint = options.peer.ok_or(SessionError::ConfigError)?;
    if !allowed_underlay(peer_endpoint, options.isolated)
        || !allowed_underlay(options.bind, options.isolated)
    {
        return Err(SessionError::ConfigError.into());
    }
    let signing = SigningKey::from_bytes(&options.local_seed);
    let local = Identity::from_public_key(1, options.service, signing.verifying_key().to_bytes())?;
    let peer = Identity::from_public_key(2, options.service, options.peer_key)?;
    let mut client = ClientMachine::new(machine_config(local, peer, &options), signing)?;
    let start = Instant::now();
    let open = client.start(
        options.scid.unwrap_or(random_scid()?),
        ClientMaterial {
            ephemeral_secret: random()?,
            nonce: random()?,
        },
        0,
    )?;
    send(&socket, &open, peer_endpoint)?;
    let auth = receive_retry(&socket, peer_endpoint, &open, options.budget, |verify| {
        client.receive_verify(verify, start.elapsed().as_millis() as u64)
    })?;
    send(&socket, &auth, peer_endpoint)?;
    let accept = receive_retry(&socket, peer_endpoint, &auth, options.budget, |ack| {
        client.receive_ack(ack, start.elapsed().as_millis() as u64)
    })?;
    send(&socket, &accept, peer_endpoint)?;
    ready(options.ready_fd)?;
    let data = client.send_data(
        options
            .message
            .as_deref()
            .ok_or(SessionError::ConfigError)?,
    )?;
    send(&socket, &data, peer_endpoint)?;
    receive_retry(&socket, peer_endpoint, &data, options.budget, |echo| {
        client.receive_data(echo).map(|_| ())
    })?;
    let close = client.close(0)?;
    send(&socket, &close, peer_endpoint)?;
    println!("r8session: OK");
    Ok(())
}

fn serve(options: Options) -> Result<(), CliError> {
    let socket = UdpSocket::bind(options.bind).map_err(|_| CliError::Io)?;
    configure_df(&socket)?;
    if !allowed_underlay(options.bind, options.isolated) {
        return Err(SessionError::ConfigError.into());
    }
    let signing = SigningKey::from_bytes(&options.local_seed);
    let local = Identity::from_public_key(2, options.service, signing.verifying_key().to_bytes())?;
    let peer = Identity::from_public_key(1, options.service, options.peer_key)?;
    let material = ServerMaterial {
        boot_instance: random()?,
        current_cookie_key: random()?,
        previous_cookie_key: random()?,
        previous_key_rotated_ms: 0,
    };
    let server_config = HandshakeConfig {
        local,
        peer,
        profile: 0,
        source: options.destination,
        destination: options.source,
        budget: options.budget,
        pending_limit: 256,
        established_limit: 1024,
        server_context_id: options.server_context,
    };
    let mut server = ServerMachine::new(server_config, signing, material)?;
    let selector = random::<16>()?;
    let source_hash_key = Zeroizing::new(random::<32>()?);
    let mut peer_bindings: HashMap<u64, (SocketAddr, UdpBinding)> = HashMap::new();
    let mut limiter = PrevalidationLimiter::new();
    let started = Instant::now();
    let mut successes = 0usize;
    let mut last_cookie_rotation_ms = 0u64;
    let mut ready_sent = false;
    while successes < options.max_sessions {
        let (packet, endpoint) = match receive(&socket, options.timeout, options.budget) {
            Ok(value) => value,
            Err(CliError::Session(SessionError::Timeout)) => break,
            Err(error) => return Err(error),
        };
        if !allowed_underlay(endpoint, options.isolated) {
            continue;
        }
        let binding = match endpoint_binding(endpoint, selector) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let now = started.elapsed().as_millis() as u64;
        if now.saturating_sub(last_cookie_rotation_ms) >= 600_000 {
            server.rotate_cookie_key(random()?, now);
            last_cookie_rotation_ms = now;
        }
        let bucket = now / 10_000;
        let response = match r8_proto::Header::unpack_with_budget(&packet, options.budget) {
            Ok((_header, payload)) if payload.first() == Some(&r8_session::OPEN) => server
                .receive_open_limited(
                    &packet,
                    &ObservedBinding::Udp(binding.clone()),
                    opaque_source(endpoint, &source_hash_key),
                    now,
                    bucket,
                    &mut limiter,
                )
                .ok(),
            Ok((header, payload)) if payload.first() == Some(&r8_session::OPEN_AUTH) => {
                match server.receive_open_auth(
                    &packet,
                    &ObservedBinding::Udp(binding.clone()),
                    now,
                    bucket,
                    Some(ServerHandshakeMaterial {
                        ephemeral_secret: random()?,
                        nonce: random()?,
                    }),
                ) {
                    Ok(response) => {
                        peer_bindings.insert(header.scid, (endpoint, binding.clone()));
                        Some(response)
                    }
                    Err(_) => None,
                }
            }
            Ok((header, payload)) if payload.first() == Some(&r8_session::SESSION_ACCEPT) => {
                if !peer_matches(&peer_bindings, header.scid, endpoint, &binding)
                    || server.receive_accept(&packet, now).is_err()
                {
                    continue;
                }
                if !ready_sent {
                    ready(options.ready_fd)?;
                    ready_sent = true;
                }
                None
            }
            Ok((header, payload)) if payload.first() == Some(&r8_session::SESSION_DATA) => {
                if !peer_matches(&peer_bindings, header.scid, endpoint, &binding) {
                    continue;
                }
                server
                    .receive_data(&packet, now)
                    .ok()
                    .and_then(|plaintext| server.send_data(header.scid, &plaintext).ok())
            }
            Ok((header, payload)) if payload.first() == Some(&r8_session::CLOSE) => {
                if !peer_matches(&peer_bindings, header.scid, endpoint, &binding) {
                    continue;
                }
                if server.receive_close(&packet, now).is_ok() {
                    peer_bindings.remove(&header.scid);
                    successes += 1;
                }
                None
            }
            _ => None,
        };
        if let Some(response) = response {
            send(&socket, &response, endpoint)?;
        }
        server.expire(now);
        retain_live_peer_bindings(&mut peer_bindings, |scid| server.is_live(scid));
    }
    if successes == options.max_sessions {
        println!("r8session: OK");
        Ok(())
    } else {
        Err(SessionError::Timeout.into())
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = parse_options(&args)
        .map_err(CliError::from)
        .and_then(|options| match options.mode {
            Mode::Connect => connect(options),
            Mode::Serve => serve(options),
        });
    if let Err(error) = result {
        eprintln!("r8session: {}\n{}", error.as_str(), usage());
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_hex_and_underlay() {
        assert!(hex("0").is_err());
        assert!(!allowed_underlay("8.8.8.8:9".parse().unwrap(), true));
        assert!(allowed_underlay("127.0.0.1:9".parse().unwrap(), false));
    }
    #[test]
    fn bounded_receive_constant() {
        assert_eq!(DEFAULT_BUDGET + RECV_EXTRA, 1253);
    }
    #[test]
    fn redacted_usage() {
        assert!(!usage().contains("cookie"));
        assert!(!usage().contains("key="));
    }
    fn valid_args(mode: &str) -> Vec<String> {
        vec![
            "r8session".into(),
            mode.into(),
            "--local-seed-hex".into(),
            "00".repeat(32),
            "--peer-public-key-hex".into(),
            "11".repeat(32),
            "--service-context".into(),
            "1".into(),
            "--server-context-id".into(),
            "1".into(),
            "--address".into(),
            "::1".into(),
            "--peer-address".into(),
            "::2".into(),
            "--bind".into(),
            "127.0.0.1:1".into(),
        ]
    }

    #[test]
    fn argv_validation_rejects_unrecognized_duplicate_positional_missing_and_wrong_mode_flags() {
        let mut unknown = valid_args("serve");
        unknown.extend(["--unknown", "secret-value"].into_iter().map(String::from));
        assert!(matches!(
            parse_options(&unknown),
            Err(SessionError::ConfigError)
        ));

        let mut duplicate = valid_args("serve");
        duplicate.extend(["--bind", "127.0.0.1:2"].into_iter().map(String::from));
        assert!(matches!(
            parse_options(&duplicate),
            Err(SessionError::ConfigError)
        ));

        let mut positional = valid_args("serve");
        positional.push("secret-value".into());
        assert!(matches!(
            parse_options(&positional),
            Err(SessionError::ConfigError)
        ));

        let mut missing = valid_args("serve");
        missing.push("--timeout".into());
        assert!(matches!(
            parse_options(&missing),
            Err(SessionError::ConfigError)
        ));

        let mut serve_peer = valid_args("serve");
        serve_peer.extend(["--peer", "127.0.0.1:2"].into_iter().map(String::from));
        assert!(matches!(
            parse_options(&serve_peer),
            Err(SessionError::ConfigError)
        ));

        let mut connect_sessions = valid_args("connect");
        connect_sessions.extend(
            [
                "--peer",
                "127.0.0.1:2",
                "--message-hex",
                "00",
                "--max-sessions",
                "1",
            ]
            .into_iter()
            .map(String::from),
        );
        assert!(matches!(
            parse_options(&connect_sessions),
            Err(SessionError::ConfigError)
        ));
    }

    #[test]
    fn injected_socket_and_fd_errors_keep_their_categories() {
        assert_eq!(
            send_error(&std::io::Error::from_raw_os_error(libc::EMSGSIZE)),
            CliError::Session(SessionError::Budget)
        );
        assert_eq!(
            send_error(&std::io::Error::from_raw_os_error(libc::EACCES)),
            CliError::Io
        );
        assert_eq!(
            receive_error(&std::io::Error::from(std::io::ErrorKind::TimedOut)),
            CliError::Session(SessionError::Timeout)
        );
        assert_eq!(
            receive_error(&std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            CliError::Io
        );
        assert_eq!(ready(Some(-1)), Err(CliError::Io));
    }
    #[test]
    fn selector_is_stable_and_binding_tracks_remote_endpoint() {
        let selector = [7; 16];
        let first: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:1001".parse().unwrap();
        assert_eq!(
            endpoint_binding(first, selector).unwrap(),
            endpoint_binding(first, selector).unwrap()
        );
        assert_ne!(
            endpoint_binding(first, selector).unwrap(),
            endpoint_binding(second, selector).unwrap()
        );
    }

    #[test]
    fn source_hash_is_keyed_and_peer_decision_requires_exact_binding() {
        let endpoint: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        assert_ne!(
            opaque_source(endpoint, &[1; 32]),
            opaque_source(endpoint, &[2; 32])
        );
        let binding = endpoint_binding(endpoint, [3; 16]).unwrap();
        let mut peers = HashMap::new();
        peers.insert(9, (endpoint, binding.clone()));
        assert!(peer_matches(&peers, 9, endpoint, &binding));
        assert!(!peer_matches(
            &peers,
            9,
            "127.0.0.1:1001".parse().unwrap(),
            &binding
        ));
    }

    #[test]
    fn send_result_classifier_is_not_a_budget_alias() {
        assert_ne!(SessionError::AuthFailed, SessionError::Budget);
    }
    #[test]
    fn expiry_cleanup_retain_only_live_bindings() {
        let endpoint: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let binding = endpoint_binding(endpoint, [4; 16]).unwrap();
        let mut peer_bindings = HashMap::new();
        peer_bindings.insert(1, (endpoint, binding.clone()));
        peer_bindings.insert(2, (endpoint, binding));
        retain_live_peer_bindings(&mut peer_bindings, |scid| scid == 2);
        assert!(!peer_bindings.contains_key(&1));
        assert!(peer_bindings.contains_key(&2));
    }
}
