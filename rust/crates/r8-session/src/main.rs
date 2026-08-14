use std::{
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr, UdpSocket},
    process,
    time::{Duration, Instant},
};

use ed25519_dalek::SigningKey;
use getrandom::getrandom;
use hmac::{Hmac, Mac};
use r8_proto::parse_loc;
use r8_session::{
    ClientMachine, ClientMaterial, HandshakeConfig, Identity, PrevalidationLimiter,
    ServerHandshakeMaterial, ServerMachine, ServerMaterial, SessionError, UdpBinding,
};
use sha2::Sha256;

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
    isolated: bool,
}

fn usage() -> &'static str {
    "usage: r8session serve --local-seed-hex HEX --peer-public-key-hex HEX --service-context N --server-context-id N --address IPV6 --peer-address IPV6 --bind HOST:PORT [--binding-budget N] [--timeout SECONDS] [--max-sessions N] [--allow-isolated-underlay]\n       r8session connect --local-seed-hex HEX --peer-public-key-hex HEX --service-context N --server-context-id N --address IPV6 --peer-address IPV6 --bind HOST:PORT --peer HOST:PORT --message-hex HEX [--scid N] [--binding-budget N] [--timeout SECONDS] [--allow-isolated-underlay]"
}

fn argument(args: &[String], name: &str) -> Result<String, SessionError> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .ok_or(SessionError::ConfigError)
}
fn optional(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
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
fn number<T: std::str::FromStr>(args: &[String], name: &str) -> Result<T, SessionError> {
    argument(args, name)?
        .parse()
        .map_err(|_| SessionError::ConfigError)
}
fn loc(args: &[String], name: &str) -> Result<[u8; 16], SessionError> {
    parse_loc(&argument(args, name)?).map_err(|_| SessionError::ConfigError)
}

fn parse_options(args: &[String]) -> Result<Options, SessionError> {
    let mode = match args.get(1).map(String::as_str) {
        Some("serve") => Mode::Serve,
        Some("connect") => Mode::Connect,
        _ => return Err(SessionError::ConfigError),
    };
    let budget = optional(args, "--binding-budget")
        .map(|value| value.parse().map_err(|_| SessionError::ConfigError))
        .transpose()?
        .unwrap_or(DEFAULT_BUDGET);
    if !(48..=1252).contains(&budget) {
        return Err(SessionError::ConfigError);
    }
    let service = number(args, "--service-context")?;
    let server_context = number(args, "--server-context-id")?;
    if service == 0 || server_context == 0 {
        return Err(SessionError::ConfigError);
    }
    let timeout_seconds: u64 = optional(args, "--timeout")
        .map(|value| value.parse().map_err(|_| SessionError::ConfigError))
        .transpose()?
        .unwrap_or(5);
    if timeout_seconds == 0 {
        return Err(SessionError::ConfigError);
    }
    let bind: SocketAddr = argument(args, "--bind")?
        .parse()
        .map_err(|_| SessionError::ConfigError)?;
    let peer = if mode == Mode::Connect {
        Some(
            argument(args, "--peer")?
                .parse()
                .map_err(|_| SessionError::ConfigError)?,
        )
    } else {
        None
    };
    let message = if mode == Mode::Connect {
        Some(hex(&argument(args, "--message-hex")?)?)
    } else {
        None
    };
    if message.as_ref().is_some_and(|bytes| bytes.is_empty()) {
        return Err(SessionError::ConfigError);
    }
    let scid = optional(args, "--scid")
        .map(|value| value.parse::<u64>().map_err(|_| SessionError::ConfigError))
        .transpose()?;
    if scid == Some(0) {
        return Err(SessionError::ConfigError);
    }
    let max_sessions = optional(args, "--max-sessions")
        .map(|value| value.parse().map_err(|_| SessionError::ConfigError))
        .transpose()?
        .unwrap_or(1usize);
    if max_sessions == 0 || max_sessions > 1024 {
        return Err(SessionError::ConfigError);
    }
    Ok(Options {
        mode,
        local_seed: fixed(&argument(args, "--local-seed-hex")?)?,
        peer_key: fixed(&argument(args, "--peer-public-key-hex")?)?,
        service,
        server_context,
        source: loc(args, "--address")?,
        destination: loc(args, "--peer-address")?,
        bind,
        peer,
        budget,
        timeout: Duration::from_secs(timeout_seconds),
        max_sessions,
        message,
        scid,
        isolated: args.iter().any(|arg| arg == "--allow-isolated-underlay"),
    })
}

fn allowed_underlay(address: SocketAddr, isolated: bool) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => ip.is_loopback() || (isolated && (ip.is_private() || ip.is_link_local())),
        IpAddr::V6(ip) => ip.is_loopback() || (isolated && ip.is_unicast_link_local()),
    }
}

fn configure_df(socket: &UdpSocket) -> Result<(), SessionError> {
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
            return Err(SessionError::ConfigError);
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
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("fixed HMAC key");
    mac.update(&canonical_endpoint(endpoint));
    mac.finalize().into_bytes().into()
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
fn send(socket: &UdpSocket, packet: &[u8], peer: SocketAddr) -> Result<(), SessionError> {
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
    let mut buffer = vec![0u8; budget.checked_add(RECV_EXTRA).ok_or(SessionError::Budget)?];
    match socket.recv_from(&mut buffer) {
        Ok((length, peer)) if length <= budget => {
            buffer.truncate(length);
            Ok((buffer, peer))
        }
        Ok(_) => Err(SessionError::Budget),
        Err(error)
            if error.kind() == std::io::ErrorKind::TimedOut
                || error.kind() == std::io::ErrorKind::WouldBlock =>
        {
            Err(SessionError::Timeout)
        }
        Err(_) => Err(SessionError::AuthFailed),
    }
}
fn receive_retry(
    socket: &UdpSocket,
    peer: SocketAddr,
    packet: &[u8],
    budget: usize,
) -> Result<Vec<u8>, SessionError> {
    for timeout in RETRIES {
        match receive(socket, timeout, budget) {
            Ok((response, source)) if source == peer => return Ok(response),
            Ok(_) => continue,
            Err(SessionError::Timeout) => send(socket, packet, peer)?,
            Err(error) => return Err(error),
        }
    }
    Err(SessionError::Timeout)
}

fn connect(options: Options) -> Result<(), SessionError> {
    let socket = UdpSocket::bind(options.bind).map_err(|_| SessionError::ConfigError)?;
    configure_df(&socket)?;
    let peer_endpoint = options.peer.ok_or(SessionError::ConfigError)?;
    if !allowed_underlay(peer_endpoint, options.isolated)
        || !allowed_underlay(options.bind, options.isolated)
    {
        return Err(SessionError::ConfigError);
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
    let verify = receive_retry(&socket, peer_endpoint, &open, options.budget)?;
    let auth = client.receive_verify(&verify, start.elapsed().as_millis() as u64)?;
    send(&socket, &auth, peer_endpoint)?;
    let ack = receive_retry(&socket, peer_endpoint, &auth, options.budget)?;
    let accept = client.receive_ack(&ack, start.elapsed().as_millis() as u64)?;
    send(&socket, &accept, peer_endpoint)?;
    let data = client.send_data(
        options
            .message
            .as_deref()
            .ok_or(SessionError::ConfigError)?,
    )?;
    send(&socket, &data, peer_endpoint)?;
    let echo = receive_retry(&socket, peer_endpoint, &data, options.budget)?;
    let _ = client.receive_data(&echo)?;
    let close = client.close(0)?;
    send(&socket, &close, peer_endpoint)?;
    println!("r8session: OK");
    Ok(())
}

fn serve(options: Options) -> Result<(), SessionError> {
    let socket = UdpSocket::bind(options.bind).map_err(|_| SessionError::ConfigError)?;
    configure_df(&socket)?;
    if !allowed_underlay(options.bind, options.isolated) {
        return Err(SessionError::ConfigError);
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
    let source_hash_key = random::<32>()?;
    let mut peer_bindings: HashMap<u64, (SocketAddr, UdpBinding)> = HashMap::new();
    let mut limiter = PrevalidationLimiter::new();
    let started = Instant::now();
    let mut successes = 0usize;
    let mut last_cookie_rotation_ms = 0u64;
    while successes < options.max_sessions {
        let (packet, endpoint) = match receive(&socket, options.timeout, options.budget) {
            Ok(value) => value,
            Err(SessionError::Timeout) => break,
            Err(_) => continue,
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
                    &binding,
                    opaque_source(endpoint, &source_hash_key),
                    now,
                    bucket,
                    &mut limiter,
                )
                .ok(),
            Ok((header, payload)) if payload.first() == Some(&r8_session::OPEN_AUTH) => {
                match server.receive_open_auth(
                    &packet,
                    &binding,
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
            let _ = send(&socket, &response, endpoint);
        }
        server.expire(now);
        retain_live_peer_bindings(&mut peer_bindings, |scid| server.is_live(scid));
    }
    if successes == options.max_sessions {
        println!("r8session: OK");
        Ok(())
    } else {
        Err(SessionError::Timeout)
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = parse_options(&args).and_then(|options| match options.mode {
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
