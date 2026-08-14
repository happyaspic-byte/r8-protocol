//! Strict R8 v0.2 ECHO client and DGRAM sender.

use r8_proto::*;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};
fn is_budget_send_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EMSGSIZE)
}
fn validate_send_count(sent: usize, expected: usize) -> io::Result<()> {
    if sent == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "UDP send returned a short count",
        ))
    }
}

fn send_packet_with<F>(
    packet: &[u8],
    peer: SocketAddr,
    send: F,
) -> Result<usize, Box<dyn std::error::Error>>
where
    F: FnOnce(&[u8], SocketAddr) -> io::Result<usize>,
{
    match send(packet, peer) {
        Ok(sent) => {
            validate_send_count(sent, packet.len())?;
            Ok(sent)
        }
        Err(error) if is_budget_send_error(&error) => Err(Box::new(WireError::BindingBudget)),
        Err(error) => Err(Box::new(error)),
    }
}

fn send_packet(
    socket: &UdpSocket,
    packet: &[u8],
    peer: SocketAddr,
) -> Result<usize, Box<dyn std::error::Error>> {
    send_packet_with(packet, peer, |packet, peer| socket.send_to(packet, peer))
}

const DEFAULT_BUDGET: usize = 1252;

fn isolated(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}
fn validate_underlay(addr: SocketAddr, allow_isolated: bool) -> Result<(), String> {
    if !addr.is_ipv4() {
        return Err("only IPv4 UDP underlay is supported".into());
    }
    if addr.ip().is_loopback() || (allow_isolated && isolated(addr.ip())) {
        Ok(())
    } else if isolated(addr.ip()) {
        Err("isolated underlay requires --allow-isolated-underlay".into())
    } else {
        Err("public underlay is rejected".into())
    }
}
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
fn set_df(socket: &UdpSocket) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        let value: libc::c_int = libc::IP_PMTUDISC_DO;
        if libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
fn endpoint(text: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    text.to_socket_addrs()?
        .next()
        .ok_or_else(|| "peer endpoint is unresolved".into())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut address = None;
    let mut peer = None;
    let mut bind = "127.0.0.1:0".to_owned();
    let mut count: u16 = 4;
    let mut timeout_ms = 1000u64;
    let mut dgram = None;
    let mut sport = 1000u16;
    let mut dport = 9000u16;
    let mut budget = DEFAULT_BUDGET;
    let mut allow_isolated = false;
    let mut target = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--address" => address = Some(args.next().ok_or("--address needs a value")?),
            "--peer" => peer = Some(args.next().ok_or("--peer needs a value")?),
            "--bind" => bind = args.next().ok_or("--bind needs a value")?,
            "--count" => count = args.next().ok_or("--count needs a value")?.parse()?,
            "--timeout-ms" => {
                timeout_ms = args.next().ok_or("--timeout-ms needs a value")?.parse()?
            }
            "--dgram" => dgram = Some(args.next().ok_or("--dgram needs a value")?),
            "--sport" => sport = args.next().ok_or("--sport needs a value")?.parse()?,
            "--dport" => dport = args.next().ok_or("--dport needs a value")?.parse()?,
            "--binding-budget" => {
                budget = args
                    .next()
                    .ok_or("--binding-budget needs a value")?
                    .parse()?
            }
            "--allow-isolated-underlay" => allow_isolated = true,
            _ if !arg.starts_with('-') && target.is_none() => target = Some(arg),
            _ => return Err("invalid argument".into()),
        }
    }
    if count == 0 {
        return Err("--count must be greater than zero".into());
    }
    if !(HEADER_LEN..=SERIALIZED_R8_MAX).contains(&budget) {
        return Err("--binding-budget must be 48..1280".into());
    }
    let me = parse_loc(&address.ok_or("--address is required")?)?;
    let target = parse_loc(&target.ok_or("target locator is required")?)?;
    let peer_argument = peer.ok_or("--peer is required")?;
    let (peer_loc, peer_text) = peer_argument
        .split_once('=')
        .ok_or("--peer must be loc=host:port")?;
    if parse_loc(peer_loc)? != target {
        return Err("peer locator does not match target".into());
    }
    let peer = endpoint(peer_text)?;
    let bind: SocketAddr = bind.parse()?;
    validate_underlay(bind, allow_isolated)?;
    validate_underlay(peer, allow_isolated)?;
    let socket = UdpSocket::bind(bind)?;
    set_df(&socket)?;
    if let Some(message) = dgram {
        let packet = build_dgram_with_budget(
            &Header::new(NH_DGRAM, me, target),
            sport,
            dport,
            message.as_bytes(),
            budget,
        )
        .map_err(|_| "E-BUDGET")?;
        send_packet(&socket, &packet, peer)?;
        println!("[dgram] sent length={}", packet.len());
        return Ok(());
    }
    let ident = (std::process::id() & u32::from(u16::MAX)) as u16;
    let mut received = 0u32;
    let mut invalid = 0u32;
    for sequence in 1..=count {
        let body = [
            ((ident >> 8) as u8),
            ident as u8,
            ((sequence >> 8) as u8),
            sequence as u8,
        ];
        let packet = build_ctl_with_budget(
            &Header::new(NH_CTL, me, target),
            CTL_ECHO_REQUEST,
            0,
            &body,
            budget,
        )
        .map_err(|_| "E-BUDGET")?;
        let started = Instant::now();
        send_packet(&socket, &packet, peer)?;
        let deadline = started + Duration::from_millis(timeout_ms);
        let mut matched = false;
        let mut buffer = vec![0u8; budget + 1];
        while Instant::now() < deadline {
            socket.set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))?;
            let (length, source) = match socket.recv_from(&mut buffer) {
                Ok(value) => value,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    break
                }
                Err(error) => return Err(error.into()),
            };
            if length > budget || source != peer {
                invalid += 1;
                continue;
            }
            let (header, payload) = match Header::unpack_with_budget(&buffer[..length], budget) {
                Ok(value) => value,
                Err(_) => {
                    invalid += 1;
                    continue;
                }
            };
            match parse_ctl(&header, payload) {
                Ok((CTL_ECHO_REPLY, 0, reply))
                    if header.next_header == NH_CTL
                        && header.src == target
                        && header.dst == me
                        && reply == body =>
                {
                    received += 1;
                    matched = true;
                    println!(
                        "R8-ECHO reply sequence={sequence} latency_ms={:.2}",
                        started.elapsed().as_secs_f64() * 1000.0
                    );
                    break;
                }
                _ => invalid += 1,
            }
        }
        if !matched {
            println!("R8-ECHO timeout sequence={sequence}");
        }
    }
    let sent = u32::from(count);
    println!("R8-ECHO summary sent={sent} received={received} invalid={invalid}");
    if sent != received || invalid != 0 {
        return Err("echo loss or invalid reply".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_emsgsize_is_a_budget_send_error() {
        assert!(is_budget_send_error(&io::Error::from_raw_os_error(
            libc::EMSGSIZE
        )));
        assert!(!is_budget_send_error(&io::Error::from_raw_os_error(
            libc::EACCES
        )));
    }
    #[test]
    fn send_count_requires_the_complete_datagram() {
        assert!(validate_send_count(12, 12).is_ok());
        assert_eq!(
            validate_send_count(0, 12).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
        assert_eq!(
            validate_send_count(11, 12).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
    }
    #[test]
    fn injected_send_results_preserve_budget_and_short_write_contracts() {
        let packet = [0; 12];
        let peer = "127.0.0.1:9".parse().unwrap();

        assert_eq!(send_packet_with(&packet, peer, |_, _| Ok(12)).unwrap(), 12);
        for sent in [0, 11] {
            let error = send_packet_with(&packet, peer, |_, _| Ok(sent)).unwrap_err();
            assert_eq!(
                error.downcast_ref::<io::Error>().unwrap().kind(),
                io::ErrorKind::WriteZero
            );
        }
        let budget = send_packet_with(&packet, peer, |_, _| {
            Err(io::Error::from_raw_os_error(libc::EMSGSIZE))
        })
        .unwrap_err();
        assert_eq!(
            budget.downcast_ref::<WireError>(),
            Some(&WireError::BindingBudget)
        );
        let denied = send_packet_with(&packet, peer, |_, _| {
            Err(io::Error::from_raw_os_error(libc::EACCES))
        })
        .unwrap_err();
        assert_eq!(
            denied.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(libc::EACCES)
        );
    }
}
