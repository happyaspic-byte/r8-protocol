//! Strict R8 v0.2 UDP ECHO responder and DGRAM sink.

use r8_proto::*;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};

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

fn set_df(socket: &UdpSocket) -> std::io::Result<()> {
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
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut address = None;
    let mut bind = "127.0.0.1:52808".to_owned();
    let mut budget = DEFAULT_BUDGET;
    let mut allow_isolated = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--address" => address = Some(args.next().ok_or("--address needs a value")?),
            "--bind" => bind = args.next().ok_or("--bind needs a value")?,
            "--binding-budget" => {
                budget = args
                    .next()
                    .ok_or("--binding-budget needs a value")?
                    .parse()?
            }
            "--allow-isolated-underlay" => allow_isolated = true,
            _ => return Err("invalid argument".into()),
        }
    }
    if !(HEADER_LEN..=SERIALIZED_R8_MAX).contains(&budget) {
        return Err("--binding-budget must be 48..1280".into());
    }
    let bind: SocketAddr = bind.parse()?;
    validate_underlay(bind, allow_isolated)?;
    let me = parse_loc(&address.ok_or("--address is required")?)?;
    let socket = UdpSocket::bind(bind)?;
    set_df(&socket)?;
    println!("[r8d] ready budget={budget}");

    let mut buffer = vec![0u8; budget + 1];
    loop {
        let (length, peer) = socket.recv_from(&mut buffer)?;
        if length > budget {
            println!("[drop] E-BUDGET length={length}");
            continue;
        }
        let (header, payload) = match Header::unpack_with_budget(&buffer[..length], budget) {
            Ok(packet) => packet,
            Err(error) => {
                println!("[drop] {error}");
                continue;
            }
        };
        if header.dst != me {
            println!("[drop] DST");
            continue;
        }
        match header.next_header {
            NH_CTL => match parse_ctl(&header, payload) {
                Ok((CTL_ECHO_REQUEST, 0, body)) => {
                    let reply = build_ctl_with_budget(
                        &Header::new(NH_CTL, me, header.src),
                        CTL_ECHO_REPLY,
                        0,
                        body,
                        budget,
                    );
                    match reply {
                        Ok(packet) => match send_packet(&socket, &packet, peer) {
                            Ok(_) => println!("[echo] reply length={}", packet.len()),
                            Err(error)
                                if error.downcast_ref::<WireError>()
                                    == Some(&WireError::BindingBudget) =>
                            {
                                println!("[drop] E-BUDGET")
                            }
                            Err(error) => return Err(error),
                        },
                        Err(error) => println!("[drop] {error}"),
                    }
                }
                Ok(_) => println!("[drop] CTL"),
                Err(error) => println!("[drop] {error}"),
            },
            NH_DGRAM => match parse_dgram(&header, payload) {
                Ok((_, _, data)) => println!("[dgram] received length={}", data.len()),
                Err(error) => println!("[drop] {error}"),
            },
            _ => println!("[drop] NEXT_HEADER"),
        }
    }
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
