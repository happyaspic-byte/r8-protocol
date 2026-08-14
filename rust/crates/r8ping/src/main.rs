//! r8ping — R8 echo client (udp-binding).
//!
//! Usage: r8ping --address 8:1::20 --peer 8:1::10=127.0.0.1:52808 [--count 4] 8:1::10

use r8_proto::*;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut address: Option<String> = None;
    let mut peer: Option<String> = None;
    let mut count: u16 = 4;
    let mut timeout_ms: u64 = 1000;
    let mut target: Option<String> = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--address" => address = Some(it.next().ok_or("--address needs a value")?),
            "--peer" => peer = Some(it.next().ok_or("--peer needs a value")?),
            "--count" => count = it.next().ok_or("--count needs a value")?.parse()?,
            "--timeout-ms" => timeout_ms = it.next().ok_or("--timeout-ms needs a value")?.parse()?,
            _ if !a.starts_with('-') => target = Some(a),
            _ => return Err(format!("unknown arg: {a}").into()),
        }
    }
    let me = parse_loc(&address.ok_or("--address is required")?)?;
    let target_loc = parse_loc(&target.ok_or("target locator is required")?)?;
    let peer = peer.ok_or("--peer loc=host:port is required")?;
    let (peer_loc, peer_dest) = peer.split_once('=').ok_or("--peer must be loc=host:port")?;
    if parse_loc(peer_loc)? != target_loc {
        return Err("peer locator does not match target".into());
    }

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    let ident = (std::process::id() & 0xffff) as u16;
    let mut sent = 0u32;
    let mut rcvd = 0u32;

    for seq in 1..=count {
        let hdr = Header::new(NH_CTL, me, target_loc);
        let mut body = Vec::with_capacity(4);
        body.extend_from_slice(&ident.to_be_bytes());
        body.extend_from_slice(&seq.to_be_bytes());
        let pkt = build_ctl(&hdr, CTL_ECHO_REQUEST, 0, &body, true);
        let t0 = Instant::now();
        sock.send_to(&pkt, peer_dest)?;
        sent += 1;
        let mut buf = [0u8; 2048];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                let ok_reply = match Header::unpack(&buf[..n]) {
                    Ok((rh, payload)) => match parse_ctl(&rh, payload) {
                        Ok((t, _c, _s, rb, ok)) => {
                            if ok && t == CTL_ECHO_REPLY && rb == body.as_slice() {
                                rcvd += 1;
                                println!(
                                    "R8-ECHO reply from {} sequence={seq} latency={:.2} ms",
                                    fmt_loc(&rh.src),
                                    t0.elapsed().as_secs_f64() * 1000.0
                                );
                                true
                            } else {
                                false
                            }
                        }
                        Err(_) => false,
                    },
                    Err(_) => false,
                };
                if !ok_reply {
                    println!("R8-ECHO invalid reply sequence={seq}");
                }
            }
            Err(_) => println!("R8-ECHO timeout sequence={seq}"),
        }
    }
    let loss = 100.0 * (sent - rcvd) as f64 / sent as f64;
    println!("--- {} r8ping statistics ---", fmt_loc(&target_loc));
    println!("{sent} sent, {rcvd} received, {loss:.0}% loss");
    Ok(())
}
