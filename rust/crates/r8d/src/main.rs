//! r8d — R8 daemon: udp-binding ECHO responder + DGRAM sink (v0.1 static mode).
//!
//! Usage: r8d --address 8:1::10 [--bind 0.0.0.0:52808]

use r8_proto::*;
use std::net::UdpSocket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut address: Option<String> = None;
    let mut bind = format!("0.0.0.0:{R8_UDP_PORT}");
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--address" => address = Some(it.next().ok_or("--address needs a value")?),
            "--bind" => bind = it.next().ok_or("--bind needs a value")?,
            _ => return Err(format!("unknown arg: {a}").into()),
        }
    }
    let me = parse_loc(&address.ok_or("--address is required")?)?;
    let sock = UdpSocket::bind(&bind)?;
    println!("[r8d] listen {} on {} (udp-binding)", fmt_loc(&me), bind);

    let mut buf = [0u8; 65535];
    loop {
        let (n, peer) = sock.recv_from(&mut buf)?;
        let (hdr, payload) = match Header::unpack(&buf[..n]) {
            Ok(v) => v,
            Err(e) => {
                println!("[drop] {e}");
                continue;
            }
        };
        if hdr.dst != me {
            println!("[drop] dst {} != me {}", fmt_loc(&hdr.dst), fmt_loc(&me));
            continue;
        }
        match hdr.next_header {
            NH_CTL => {
                if let Ok((ctype, _code, _csum, body, ok)) = parse_ctl(&hdr, payload) {
                    if ok && ctype == CTL_ECHO_REQUEST {
                        let mut rh = Header::new(NH_CTL, me, hdr.src);
                        rh.scid = hdr.scid;
                        let pkt = build_ctl(&rh, CTL_ECHO_REPLY, 0, body, true);
                        let _ = sock.send_to(&pkt, peer);
                        println!("[echo] reply -> {}", fmt_loc(&hdr.src));
                    }
                }
            }
            NH_DGRAM => {
                if let Ok((sport, dport, data, ok)) = parse_dgram(&hdr, payload) {
                    if ok {
                        println!(
                            "[dgram] {}:{sport} -> :{dport} {:?}",
                            fmt_loc(&hdr.src),
                            String::from_utf8_lossy(data)
                        );
                    } else {
                        println!("[drop] bad dgram checksum from {}", fmt_loc(&hdr.src));
                    }
                }
            }
            nh => println!("[drop] unsupported next-header {nh}"),
        }
    }
}
