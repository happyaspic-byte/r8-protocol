//! R8 wire format v0.1 — source of truth: spec/0001-wire-format-v0.1.md
//!
//! Lab use only; NOT an Internet standard. std-only, no external crates.

pub const R8_UDP_PORT: u16 = 52808; // dynamic/private range (RFC 6335)
pub const R8_ETHERTYPE: u16 = 0x88B5; // IEEE local experimental (eth-binding, M4)
pub const VERSION: u8 = 8;
pub const HEADER_LEN: usize = 48;

pub const NH_CTL: u8 = 1;
pub const NH_DGRAM: u8 = 2;
pub const NH_SES: u8 = 3;
pub const NH_NONE: u8 = 59;

pub const CTL_ECHO_REQUEST: u8 = 1;
pub const CTL_ECHO_REPLY: u8 = 2;
pub const CTL_DEST_UNREACHABLE: u8 = 128;
pub const CTL_TIME_EXCEEDED: u8 = 129;
pub const CTL_PACKET_TOO_BIG: u8 = 130;

/// 128-bit locator or EID.
pub type Loc = [u8; 16];

/// Parse an RFC 4291 textual locator, e.g. "8:1::10".
pub fn parse_loc(s: &str) -> Result<Loc, std::net::AddrParseError> {
    Ok(s.parse::<std::net::Ipv6Addr>()?.octets())
}

/// Format a locator in RFC 4291 compressed form.
pub fn fmt_loc(l: &Loc) -> String {
    std::net::Ipv6Addr::from(*l).to_string()
}

/// R8 base header, 48 bytes (spec section 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub profile: u8,
    pub tc: u8,
    pub next_header: u8,
    pub hop_limit: u8,
    pub flags: u8,
    pub path_slot: u8,
    pub scid: u64,
    pub src: Loc,
    pub dst: Loc,
}

impl Header {
    pub fn new(next_header: u8, src: Loc, dst: Loc) -> Self {
        Header {
            profile: 0,
            tc: 0,
            next_header,
            hop_limit: 64,
            flags: 0,
            path_slot: 0,
            scid: 0,
            src,
            dst,
        }
    }

    /// Serialize header + payload (payload length is taken from `payload`).
    pub fn pack(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.push((VERSION << 4) | (self.profile & 0x0f));
        out.push(self.tc);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.push(self.next_header);
        out.push(self.hop_limit);
        out.push(self.flags);
        out.push(self.path_slot);
        out.extend_from_slice(&self.scid.to_be_bytes());
        out.extend_from_slice(&self.src);
        out.extend_from_slice(&self.dst);
        out.extend_from_slice(payload);
        out
    }

    /// Parse header; returns the header and the payload slice.
    pub fn unpack(data: &[u8]) -> Result<(Header, &[u8]), &'static str> {
        if data.len() < HEADER_LEN {
            return Err("short packet");
        }
        if data[0] >> 4 != VERSION {
            return Err("bad version");
        }
        let plen = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < HEADER_LEN + plen {
            return Err("truncated payload");
        }
        let scid = u64::from_be_bytes(data[8..16].try_into().map_err(|_| "scid")?);
        let mut src = [0u8; 16];
        src.copy_from_slice(&data[16..32]);
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&data[32..48]);
        let hdr = Header {
            profile: data[0] & 0x0f,
            tc: data[1],
            next_header: data[4],
            hop_limit: data[5],
            flags: data[6],
            path_slot: data[7],
            scid,
            src,
            dst,
        };
        Ok((hdr, &data[HEADER_LEN..HEADER_LEN + plen]))
    }
}

fn sum16(data: &[u8]) -> u32 {
    let mut s: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for w in &mut chunks {
        s += u16::from_be_bytes([w[0], w[1]]) as u32;
        s = (s & 0xffff) + (s >> 16);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        s += (rem[0] as u32) << 8;
        s = (s & 0xffff) + (s >> 16);
    }
    s
}

/// 16-bit one's-complement checksum over pseudo-header + body.
/// `pseudo` must be even-length (the R8 pseudo-header is always 40 bytes).
pub fn checksum16(pseudo: &[u8], body: &[u8]) -> u16 {
    debug_assert!(pseudo.len() % 2 == 0);
    let mut s = sum16(pseudo).wrapping_add(sum16(body));
    s = (s & 0xffff) + (s >> 16);
    !(s as u16)
}

/// Pseudo-header: src(16) + dst(16) + payload-len(4) + next-header(4).
pub fn pseudo_header(hdr: &Header, plen: u32, nh: u8) -> [u8; 40] {
    let mut p = [0u8; 40];
    p[..16].copy_from_slice(&hdr.src);
    p[16..32].copy_from_slice(&hdr.dst);
    p[32..36].copy_from_slice(&plen.to_be_bytes());
    p[36..40].copy_from_slice(&(nh as u32).to_be_bytes());
    p
}

/// Build a full R8 packet carrying a CTL message.
pub fn build_ctl(hdr: &Header, ctype: u8, code: u8, body: &[u8], with_checksum: bool) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(ctype);
    msg.push(code);
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(body);
    if with_checksum {
        let c = checksum16(&pseudo_header(hdr, msg.len() as u32, NH_CTL), &msg);
        msg[2..4].copy_from_slice(&c.to_be_bytes());
    }
    hdr.pack(&msg)
}

/// Parse a CTL payload; `ok` is the checksum verdict (true when checksum is absent).
pub fn parse_ctl<'a>(
    hdr: &Header,
    payload: &'a [u8],
) -> Result<(u8, u8, u16, &'a [u8], bool), &'static str> {
    if payload.len() < 4 {
        return Err("short ctl");
    }
    let csum = u16::from_be_bytes([payload[2], payload[3]]);
    let ok = csum == 0 || checksum16(&pseudo_header(hdr, payload.len() as u32, NH_CTL), payload) == 0;
    Ok((payload[0], payload[1], csum, &payload[4..], ok))
}

/// Build a full R8 packet carrying a DGRAM message.
pub fn build_dgram(hdr: &Header, sport: u16, dport: u16, data: &[u8], with_checksum: bool) -> Vec<u8> {
    let length = (8 + data.len()) as u16;
    let mut msg = Vec::with_capacity(length as usize);
    msg.extend_from_slice(&sport.to_be_bytes());
    msg.extend_from_slice(&dport.to_be_bytes());
    msg.extend_from_slice(&length.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(data);
    if with_checksum {
        let c = checksum16(&pseudo_header(hdr, msg.len() as u32, NH_DGRAM), &msg);
        msg[6..8].copy_from_slice(&c.to_be_bytes());
    }
    hdr.pack(&msg)
}

/// Parse a DGRAM payload -> (sport, dport, data, checksum_ok).
pub fn parse_dgram<'a>(
    hdr: &Header,
    payload: &'a [u8],
) -> Result<(u16, u16, &'a [u8], bool), &'static str> {
    if payload.len() < 8 {
        return Err("short dgram");
    }
    let length = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    if length < 8 || payload.len() < length {
        return Err("bad dgram length");
    }
    let csum = u16::from_be_bytes([payload[6], payload[7]]);
    let ok = csum == 0 || checksum16(&pseudo_header(hdr, payload.len() as u32, NH_DGRAM), payload) == 0;
    let sport = u16::from_be_bytes([payload[0], payload[1]]);
    let dport = u16::from_be_bytes([payload[2], payload[3]]);
    Ok((sport, dport, &payload[8..length], ok))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(s: &str) -> Loc {
        parse_loc(s).unwrap()
    }

    #[test]
    fn header_roundtrip() {
        let mut h = Header::new(NH_CTL, loc("8:1::10"), loc("8:1::20"));
        h.scid = 0x1122_3344_5566_7788;
        let raw = h.pack(b"hello");
        assert_eq!(raw.len(), HEADER_LEN + 5);
        let (h2, pl) = Header::unpack(&raw).unwrap();
        assert_eq!(pl, b"hello");
        assert_eq!(h2, h);
    }

    #[test]
    fn rejects_bad_version_and_truncation() {
        let h = Header::new(NH_CTL, loc("8:1::10"), loc("8:1::20"));
        let mut raw = h.pack(b"abc");
        raw[0] = 6 << 4; // IPv6 masquerading as R8
        assert!(Header::unpack(&raw).is_err());
        let raw = h.pack(b"abc");
        assert!(Header::unpack(&raw[..raw.len() - 1]).is_err());
    }

    #[test]
    fn ctl_checksum_detects_corruption() {
        let h = Header::new(NH_CTL, loc("8:1::10"), loc("8:1::20"));
        let pkt = build_ctl(&h, CTL_ECHO_REQUEST, 0, &[0, 7, 0, 42], true);
        let (h3, p3) = Header::unpack(&pkt).unwrap();
        let (t, _c, _s, body, ok) = parse_ctl(&h3, p3).unwrap();
        assert!(ok && t == CTL_ECHO_REQUEST && body == [0, 7, 0, 42]);
        let mut bad = pkt.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xff;
        let (hb, pb) = Header::unpack(&bad).unwrap();
        assert!(!parse_ctl(&hb, pb).unwrap().4);
    }

    #[test]
    fn dgram_roundtrip() {
        let h = Header::new(NH_DGRAM, loc("8:1::10"), loc("8:1::20"));
        let pkt = build_dgram(&h, 1000, 9000, b"ping", true);
        let (hd, pd) = Header::unpack(&pkt).unwrap();
        let (sp, dp, data, ok) = parse_dgram(&hd, pd).unwrap();
        assert!(ok && sp == 1000 && dp == 9000 && data == b"ping");
    }
}
