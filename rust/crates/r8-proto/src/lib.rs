//! Strict R8 wire format v0.2 for a private, experimental closed lab.

use std::error::Error;
use std::fmt;

pub const R8_UDP_PORT: u16 = 52808;
pub const R8_ETHERTYPE: u16 = 0x88B5;
pub const VERSION: u8 = 8;
pub const HEADER_LEN: usize = 48;
pub const SERIALIZED_R8_MAX: usize = 1280;

pub const NH_CTL: u8 = 1;
pub const NH_DGRAM: u8 = 2;
pub const NH_SES: u8 = 3;
pub const NH_NONE: u8 = 59;

pub const CTL_ECHO_REQUEST: u8 = 1;
pub const CTL_ECHO_REPLY: u8 = 2;
pub const CTL_DEST_UNREACHABLE: u8 = 128;
pub const CTL_TIME_EXCEEDED: u8 = 129;
pub const CTL_PACKET_TOO_BIG: u8 = 130;

pub type Loc = [u8; 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    Truncated,
    TrailingBytes,
    PacketCap,
    BindingBudget,
    LengthOverflow,
    Version,
    Profile,
    TrafficClass,
    NextHeader,
    HopLimit,
    Flags,
    PathSlot,
    Scid,
    NonePayload,
    CtlShort,
    CtlType,
    CtlCode,
    CtlBody,
    CtlChecksum,
    DgramShort,
    DgramLength,
    DgramChecksum,
}

impl WireError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Truncated => "TRUNCATED",
            Self::TrailingBytes => "TRAILING_BYTES",
            Self::PacketCap => "PACKET_CAP",
            Self::BindingBudget => "BINDING_BUDGET",
            Self::LengthOverflow => "LENGTH_OVERFLOW",
            Self::Version => "VERSION",
            Self::Profile => "PROFILE",
            Self::TrafficClass => "TRAFFIC_CLASS",
            Self::NextHeader => "NEXT_HEADER",
            Self::HopLimit => "HOP_LIMIT",
            Self::Flags => "FLAGS",
            Self::PathSlot => "PATH_SLOT",
            Self::Scid => "SCID",
            Self::NonePayload => "NONE_PAYLOAD",
            Self::CtlShort => "CTL_SHORT",
            Self::CtlType => "CTL_TYPE",
            Self::CtlCode => "CTL_CODE",
            Self::CtlBody => "CTL_BODY",
            Self::CtlChecksum => "CTL_CHECKSUM",
            Self::DgramShort => "DGRAM_SHORT",
            Self::DgramLength => "DGRAM_LENGTH",
            Self::DgramChecksum => "DGRAM_CHECKSUM",
        }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for WireError {}

pub fn parse_loc(s: &str) -> Result<Loc, std::net::AddrParseError> {
    Ok(s.parse::<std::net::Ipv6Addr>()?.octets())
}

pub fn fmt_loc(l: &Loc) -> String {
    std::net::Ipv6Addr::from(*l).to_string()
}

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

fn checked_packet_len(payload_len: usize, budget: usize) -> Result<usize, WireError> {
    if payload_len > u16::MAX as usize {
        return Err(WireError::LengthOverflow);
    }
    let total = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(WireError::LengthOverflow)?;
    if total > SERIALIZED_R8_MAX {
        return Err(WireError::PacketCap);
    }
    if total > budget {
        return Err(WireError::BindingBudget);
    }
    Ok(total)
}

impl Header {
    pub fn new(next_header: u8, src: Loc, dst: Loc) -> Self {
        Self {
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

    pub fn pack(&self, payload: &[u8]) -> Result<Vec<u8>, WireError> {
        self.pack_with_budget(payload, SERIALIZED_R8_MAX)
    }

    pub fn pack_with_budget(&self, payload: &[u8], budget: usize) -> Result<Vec<u8>, WireError> {
        let total = checked_packet_len(payload.len(), budget)?;
        validate_header(self, payload)?;
        let payload_len = u16::try_from(payload.len()).map_err(|_| WireError::LengthOverflow)?;
        let mut out = Vec::with_capacity(total);
        out.push((VERSION << 4) | self.profile);
        out.push(self.tc);
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.push(self.next_header);
        out.push(self.hop_limit);
        out.push(self.flags);
        out.push(self.path_slot);
        out.extend_from_slice(&self.scid.to_be_bytes());
        out.extend_from_slice(&self.src);
        out.extend_from_slice(&self.dst);
        out.extend_from_slice(payload);
        Ok(out)
    }

    pub fn unpack(data: &[u8]) -> Result<(Header, &[u8]), WireError> {
        Self::unpack_with_budget(data, SERIALIZED_R8_MAX)
    }

    pub fn unpack_with_budget(data: &[u8], budget: usize) -> Result<(Header, &[u8]), WireError> {
        if data.len() > SERIALIZED_R8_MAX {
            return Err(WireError::PacketCap);
        }
        if data.len() > budget {
            return Err(WireError::BindingBudget);
        }
        if data.len() < HEADER_LEN {
            return Err(WireError::Truncated);
        }
        let payload_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
        let expected = HEADER_LEN
            .checked_add(payload_len)
            .ok_or(WireError::LengthOverflow)?;
        if data.len() < expected {
            return Err(WireError::Truncated);
        }
        if data.len() > expected {
            return Err(WireError::TrailingBytes);
        }
        if data[0] >> 4 != VERSION {
            return Err(WireError::Version);
        }
        if !matches!(data[4], NH_CTL | NH_DGRAM | NH_SES | NH_NONE) {
            return Err(WireError::NextHeader);
        }
        let mut src = [0; 16];
        src.copy_from_slice(&data[16..32]);
        let mut dst = [0; 16];
        dst.copy_from_slice(&data[32..48]);
        let header = Header {
            profile: data[0] & 0x0f,
            tc: data[1],
            next_header: data[4],
            hop_limit: data[5],
            flags: data[6],
            path_slot: data[7],
            scid: u64::from_be_bytes(data[8..16].try_into().map_err(|_| WireError::Truncated)?),
            src,
            dst,
        };
        let payload = &data[HEADER_LEN..expected];
        validate_header(&header, payload)?;
        Ok((header, payload))
    }
}

fn validate_header(header: &Header, payload: &[u8]) -> Result<(), WireError> {
    if !matches!(header.next_header, NH_CTL | NH_DGRAM | NH_SES | NH_NONE) {
        return Err(WireError::NextHeader);
    }
    if header.next_header == NH_SES {
        return validate_ses_header(header, payload);
    }
    if header.profile > 3 {
        return Err(WireError::Profile);
    }
    if header.tc != 0 {
        return Err(WireError::TrafficClass);
    }
    if header.hop_limit == 0 {
        return Err(WireError::HopLimit);
    }
    if header.flags & !0x03 != 0 {
        return Err(WireError::Flags);
    }
    match header.next_header {
        NH_CTL => {
            if header.profile != 0 {
                return Err(WireError::Profile);
            }
            if header.flags != 0 {
                return Err(WireError::Flags);
            }
            if header.path_slot != 0 {
                return Err(WireError::PathSlot);
            }
            if header.scid != 0 {
                return Err(WireError::Scid);
            }
            parse_ctl(header, payload)?;
        }
        NH_DGRAM => {
            if header.profile != 0 {
                return Err(WireError::Profile);
            }
            if header.flags != 0 {
                return Err(WireError::Flags);
            }
            if header.path_slot != 0 {
                return Err(WireError::PathSlot);
            }
            if header.scid != 0 {
                return Err(WireError::Scid);
            }
            parse_dgram(header, payload)?;
        }
        NH_NONE => {
            if header.profile != 0 {
                return Err(WireError::Profile);
            }
            if header.flags != 0 {
                return Err(WireError::Flags);
            }
            if header.path_slot != 0 {
                return Err(WireError::PathSlot);
            }
            if header.scid != 0 {
                return Err(WireError::Scid);
            }
            if !payload.is_empty() {
                return Err(WireError::NonePayload);
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn validate_ses_header(header: &Header, payload: &[u8]) -> Result<(), WireError> {
    if header.scid == 0 {
        return Err(WireError::Scid);
    }
    if payload.len() < 4 {
        return Err(WireError::Truncated);
    }
    let typ = payload[0];
    if !matches!(typ, 1..=7) || payload[1] != 1 {
        return Err(WireError::NextHeader);
    }
    if header.profile > 3 || payload[2] != header.profile {
        return Err(WireError::Profile);
    }
    if header.tc != 0 {
        return Err(WireError::TrafficClass);
    }
    if header.hop_limit == 0 {
        return Err(WireError::HopLimit);
    }
    if payload[3] != 0 || header.flags & !0x03 != 0 {
        return Err(WireError::Flags);
    }
    match typ {
        1..=4 => {
            if header.flags != 0 {
                return Err(WireError::Flags);
            }
            if header.path_slot != 0 {
                return Err(WireError::PathSlot);
            }
        }
        5 => {
            if header.flags != 1 {
                return Err(WireError::Flags);
            }
            if header.path_slot != 0 {
                return Err(WireError::PathSlot);
            }
        }
        6 | 7 if header.profile == 3 => {
            if !matches!(header.flags, 1 | 3) {
                return Err(WireError::Flags);
            }
            let expected_slot = if header.flags == 1 { 0 } else { 1 };
            if header.path_slot != expected_slot {
                return Err(WireError::PathSlot);
            }
        }
        6 | 7 => {
            if header.flags != 1 {
                return Err(WireError::Flags);
            }
            if header.path_slot != 0 {
                return Err(WireError::PathSlot);
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn sum16(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut pairs = data.chunks_exact(2);
    for pair in &mut pairs {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if let [last] = pairs.remainder() {
        sum += u32::from(*last) << 8;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

fn checksum_raw(pseudo: &[u8], body: &[u8]) -> u16 {
    let mut sum = sum16(pseudo) + sum16(body);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    match u16::try_from(sum) {
        Ok(folded) => !folded,
        Err(_) => 0,
    }
}

pub fn checksum16(pseudo: &[u8], body: &[u8]) -> u16 {
    let checksum = checksum_raw(pseudo, body);
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

pub fn pseudo_header(header: &Header, payload_len: u32, next_header: u8) -> [u8; 40] {
    let mut pseudo = [0; 40];
    pseudo[..16].copy_from_slice(&header.src);
    pseudo[16..32].copy_from_slice(&header.dst);
    pseudo[32..36].copy_from_slice(&payload_len.to_be_bytes());
    pseudo[36..40].copy_from_slice(&u32::from(next_header).to_be_bytes());
    pseudo
}

fn checksum_valid(header: &Header, payload: &[u8], next_header: u8) -> bool {
    checksum_raw(
        &pseudo_header(
            header,
            u32::try_from(payload.len()).unwrap_or(u32::MAX),
            next_header,
        ),
        payload,
    ) == 0
}

fn validate_ctl(typ: u8, code: u8, body: &[u8]) -> Result<(), WireError> {
    match typ {
        CTL_ECHO_REQUEST | CTL_ECHO_REPLY => {
            if code != 0 {
                return Err(WireError::CtlCode);
            }
            if body.len() < 4 {
                return Err(WireError::CtlBody);
            }
        }
        CTL_DEST_UNREACHABLE => {
            if !matches!(code, 0 | 1 | 3 | 4) {
                return Err(WireError::CtlCode);
            }
            if body.len() > 512 {
                return Err(WireError::CtlBody);
            }
        }
        CTL_TIME_EXCEEDED => {
            if code != 0 {
                return Err(WireError::CtlCode);
            }
            if body.len() > 512 {
                return Err(WireError::CtlBody);
            }
        }
        CTL_PACKET_TOO_BIG => {
            if code != 0 {
                return Err(WireError::CtlCode);
            }
            if body.len() < 4 || body.len() - 4 > 512 {
                return Err(WireError::CtlBody);
            }
        }
        _ => return Err(WireError::CtlType),
    }
    Ok(())
}

fn validate_ctl_shape(payload: &[u8]) -> Result<(), WireError> {
    if payload.len() < 4 {
        return Err(WireError::CtlShort);
    }
    validate_ctl(payload[0], payload[1], &payload[4..])
}

pub fn build_ctl(header: &Header, ctype: u8, code: u8, body: &[u8]) -> Result<Vec<u8>, WireError> {
    build_ctl_with_budget(header, ctype, code, body, SERIALIZED_R8_MAX)
}

pub fn build_ctl_with_budget(
    header: &Header,
    ctype: u8,
    code: u8,
    body: &[u8],
    budget: usize,
) -> Result<Vec<u8>, WireError> {
    if header.next_header != NH_CTL {
        return Err(WireError::NextHeader);
    }
    let length = 4usize
        .checked_add(body.len())
        .ok_or(WireError::LengthOverflow)?;
    checked_packet_len(length, budget)?;
    validate_ctl(ctype, code, body)?;
    let mut payload = Vec::with_capacity(length);
    payload.extend_from_slice(&[ctype, code, 0, 0]);
    payload.extend_from_slice(body);
    let checksum = checksum16(
        &pseudo_header(
            header,
            u32::try_from(length).map_err(|_| WireError::LengthOverflow)?,
            NH_CTL,
        ),
        &payload,
    );
    payload[2..4].copy_from_slice(&checksum.to_be_bytes());
    header.pack_with_budget(&payload, budget)
}

pub fn parse_ctl<'a>(header: &Header, payload: &'a [u8]) -> Result<(u8, u8, &'a [u8]), WireError> {
    validate_ctl_shape(payload)?;
    if u16::from_be_bytes([payload[2], payload[3]]) == 0 || !checksum_valid(header, payload, NH_CTL)
    {
        return Err(WireError::CtlChecksum);
    }
    Ok((payload[0], payload[1], &payload[4..]))
}

fn validate_dgram_shape(payload: &[u8]) -> Result<(), WireError> {
    if payload.len() < 8 {
        return Err(WireError::DgramShort);
    }
    let declared = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
    if declared != payload.len() {
        return Err(WireError::DgramLength);
    }
    Ok(())
}

pub fn build_dgram(
    header: &Header,
    sport: u16,
    dport: u16,
    data: &[u8],
) -> Result<Vec<u8>, WireError> {
    build_dgram_with_budget(header, sport, dport, data, SERIALIZED_R8_MAX)
}

pub fn build_dgram_with_budget(
    header: &Header,
    sport: u16,
    dport: u16,
    data: &[u8],
    budget: usize,
) -> Result<Vec<u8>, WireError> {
    if header.next_header != NH_DGRAM {
        return Err(WireError::NextHeader);
    }
    let length = 8usize
        .checked_add(data.len())
        .ok_or(WireError::LengthOverflow)?;
    checked_packet_len(length, budget)?;
    let length_u16 = u16::try_from(length).map_err(|_| WireError::LengthOverflow)?;
    let mut payload = Vec::with_capacity(length);
    payload.extend_from_slice(&sport.to_be_bytes());
    payload.extend_from_slice(&dport.to_be_bytes());
    payload.extend_from_slice(&length_u16.to_be_bytes());
    payload.extend_from_slice(&[0, 0]);
    payload.extend_from_slice(data);
    let checksum = checksum16(
        &pseudo_header(
            header,
            u32::try_from(length).map_err(|_| WireError::LengthOverflow)?,
            NH_DGRAM,
        ),
        &payload,
    );
    payload[6..8].copy_from_slice(&checksum.to_be_bytes());
    header.pack_with_budget(&payload, budget)
}

pub fn parse_dgram<'a>(
    header: &Header,
    payload: &'a [u8],
) -> Result<(u16, u16, &'a [u8]), WireError> {
    validate_dgram_shape(payload)?;
    if u16::from_be_bytes([payload[6], payload[7]]) == 0
        || !checksum_valid(header, payload, NH_DGRAM)
    {
        return Err(WireError::DgramChecksum);
    }
    Ok((
        u16::from_be_bytes([payload[0], payload[1]]),
        u16::from_be_bytes([payload[2], payload[3]]),
        &payload[8..],
    ))
}
#[cfg(test)]
mod tests {
    use super::*;

    fn header(next_header: u8) -> Header {
        Header::new(next_header, [0; 16], [0; 16])
    }

    fn body_for_zero_checksum(header: &Header, next_header: u8, prefix: &[u8]) -> [u8; 2] {
        for value in 0..=u16::MAX {
            let mut payload = prefix.to_vec();
            payload.extend_from_slice(&value.to_be_bytes());
            if checksum_raw(
                &pseudo_header(header, u32::try_from(payload.len()).unwrap(), next_header),
                &payload,
            ) == 0
            {
                return value.to_be_bytes();
            }
        }
        panic!("a 16-bit checksum complement must exist");
    }

    #[test]
    fn builders_encode_computed_zero_as_ffff_and_parsers_accept_it() {
        let ctl_header = header(NH_CTL);
        let ctl_prefix = [CTL_ECHO_REQUEST, 0, 0, 0, 0, 0];
        let ctl_tail = body_for_zero_checksum(&ctl_header, NH_CTL, &ctl_prefix);
        let ctl_packet = build_ctl(
            &ctl_header,
            CTL_ECHO_REQUEST,
            0,
            &[0, 0, ctl_tail[0], ctl_tail[1]],
        )
        .unwrap();
        let (ctl_header, ctl_payload) = Header::unpack(&ctl_packet).unwrap();
        assert_eq!(&ctl_payload[2..4], &[0xff, 0xff]);
        assert!(parse_ctl(&ctl_header, ctl_payload).is_ok());

        let dgram_header = header(NH_DGRAM);
        let dgram_prefix = [0, 1, 0, 2, 0, 10, 0, 0];
        let dgram_tail = body_for_zero_checksum(&dgram_header, NH_DGRAM, &dgram_prefix);
        let dgram_packet = build_dgram(&dgram_header, 1, 2, &dgram_tail).unwrap();
        let (dgram_header, dgram_payload) = Header::unpack(&dgram_packet).unwrap();
        assert_eq!(&dgram_payload[6..8], &[0xff, 0xff]);
        assert!(parse_dgram(&dgram_header, dgram_payload).is_ok());
    }

    #[test]
    fn profile_three_session_data_allows_primary_and_redundant_pairs_only() {
        let mut session = header(NH_SES);
        session.profile = 3;
        session.scid = 1;
        let envelope = [6, 1, 3, 0];

        session.flags = 1;
        session.path_slot = 0;
        assert_eq!(validate_ses_header(&session, &envelope), Ok(()));

        session.flags = 3;
        session.path_slot = 1;
        assert_eq!(validate_ses_header(&session, &envelope), Ok(()));

        session.flags = 1;
        session.path_slot = 1;
        assert_eq!(
            validate_ses_header(&session, &envelope),
            Err(WireError::PathSlot)
        );

        session.flags = 3;
        session.path_slot = 0;
        assert_eq!(
            validate_ses_header(&session, &envelope),
            Err(WireError::PathSlot)
        );

        session.flags = 0;
        session.path_slot = 0;
        assert_eq!(
            validate_ses_header(&session, &envelope),
            Err(WireError::Flags)
        );

        session.flags = 2;
        assert_eq!(
            validate_ses_header(&session, &envelope),
            Err(WireError::Flags)
        );
    }

    #[test]
    fn ses_validation_uses_contract_precedence() {
        let mut session = header(NH_SES);
        session.profile = 3;
        session.scid = 1;
        let envelope = [6, 1, 3, 0];

        session.tc = 1;
        session.hop_limit = 0;
        session.flags = 0;
        session.path_slot = 1;
        assert_eq!(
            validate_ses_header(&session, &envelope),
            Err(WireError::TrafficClass)
        );

        session.tc = 0;
        assert_eq!(
            validate_ses_header(&session, &envelope),
            Err(WireError::HopLimit)
        );

        session.hop_limit = 64;
        assert_eq!(
            validate_ses_header(&session, &envelope),
            Err(WireError::Flags)
        );

        session.flags = 1;
        assert_eq!(
            validate_ses_header(&session, &envelope),
            Err(WireError::PathSlot)
        );
    }

    #[test]
    fn unknown_next_header_preempts_all_other_header_conflicts() {
        let mut packet = [0u8; HEADER_LEN];
        packet[0] = (VERSION << 4) | 0x0f;
        packet[1] = 1;
        packet[4] = 4;
        packet[5] = 0;
        packet[6] = 0xff;
        packet[7] = 1;
        packet[8..16].copy_from_slice(&1u64.to_be_bytes());
        assert_eq!(Header::unpack(&packet), Err(WireError::NextHeader));
    }
}
