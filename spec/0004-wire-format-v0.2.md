# R8 Wire Format v0.2

> Status: normative Gate-0 contract for the private, experimental, closed-lab R8 protocol. This is not an Internet standard.

## 1. Revision selection and scope

This is the single active strict wire contract. It replaces v0.1 for a clean deployment/configuration cutover while retaining header Version nibble `8` and the 48-byte header layout. An implementation is configured for either this contract or no R8 wire service; it MUST NOT accept v0.1's permissive packet language. There is no dual parser, on-wire negotiation, compatibility path, or shim.

All integers are unsigned big-endian. The serialized R8 packet maximum and carrier budget formulas are `P-SERIALIZED-R8-MAX`, `P-UDP-BINDING-BUDGET`, and `P-NATIVE-BINDING-BUDGET` in `parameters-v0.1.md`; those parameter IDs and values are unchanged. A serializer MUST check every source length before conversion to `u16`, reject a payload length above `65535`, reject a complete packet above the applicable binding budget or 1280-byte serialized cap, and never fragment. A receiver MUST apply the same cap before allocating payload storage.

## 2. Fixed header

Every packet is exactly a 48-byte header followed by exactly `Payload Length` bytes:

| Offset | Bytes | Field | Required value/rule |
|---:|---:|---|---|
| 0 | 1 | Version / Profile | high nibble exactly `8`; low nibble is Profile below |
| 1 | 1 | Traffic Class | exactly `0` |
| 2 | 2 | Payload Length | exact following byte count |
| 4 | 1 | Next Header | `1=CTL`, `2=DGRAM`, `3=SES`, `59=NONE` only |
| 5 | 1 | Hop Limit | nonzero on transmit and receive; forwarding decrements once and drops instead of emitting a packet when it would become zero |
| 6 | 1 | Flags | only defined flag combinations below |
| 7 | 1 | Path Slot | constrained by profile and next header below |
| 8 | 8 | SCID | constrained by next header below |
| 16 | 16 | Source LOC | exact bytes; no textual encoding on wire |
| 32 | 16 | Destination LOC | exact bytes; no textual encoding on wire |

The received datagram/frame length MUST equal `48 + Payload Length` exactly. Truncation and trailing bytes are errors. `Payload Length` is encoded only after checked validation; no narrowing cast is permitted. After packet cap, applicable binding budget, the 48-byte minimum, and exact received length, the parser checks the header Version first and then the Next Header allow-list. An unsupported Next Header is `NEXT_HEADER` before profile, Traffic Class, Hop Limit, flags, Path Slot, or SCID validation.

Allowed Profiles are `0`, `1`, `2`, and `3`; profiles `4` through `15` are reserved and rejected. Header flags are `V=0x01` (protected session) and `R=0x02` (redundant copy); all other bits are reserved and rejected. CTL, DGRAM, and NONE have the following complete header rules:

| Next Header | Profile | Flags | Path Slot | SCID | Payload rule |
|---|---|---|---|---|---|
| CTL | 0 | `0x00` | 0 | 0 | strict CTL below |
| DGRAM | 0 | `0x00` | 0 | 0 | strict DGRAM below |
| NONE | 0 | `0x00` | 0 | 0 | Payload Length exactly 0 |

A SES packet has nonzero SCID and a payload of at least the four-byte canonical SES envelope. After exact packet length and fixed-header field validation, the parser reads that envelope's `type`, `session_version`, `profile`, and reserved SES flags without allocating session state. It accepts the outer header only if `session_version=1`, the SES profile equals the header Profile, SES flags are zero, and this type-aware rule holds:

| SES type | Header Profile | Header Flags | Path Slot |
|---:|---|---|---|
| 1 `OPEN`, 2 `VERIFY_COOKIE`, 3 `OPEN_AUTH`, 4 `OPEN_ACK` | 0, 1, 2, or 3 | `0x00` | 0 |
| 5 `SESSION_ACCEPT` | 0, 1, 2, or 3 | `0x01` | 0 |
| 6 `SESSION_DATA`, 7 `CLOSE` | 0, 1, or 2 | `0x01` | 0 |
| 6 `SESSION_DATA`, 7 `CLOSE` | 3 | `0x01` | 0 |
| 6 `SESSION_DATA`, 7 `CLOSE` | 3 | `0x03` | 1 |

The type and envelope fields remain subject to the exact SES body rules in `0005-session-security-v0.1.md`; unknown SES types are rejected. Thus Profile 3's initial handshake is permitted only unprotected on slot zero, `SESSION_ACCEPT` is protected on slot zero, and application data is never unprotected. `R` is otherwise rejected. Every other fixed-header combination, including CTL/DGRAM with a session context, protected CTL/DGRAM, Profile 3 without SES, a nonzero path slot outside the permitted Profile-3 SES rows, or a reserved flag, is rejected. For protected SES types, the full 48-byte header, including flags and Path Slot, is authenticated AEAD associated data; flags confer no authority by themselves.
For `SES` outer-envelope rejection, after packet-cap, applicable-binding-budget, 48-byte-header minimum, and exact-received-length checks, dispatch on header Version and the Next Header allow-list before applying the following `SES` order. A zero SCID is `SCID`; a payload shorter than the four-byte SES envelope is `TRUNCATED`; an unknown SES type or `session_version` other than `1` is `NEXT_HEADER`; a reserved SES or header profile, or a SES/header profile mismatch, is `PROFILE`; a nonzero Traffic Class is `TRAFFIC_CLASS`; a zero Hop Limit is `HOP_LIMIT`; nonzero SES envelope flags or a header flag combination not allowed for the resolved type/profile is `FLAGS`; otherwise a path-slot mismatch is `PATH_SLOT`. This SES order intentionally precedes conflicting generic profile, Traffic Class, Hop Limit, and flag checks. The parser reads no session body semantics at this stage; those remain exclusively the M2 session contract.

## 3. Checksum definition

For CTL and DGRAM only, `Checksum` is the 16-bit one's-complement checksum of this exact byte sequence:

```
Source LOC (16) || Destination LOC (16) || Payload Length as u32 (4) ||
Next Header as u32 (4) || exact declared payload bytes with checksum field zeroed
```

Odd-length input is padded with one zero byte solely for checksum arithmetic. A computed zero is transmitted as `0xffff`. A received checksum of `0x0000` is invalid. The checksum field is included as two zero bytes during computation; no carrier bytes, trailing bytes, or undeclared bytes participate.

## 4. CTL (`Next Header=1`)

CTL is exactly `type:u8 || code:u8 || checksum:u16 || body`. Its checksum is mandatory and nonzero. Type, code, and body minimums are:

| Type | Name | Allowed code | Minimum body | Additional strict rule |
|---:|---|---|---:|---|
| 1 | ECHO_REQUEST | 0 | 4 | first four body bytes are Identifier:u16 and Sequence:u16 |
| 2 | ECHO_REPLY | 0 | 4 | first four body bytes are Identifier:u16 and Sequence:u16 |
| 128 | DEST_UNREACHABLE | 0, 1, 3, 4 | 0 | quoted bytes, if present, at most 512 |
| 129 | TIME_EXCEEDED | 0 | 0 | quoted bytes, if present, at most 512 |
| 130 | PACKET_TOO_BIG | 0 | 4 | first four body bytes are MTU:u32; quoted bytes thereafter at most 512 |

A CTL payload shorter than four bytes, an unknown type, an unlisted code, a body shorter than the listed minimum, a quote over 512 bytes, or a failed checksum is rejected. An implementation MUST NOT generate an error in response to any received CTL error type (`>=128`).

## 5. DGRAM (`Next Header=2`)

DGRAM is exactly `source_port:u16 || destination_port:u16 || length:u16 || checksum:u16 || data`. The payload is at least eight bytes. `length` includes the DGRAM header and MUST equal both `Payload Length` and the exact received DGRAM byte count. Its checksum is mandatory and nonzero and is computed over the exact declared DGRAM span defined in section 3. A zero, shorter, longer, truncated, or trailing DGRAM length is rejected before delivery. No transport retransmission, ordering, or congestion behavior is implied.

## 6. SES (`Next Header=3`) and carrier use

SES structure, cryptographic validation, and state are exclusively `0005-session-security-v0.1.md`; locator controls and typed bindings are `0006-mobility-v0.1.md`; native framing and forwarding are `0007-native-binding-v0.1.md`; Profile-3 delivery is `0008-redundant-v0.1.md`. SES parsing begins only after this document's exact packet-length, header, profile, flag, slot, and SCID validation succeeds. The full 48-byte header is included in session AEAD associated data as required by the session contract.

UDP carries exactly one serialized R8 packet per UDP payload. Native carries exactly one serialized R8 packet after Ethernet II EtherType `0x88B5`. Carrier padding, aggregation, and fragmentation are not R8 bytes and are rejected where they make the exact packet length ambiguous.

## 7. Typed errors and fail-closed behavior

Wire parsing reports exactly one finite `WireError`: `TRUNCATED`, `TRAILING_BYTES`, `PACKET_CAP`, `BINDING_BUDGET`, `LENGTH_OVERFLOW`, `VERSION`, `PROFILE`, `TRAFFIC_CLASS`, `NEXT_HEADER`, `HOP_LIMIT`, `FLAGS`, `PATH_SLOT`, `SCID`, `NONE_PAYLOAD`, `CTL_SHORT`, `CTL_TYPE`, `CTL_CODE`, `CTL_BODY`, `CTL_CHECKSUM`, `DGRAM_SHORT`, `DGRAM_LENGTH`, or `DGRAM_CHECKSUM`. Unknown or reserved values always select their corresponding finite error and are never ignored.

A received wire error drops the packet without delivery, forwarding, session allocation, replay mutation, timer refresh, or error-packet generation. Serializer budget failures use `E-BUDGET`; malformed/unknown wire inputs are fail-closed local parser failures and do not weaken the registry's `E-COOKIE`, `E-CAPACITY`, `E-SCID`, `E-COUNTER`, `E-REPLAY`, `E-CANDIDATE`, or `E-PATH` outcomes. Implementations may count finite categories but MUST NOT log secrets or unbounded identifiers.
