# R8 Session Security v0.1

> Status: normative Gate-0 contract for the private, experimental, closed-lab R8 protocol. This document is not an Internet standard.

## 1. Scope and constants

This document defines the `SES` payload (`Next Header=3`) for protected R8 sessions. It supplements the fixed 48-byte header and strict accepted packet language in `0004-wire-format-v0.2.md`; it does not change them. All multibyte integers are unsigned, big-endian. A parser rejects truncation, trailing bytes, non-canonical encodings, reserved values, and unsupported message types before any state mutation.

`spec/parameters-v0.1.md` is normative for every resource, rate, timeout, capacity, amplification, replay, cookie, and packet-size limit. `P-SESSION-COUNTER-MAX`, `P-COUNTER-RESERVED`, and `P-COUNTER-USABLE-RANGE` define the counter domain; `P-REPLAY-WINDOW` and `P-REPLAY-FORWARD-GAP-MAX` define replay handling, and `P-REPLAY-FORWARD-JUMP-MAX` is its exact alias. `P-OPEN-TOTAL-TIMEOUT`, `P-POST-COOKIE-PENDING-TIMEOUT`, `P-HANDSHAKE-RETRY-SCHEDULE`, `P-PENDING-SESSIONS-MAX`, `P-ESTABLISHED-SESSIONS-MAX`, and `P-SESSION-IDLE-TIMEOUT` define all handshake/session deadlines and capacities. `P-VERIFY-COOKIE-MAX-RESPONSE`, `P-PREVALIDATION-CUMULATIVE-RATIO`, `P-PREVALIDATION-SOURCE-TABLE-MAX`, `P-PREVALIDATION-GLOBAL-BURST`, and `P-PREVALIDATION-GLOBAL-REFILL` define prevalidation controls.

An experiment manifest is an immutable startup input. For every `(local_role, service_context)` it maps the expected remote role, remote EID128, and complete 32-byte Ed25519 public key. `service_context` is a manifest-defined nonzero `u32`; a peer is authorized only when all four values match. EID128 is `first128(SHA-256("R8 EID v1" || ed25519_public_key))`, in network byte order. A full key match is always required; EID equality alone is insufficient.

The only allowed algorithms are Ed25519, X25519, HKDF-SHA256, HMAC-SHA256, ChaCha20-Poly1305, and OS CSPRNG. Implementations use maintained library APIs and do not implement primitives. There is no alternate security mode, downgrade path, or in-session rekey.

## 2. Canonical SES encoding

Every SES payload starts with:

| Offset | Field | Encoding |
|---:|---|---|
| 0 | `type` | `u8` below |
| 1 | `session_version` | `u8`, exactly `1` |
| 2 | `profile` | `u8`, exactly the header Profile |
| 3 | `flags` | `u8`, exactly zero |

`role` is `u8`: `1=client`, `2=server`; all other values fail. Each message has exactly the following body after this four-byte prefix. `SCID` is the nonzero header Session Context ID and is never duplicated in a body.

| Type | Name | Exact body, in order |
|---:|---|---|
| 1 | `OPEN` | `sender_role:u8, receiver_role:u8, service_context:u32, sender_eid:16, sender_public_key:32, sender_ephemeral:32, sender_nonce:32` |
| 2 | `VERIFY_COOKIE` | `receiver_role:u8, sender_role:u8, service_context:u32, sender_public_key:32, sender_ephemeral_hash:32, server_boot_instance:16, cookie:32` |
| 3 | `OPEN_AUTH` | `sender_role:u8, receiver_role:u8, service_context:u32, sender_eid:16, sender_public_key:32, sender_ephemeral:32, sender_nonce:32, server_boot_instance:16, cookie:32, signature:64` |
| 4 | `OPEN_ACK` | `sender_role:u8, receiver_role:u8, service_context:u32, sender_eid:16, sender_public_key:32, sender_ephemeral:32, sender_nonce:32, signature:64` |
| 5 | `SESSION_ACCEPT` | `counter:u64, ciphertext_and_tag:60` |
| 6 | `SESSION_DATA` | `counter:u64, ciphertext_and_tag:variable` |
| 7 | `CLOSE` | `counter:u64, ciphertext_and_tag:18` |

For type 5, plaintext is exactly `"R8 ACCEPT v1"` (12 ASCII bytes) followed by `transcript_hash` (32 bytes), so its ciphertext-and-tag is 60 bytes. For type 6 plaintext is `delivery bytes` and the tag is exactly 16 bytes. For type 7 plaintext is `error_code:u16`; its ciphertext-and-tag is 18 bytes. Empty application data is permitted and is encoded as a 16-byte tag. The effective binding budget formula determines the maximum type-6 plaintext; serializers reject excess data and never fragment.

### 2.1 Outer-header admission

The strict outer-wire parser in `0004-wire-format-v0.2.md` reads only the bounded four-byte SES envelope before applying this table. All SES packets require a nonzero SCID, `session_version=1`, SES `profile` equal to header Profile, and SES flags equal to zero.

| SES type | Header Profile | Header Flags | Path Slot | Protection rule |
|---:|---|---|---|---|
| 1 `OPEN`, 2 `VERIFY_COOKIE`, 3 `OPEN_AUTH`, 4 `OPEN_ACK` | 0, 1, 2, or 3 | `0x00` | 0 | unprotected handshake only |
| 5 `SESSION_ACCEPT` | 0, 1, 2, or 3 | `V` (`0x01`) | 0 | protected AEAD only |
| 6 `SESSION_DATA`, 7 `CLOSE` | 0, 1, or 2 | `V` (`0x01`) | 0 | protected AEAD only |
| 6 `SESSION_DATA`, 7 `CLOSE` | 3 | `V` (`0x01`) | 0 | protected AEAD only |
| 6 `SESSION_DATA`, 7 `CLOSE` | 3 | `V|R` (`0x03`) | 1 | protected AEAD only |

`R` is rejected in every other case. Profile 3 may begin only with the unprotected slot-zero handshake rows; it may not send unprotected `SESSION_ACCEPT`, application data, or close traffic. The cookie-first allocation and authentication requirements in this document apply unchanged to the unprotected handshake rows.

For type 5, 6, and 7, AEAD associated data is the canonical 48-byte header formed from the exact serialized header with only byte offset 5 (Hop Limit) replaced by zero, followed by the four-byte SES prefix and the counter. Every other header byte, including header Profile, flags, Path Slot, SCID, LOCs, and payload length, is authenticated. Types 1–4 are not AEAD-protected and must never set `V` or `R`.

### 2.2 Canonical transcript and signatures


`T0` is the concatenation, without length prefixes, of:

```
ASCII("R8 session transcript v1") || wire_version:u8 || profile:u8 ||
SCID:u64 || client_role:u8 || server_role:u8 || service_context:u32 ||
client_eid:16 || client_public_key:32 || server_eid:16 || server_public_key:32 ||
client_ephemeral:32 || server_ephemeral:32 || client_nonce:32 || server_nonce:32 ||
server_boot_instance:16
```

The client signature in `OPEN_AUTH` is Ed25519 over `ASCII("R8 OPEN_AUTH v1") || T0`, where server fields are taken from `VERIFY_COOKIE` except the server key, ephemeral, and nonce are all-zero byte strings. The server signature in `OPEN_ACK` is Ed25519 over `ASCII("R8 OPEN_ACK v1") || T0`, with its actual fields. `transcript_hash = SHA-256(T0 || client_signature || server_signature)`. Canonical construction is byte concatenation exactly as shown; no text normalization or omitted field is permitted.

A cookie is `HMAC-SHA256(cookie_key, C)`, where `C` is `ASCII("R8 cookie v1") || observed_source_binding || wire_version:u8 || session_version:u8 || client_role:u8 || server_role:u8 || service_context:u32 || SCID:u64 || client_eid:16 || SHA-256(client_public_key) || SHA-256(client_ephemeral) || server_boot_instance:16 || bucket:u64 || server_context_id:u32`. `observed_source_binding` is the exact variant and canonical bytes of the shared `ObservedBinding = UdpBinding | NativeBinding` union defined in `0006-mobility-v0.1.md`; `server_context_id` is a nonzero immutable manifest `u32`. Cookie keys and bucket acceptance follow the parameters registry.

### 2.3 Key schedule, nonce, and AEAD

After verified signatures, both sides compute X25519 using their local ephemeral secret and the authenticated peer ephemeral public key. An all-zero shared result fails before HKDF. Let `PRK = HKDF-Extract(salt=transcript_hash, IKM=shared_secret)`. For each direction and path slot, derive a distinct 32-byte key with `HKDF-Expand(PRK, ASCII("R8 key v1") || wire_version || session_version || profile || transcript_hash || sender_role || receiver_role || path_slot, 32)`. Session v0.1 single-path traffic uses path slot zero.

For type 5, 6, or 7, AEAD associated data includes the canonical 48-byte header defined in section 2.1, concatenated with the four-byte SES prefix and `counter:u64`; Profile 3 `SESSION_DATA` (type 6) additionally includes `delivery_id:u64` as specified by `0008-redundant-v0.1.md`. `CLOSE` (type 7) never includes a delivery ID and retains its common protected body layout. The nonce is exactly `0x00000000 || counter_u64_be`. Usable send counters are exactly `1..u64::MAX-1`; counter zero is invalid and `u64::MAX` is reserved. A send atomically reserves its counter before encryption; it never wraps. Cached retransmission may resend only the identical already-encrypted serialized packet, never encrypt a different plaintext at that counter. Before exhaustion, close locally, release the session, and require a fresh cookie-authenticated handshake.
Handshake bootstrap transfer and every authenticated decrypt/data transaction are opaque one-shot handles. Canonical SCID, roles, LOCs, transcript, schedule, sessions, counter, close bit, delivery ID, and plaintext authority remain in implementation-private owner state rather than caller-writable fields; changing an ordinary facade or nested object cannot alter commit authority. A commit resolves only the exact owner/session record, and abort, close, timeout, restart, or transfer purges every outstanding record. Terminal disposal releases retained traffic-session references, while a successful Profile-3 ownership transfer detaches the sessions without releasing them. Any injected clock is read and validated before irreversible replay commit, and no fallible caller-controlled operation follows that commit. A machine or mobility manager never exposes its private signing identity.
Runtime client/server ephemeral secrets and nonces are generated inside the private handshake owner with the OS CSPRNG; ordinary callers cannot inject or recover them. Deterministic material injection is an internal vector-test authority only. Derived traffic keys, PRK, transcript hash, and replay/counter state never appear on machine, pending-record, or session facades, and reinitializing a live session facade is rejected before owner mutation.

## 3. State and transition contract

States are `IDLE`, `COOKIE_WAIT`, `AUTH_WAIT`, `PENDING`, `ESTABLISHED`, `CLOSING`, and `RELEASED`. A server has no state for an initial `OPEN`; its first state allocation is `PENDING` after successful cookie, pin, EID, signature, and X25519 validation. Client lookup and server lookup use `(wire_version, local_role, SCID, expected_peer_EID)`. An occupied SCID with a different canonical opening transcript or binding fails `SCID_COLLISION` and never replaces state.
The complete inbound-message legality matrix is below. A `—` cell is `UNEXPECTED_MESSAGE` with no mutation, timer reset, allocation, or release; before authentication it is a silent drop. `CLOSE` is accepted only where the transition table permits an authenticated close.

| Local role/state | `OPEN` | `VERIFY_COOKIE` | `OPEN_AUTH` | `OPEN_ACK` | `SESSION_ACCEPT` | `SESSION_DATA` | `CLOSE` |
|---|---|---|---|---|---|---|---|
| client `IDLE` | — | — | — | — | — | — | — |
| client `COOKIE_WAIT` | — | accepted | — | — | — | — | — |
| client `AUTH_WAIT` | — | accepted retry | — | accepted | — | — | — |
| client `ESTABLISHED` | — | — | — | accepted retry | — | accepted | accepted |
| server no entry | accepted | — | accepted | — | — | — | — |
| server `PENDING` | — | — | accepted retry | — | accepted | — | accepted |
| server `ESTABLISHED` | — | — | accepted retry | — | accepted retry | accepted | accepted |
| either `CLOSING`/`RELEASED` | — | — | — | — | — | — | duplicate close only |

Each row specifies precondition; action; mutation; externally visible error; timer; idempotency; and release.

| Local role/state + inbound/event | Precondition | Action and mutation | Error | Timer / idempotency | Release |
|---|---|---|---|---|---|
| client `IDLE` + start | manifest pin exists; random nonzero SCID and fresh ephemeral/nonce obtained | send canonical `OPEN`; enter `COOKIE_WAIT` | local `CONFIG_ERROR`/`RNG_FAILURE` | start `P-OPEN-TOTAL-TIMEOUT`; retransmit only at `P-HANDSHAKE-RETRY-SCHEDULE`; identical `OPEN` is retry key | deadline/fatal error releases secrets and entry |
| server no entry + `OPEN` | structural validity; `P-PREVALIDATION-SOURCE-TABLE-MAX` and `P-PREVALIDATION-GLOBAL-BURST`/`P-PREVALIDATION-GLOBAL-REFILL` capacity | validate only cheap fields and source budget; emit `VERIFY_COOKIE`; allocate nothing | malformed silently drop; budget failure silently drop | response obeys `P-VERIFY-COOKIE-MAX-RESPONSE` and `P-PREVALIDATION-CUMULATIVE-RATIO`; identical request gets deterministic cookie while valid | none allocated |
| client `COOKIE_WAIT` + `VERIFY_COOKIE` | roles/service, derived EID/full key, ephemeral hash, and boot instance match sent opening and manifest | retain cookie; construct/sign `OPEN_AUTH`; enter `AUTH_WAIT` | `AUTH_FAILED` locally | retain the original `P-OPEN-TOTAL-TIMEOUT`; retransmit only at `P-HANDSHAKE-RETRY-SCHEDULE`; duplicate valid verify replaces identical cookie only | deadline/fatal error releases client entry |
| server no entry + `OPEN_AUTH` | valid cookie before signature/X25519; pin, EID, roles, service, SCID and source accounting match; `P-PENDING-SESSIONS-MAX` has capacity | verify client signature; generate server ephemeral/nonce; reject all-zero X25519; derive keys; sign/send `OPEN_ACK`; allocate `PENDING` | invalid prevalidation silently drop; postvalidation `AUTH_FAILED` where authenticated response is possible | `P-POST-COOKIE-PENDING-TIMEOUT`; identical canonical opening retransmits cached `OPEN_ACK`, no new allocation | pending timeout or fatal validation releases all keys/state |
| client `AUTH_WAIT`/`ESTABLISHED` + `OPEN_ACK` | exact pin/roles/service/SCID; server signature and EID valid; all-zero rejection passes; `P-ESTABLISHED-SESSIONS-MAX` has capacity | in `AUTH_WAIT`, derive keys, verify transcript, encrypt/send `SESSION_ACCEPT`, enter `ESTABLISHED`; in `ESTABLISHED`, resend only cached accept | `AUTH_FAILED` locally | `P-OPEN-TOTAL-TIMEOUT` remains until accept sent; duplicate ack retransmits exact cached accept | fatal/deadline/capacity failure releases entry |
| server `PENDING`/`ESTABLISHED` + `SESSION_ACCEPT` | counter valid, AEAD authentic, plaintext/hash exact; `P-ESTABLISHED-SESSIONS-MAX` has capacity when promoting | atomically replay-mark; `PENDING` enters `ESTABLISHED`; an established duplicate is dropped/no delivery | `AUTH_FAILED`/`REPLAY` drop without mutation before successful authentication | reset `P-SESSION-IDLE-TIMEOUT` only on first acceptance | timeout/close/capacity failure releases entry |
| server `PENDING`/`ESTABLISHED` + identical `OPEN_AUTH` | canonical opening matches retained transcript and binding | resend cached `OPEN_ACK`; do not allocate or replace state | `SCID_COLLISION` for any difference | pending timer unchanged; identical retry is idempotent | normal timeout/close release |
| either `ESTABLISHED` + `SESSION_DATA` | valid path, counter window and AEAD | authenticate, atomically mark replay, deliver plaintext once, reset `P-SESSION-IDLE-TIMEOUT` | `AUTH_FAILED`, `REPLAY`, `COUNTER_RANGE`, or `MTU_EXCEEDED`; no delivery | idle timeout reset only after first acceptance | timeout releases entry |
| either `ESTABLISHED`/`PENDING` + `CLOSE`, timeout, exhaustion, fatal local policy | authenticated close or local condition | authenticated close: replay-mark; move `CLOSING`, stop sends, release; local: stop sends and release | close code or structured local error | no retry after release; duplicate close is no-op | remove live references, counters, replay, candidates, paths, ephemerals |
| either any non-`RELEASED` + restart | process restart | discard every session-related object and generate fresh boot instance/cookie secret | local `RESTART_REQUIRED` | no persistence; old packets cannot revive state | immediate full release |
| any state + wrong type/state | none | no mutation | `UNEXPECTED_MESSAGE` when safely authenticated, otherwise silent drop | no timer change; duplicate has no effect | unchanged |

Replay handling uses the 4096-bit registry sliding window and the 65536-counter registry maximum forward jump. Too-old and too-far packets are rejected before state mutation; packets in range are authenticated first and only then atomically marked. Failed authentication never advances a counter/window, refreshes a timer, or changes state.

## 4. Errors and release

Internal reason tags are reported externally only as registry categories: cookie/pre-auth failure is `E-COOKIE`; capacity is `E-CAPACITY`; SCID is `E-SCID`; counter and replay failures are `E-COUNTER` and `E-REPLAY`; timeout is `E-TIMEOUT`; budget failure is `E-BUDGET`; all authenticated protocol failure closes map to `E-PATH` where applicable. Pre-auth failures are silent drops except a rate- and amplification-compliant cookie response. An authenticated peer may receive `CLOSE` only when a usable send counter/key remains; otherwise release locally. Release removes live session references and bounded auxiliary state and emits no keys, cookies, plaintext, raw pins, or identifying labels in telemetry.
