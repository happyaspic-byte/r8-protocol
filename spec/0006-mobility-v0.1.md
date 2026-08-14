# R8 Mobility and Candidate Binding v0.1

> Status: normative Gate-0 contract for private, experimental, closed-lab R8 only.

## 1. Common candidate model

This document defines the only candidate-binding mechanism. It is used unchanged by Profile 0/1/2 mobility and Profile 3 second-path admission in `0008-redundant-v0.1.md`. Configuration and passive packet receipt never authorize an application path.

A binding is a typed, immutable observed value:

| Binding type | Canonical encoding |
|---|---|
| `UdpBinding` (`1`) | `type:u8=1, address_family:u8` (`4` or `6`), `remote_ip:4-or-16, remote_port:u16, local_selector_kind:u8` (`1=interface-id`, `2=local-address`), `local_selector:16` |
| `NativeBinding` (`2`) | `type:u8=2, ingress_descriptor_id:u32, next_hop_mac:6` |

An IPv4 address is four bytes; IPv6 is sixteen bytes; `local_selector` is a fixed 16-byte manifest ID or address with unused bytes zero. No text representation, inferred local interface, or alternate encoding is accepted. A receiver constructs a binding only from its socket/descriptor metadata and the packet source.

A proposal cache entry contains canonical signed `LOC_UPDATE` bytes and its authenticated-receipt expiry. It is not a binding or candidate. A candidate record is `(candidate_id:16, proposed_loc:16, epoch:u64, path_slot:u8, binding, expiry, state)`. `candidate_id` is nonzero random 128-bit data. At session establishment, each candidate manager generates one fresh local 32-byte OS-CSPRNG `candidate_secret`; it is reused only for that issuer's candidate tokens, is never transmitted, and is erased only on session release. Candidate release erases its token material but not the session candidate secret. States are `CHALLENGED`, `PROVEN`, `PROMOTED`, `FAILED`, and `RELEASED`. The limits and values are `P-LIVE-CANDIDATES-MAX`, `P-CANDIDATE-PROPOSAL-SLOTS`, `P-CANDIDATE-RESULT-CACHE-SLOTS`, `P-CANDIDATE-RESULT-CACHE-EXPIRY`, `P-CANDIDATE-CHALLENGE-EXPIRY`, `P-CANDIDATE-UPDATE-NOT-BEFORE`, `P-CANDIDATE-UPDATE-VALID-FOR`, `P-CANDIDATE-SECRET-BYTES`, and `P-OLD-BINDING-GRACE` in `spec/parameters-v0.1.md`.

## 2. Protected control encoding

Mobility controls are `SESSION_DATA` plaintext protected by the session AEAD in `0005-session-security-v0.1.md`, with outer packet conformance to `0004-wire-format-v0.2.md`. The exact plaintext is `ASCII("R8M1") || type:u8 || version:u8=1 || flags:u16=0 || body`; all integers are unsigned big-endian. Any other magic, version, flags, body size, or encoding is `E-CANDIDATE`.

| Type | Name | Exact body | Total plaintext length |
|---:|---|---|---:|
| 1 | `LOC_UPDATE` | `candidate_id:16, old_loc:16, new_loc:16, epoch:u64, not_before_ms:u64=0, valid_for_ms:u64=5000, path_slot:u8, signature:64` | 145 |
| 2 | `BIND_PROBE` | `candidate_id:16, loc:16, epoch:u64, path_slot:u8, probe_nonce:16` | 65 |
| 3 | `BIND_CHALLENGE` | `candidate_id:16, loc:16, epoch:u64, path_slot:u8, expiry_ms:u64, token:32` | 89 |
| 4 | `BIND_RESPONSE` | `candidate_id:16, loc:16, epoch:u64, path_slot:u8, expiry_ms:u64, token:32` | 89 |
| 5 | `CANDIDATE_RESULT` | `candidate_id:16, epoch:u64, path_slot:u8, result:u8` (`1=promoted,2=rejected,3=expired`) | 34 |

`LOC_UPDATE` is signed with the sender's configured full Ed25519 key over `ASCII("R8 LOC_UPDATE v1") || session_version || header Profile || SCID || sender_eid || receiver_eid || old_loc || new_loc || epoch || not_before_ms || valid_for_ms || candidate_id || path_slot`. After AEAD authentication and configured pin/role/service authorization, the receiver requires `not_before_ms=0` and `valid_for_ms=5000`; it sets expiry to authenticated local monotonic receipt time plus `valid_for_ms`. No sender and receiver clocks are compared. An incorrect old LOC, non-increasing epoch, unknown slot, invalid signature, or non-exact fixed field is `E-CANDIDATE` without mutation.

A challenge token is `HMAC-SHA256(candidate_secret, ASCII("R8 bind v1") || session_version || header Profile || SCID || sender_eid || receiver_eid || candidate_id || loc || canonical_binding || direction || epoch || path_slot || policy_id || expiry_ms)`. `direction` is exactly `1` when the probe sender has role 1 and its peer has role 2, and exactly `2` when the probe sender has role 2 and its peer has role 1; every other role pairing is `E-CANDIDATE`. `policy_id` is the immutable experiment-manifest `u32`. `expiry_ms` is the challenge issuer's monotonic-clock deadline; a response copies it byte-for-byte and does not interpret it in its own clock domain. The issuer alone tests expiry. A response is valid only when every token input recomputes exactly and it arrives on the exact observed typed binding.

## 3. Receive, transition, and arbitration contract

Protected control receive is transactional: (1) perform AEAD authentication and replay precheck without replay marking; (2) parse and validate the exact candidate control and all state/binding conditions; (3) atomically commit replay marking and idle refresh only when step 2 succeeds, then apply the stated mutation. A malformed or failed candidate control, including a valid-AEAD candidate failure, MUST not mutate replay state, idle state, bindings, proposals, candidates, caches, or timers. Application traffic, `BIND_PROBE`, `BIND_CHALLENGE`, `BIND_RESPONSE`, and `CANDIDATE_RESULT` require their exact allowed state and binding. An authenticated `LOC_UPDATE` may arrive from an unrecognized observed binding, but creates neither a binding nor authorization.

The proposal bucket starts with exactly two integer tokens. On each accepted non-duplicate update, add one token for each full elapsed 1000 ms since its last refill, cap at two, then consume one token; no fractional token exists. A byte-identical cached `LOC_UPDATE` consumes zero tokens and is a no-op. Distinct updates without a token are `E-CANDIDATE`. Proposal-cache capacity is reject-new, never eviction.
A result-cache entry is `(candidate_id, epoch, path_slot, result, canonical result bytes, expiry)` and expires exactly `P-CANDIDATE-RESULT-CACHE-EXPIRY` after insertion; capacity is reject-new. A duplicate control returns only its matching cached challenge or result, never extends a timer. `CANDIDATE_RESULT` is accepted only for its matching live or cached candidate state and exact binding, and otherwise is `E-CANDIDATE`. Candidate release erases its token material. On session close, fatal session error, or restart, stop all candidate timers, erase every proposal, result-cache entry, candidate record, and the session candidate secret; restart accepts no old control and requires a fresh handshake.

Outer-LOC staging is fixed: before promotion, outbound application traffic uses only the current binding and the proposed `new_loc` is control data only; the `BIND_PROBE` outer carrier is the probe sender's candidate carrier and its receiver-observed source creates the candidate binding. After promotion, outbound application traffic uses only the promoted binding; the former binding is inbound-only during grace. No received outer source, including the source of an authenticated `LOC_UPDATE`, stages, creates, authorizes, or selects an outbound binding.

| Event | Required precondition and atomic outcome | Failure/idempotency |
|---|---|---|
| `LOC_UPDATE` | exact signed update; authorization; strictly greater than committed epoch; capacity; rate token. Cache its canonical bytes and receipt-anchored expiry only. | `E-CANDIDATE`; byte-identical cached update is no-op. |
| `BIND_PROBE` | exact cached proposal fields; permitted profile/slot; candidate capacity. Construct receiver-observed binding, use the existing session candidate secret, create `CHALLENGED`, issue challenge with issuer monotonic expiry. | `E-CANDIDATE` or `E-CAPACITY`; duplicate probe returns the cached challenge without a second record. |
| `BIND_RESPONSE` | `CHALLENGED`; issuer has not reached its expiry; exact fields, token, and binding. Mark `PROVEN`, cache result. | `E-CANDIDATE`; duplicate valid response returns cached result without mutation. |
| candidate expiry or authenticated rejection | mark candidate `FAILED`; retain the last valid binding; erase candidate token material on release. | `E-TIMEOUT` or `E-CANDIDATE`; repeated event is no-op. |
| session close or restart | stop challenges, erase proposal/candidate/result-cache state and the session candidate secret. | restart requires a fresh handshake; no retry. |

When the first candidate for the greatest proposed epoch becomes `PROVEN`, form its cohort from every valid proposal already cached for that epoch and freeze membership. A cohort member is terminal when `PROVEN`, `FAILED`, or its proposal/candidate expires; all members become terminal no later than the existing `P-CANDIDATE-CHALLENGE-EXPIRY` of three seconds after its candidate was created. Do not arbitrate before every frozen member is terminal. Then select the greatest epoch and, within it, the lexicographically smallest 16-byte candidate ID among `PROVEN` members. Promote exactly that one candidate at most once; mark all other cohort candidates rejected and cache their result. Later updates with equal or lower epoch are `E-CANDIDATE`. A cohort with no `PROVEN` member performs no promotion.

Promotion installs the selected binding and LOC. The replaced binding is inbound-only for exactly `P-OLD-BINDING-GRACE` and is never selected for outbound traffic. There are at most two validated bindings; a third binding is `E-CAPACITY` until capacity is freed. No failure can remove the last valid binding, reset replay state, or roll back a committed epoch.

## 4. Mobility use and Profile-3 composition

For mobility, `LOC_UPDATE` proposes replacement on path slot zero. The protected probe and exact-binding response prove reachability before new-binding application traffic. For Profile 3, the same `LOC_UPDATE`, proposal cache, receiver-observed probe, candidate secret, token, expiry, cohort arbitration, and promotion mechanism apply to `path_slot=1`; only the existing Profile-3 admission transition derives the slot-one key and permits slot-one application traffic. There is no second candidate mechanism.

Only finite registry categories are externally reported: structural/authentication/candidate failure is `E-CANDIDATE`, capacity is `E-CAPACITY`, expiry is `E-TIMEOUT`, and replay is `E-REPLAY`. Telemetry is bounded and never includes raw LOC, IP, MAC, tokens, keys, cookies, EIDs, or SCIDs.
