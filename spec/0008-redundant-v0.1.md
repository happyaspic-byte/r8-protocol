# R8 REDUNDANT Profile 3 v0.1

> Status: normative Gate-0 contract for private, experimental, closed-lab R8 only.

## 1. Profile and admission

Profile 3 is authenticated two-path endpoint delivery. It does not establish physical separation and makes no inference about topology beyond recorded experiment evidence. A Profile-3 session starts with one validated path in slot zero using `0005-session-security-v0.1.md` and the outer packet rules in `0004-wire-format-v0.2.md`. Slot one is unavailable until it completes the exact candidate procedure in `0006-mobility-v0.1.md`.

The sole slot-one admission sequence is: protected signed `LOC_UPDATE` proposal sent on validated slot zero; candidate-originated protected `BIND_PROBE`; receiver-observed typed `UdpBinding` or `NativeBinding`; challenge token bound to identity, SCID, Profile 3 policy, candidate ID, LOC, epoch, direction, and slot one; exact-binding protected response before challenge expiry; then promotion. Configuration and passive receipt are not admission evidence. A candidate failure cannot remove slot zero or change either replay state.

There are exactly two path slots, `0` and `1`. A removed slot is permanently unavailable until a fresh session; it is never reused. Each validated slot has a distinct HKDF key derived using Profile 3 and its path slot as specified in `0005-session-security-v0.1.md`, a distinct send counter, and a distinct receive replay window. All counter, nonce, AEAD, atomic reservation, exhaustion, restart, and replay requirements in that document apply independently to each slot. There is no key reuse between slots.

## 2. Canonical Profile-3 data encoding

A Profile-3 `SESSION_DATA` payload uses the common four-byte SES prefix and then exactly:

```
counter:u64 || delivery_id:u64 || ciphertext_and_tag:variable
```

The plaintext is the application bytes. The `delivery_id` is nonzero `u64`, is generated once per logical outbound delivery, and is outside ciphertext but authenticated. AEAD associated data is the exact 48-byte R8 header, the SES four-byte prefix, `counter:u64`, and `delivery_id:u64`, in that order. The nonce remains `0x00000000 || counter_u64_be` under the key for that slot. A packet is valid only when header Profile is exactly 3, header Path Slot equals the key/replay slot used, and body layout is exact.

A logical delivery is serialized once per active slot with the same `delivery_id` and identical application bytes, but with its own slot key/counter/nonce and outer header binding. A sender must not use an identical delivery ID with different application bytes. Binding budget computation uses the registry formula and subtracts base header, SES prefix, two `u64` fields, tag, and any selected carrier metadata. Oversize application data fails before any slot counter reservation and is never fragmented.

Delivery IDs atomically increase with no wrap and use the registry maximum forward gap, dedup capacity, and expiry. Allocation starts at a random nonzero value after handshake. Before delivery-ID exhaustion, the sender closes and releases the session; it does not reset the sequence or create a replacement key.

## 3. Path and delivery state contract

Path states are `ABSENT`, `CANDIDATE`, `VALIDATED`, `ACTIVE`, `DEGRADED`, `REMOVED`, and `RELEASED`. Session delivery state contains a bounded dedup map from delivery ID to `(authenticated application bytes, expiry)` and one bounded queue per active path. Limits, expiry, and overflow policy are exactly `spec/parameters-v0.1.md`: dedup has the registry ID count and lifetime; each queue is limited to the registry packet and byte bounds; overflow drops the newest packet with telemetry.

| State + event | Precondition | Action and mutation | Error | Timer / idempotency | Release |
|---|---|---|---|---|---|
| slot 0 `VALIDATED` + Profile-3 enable | existing authenticated session and slot-zero binding | derive slot-zero Profile-3 key; enter slot 0 `ACTIVE`; slot 1 `ABSENT` | `PROFILE_INVALID` | one-time, exact repeat is no-op | session close releases all Profile-3 state |
| slot 1 `ABSENT` + protected proposal | valid `LOC_UPDATE` from slot zero with slot one; registry rate/capacity allow | create `CANDIDATE`; execute common probe/challenge flow | `AUTH_FAILED`, `EPOCH`, `CAPACITY`, `BIND_MISMATCH` | common candidate expiry; exact duplicate is no-op/cached challenge | failure releases candidate only, leaves slot zero active |
| slot 1 `CANDIDATE` + exact-binding proof | common candidate is `PROVEN`; Profile=3/slot=1 challenge binding validates | derive distinct slot-one key and initialize independent counters/replay; enter `VALIDATED`, then `ACTIVE`; emit recovered event | `CHALLENGE_INVALID` | promotion is idempotent for same candidate only | failed/expired candidate releases without slot mutation |
| any `ACTIVE` slot + outbound delivery | nonzero next delivery ID; queue and budget permit | atomically allocate one delivery ID; independently reserve each active-slot counter; enqueue/send identical plaintext on each active slot | `MTU_EXCEEDED`, `QUEUE_OVERFLOW`, `COUNTER_EXHAUSTED` | retransmit only exact cached per-slot wire packet; no new ID/counter | counter exhaustion closes session; overflow drops newest only |
| any `ACTIVE` slot + authenticated inbound packet | exact Profile-3 layout, matching slot, valid counter/window and AEAD | authenticate then atomically mark slot replay; evaluate dedup map | `AUTH_FAILED`/`REPLAY`/`COUNTER_RANGE` | failed auth does not mutate; replay duplicate is no-op | unchanged |
| dedup miss + authenticated inbound | delivery ID valid and within allowed forward gap; capacity available | insert `(ID, bytes, expiry)`; deliver exactly once | `DELIVERY_GAP`/`DEDUP_CAPACITY` | registry expiry; same queued duplicate later is no-op | expiry removes only that map entry |
| dedup hit + same authenticated bytes | same delivery ID and byte-equal plaintext | suppress delivery | none | no expiry extension; idempotent | unchanged |
| dedup hit + different authenticated bytes | same delivery ID, byte-different plaintext | protocol-close whole session; emit divergence event | `DIVERGENT_DELIVERY` | no retry | release both slots, queues, dedup, keys, counters |
| active slot + authenticated path failure/expired binding | other slot remains active | stop using failed slot; flush only its queue; enter failed slot `DEGRADED` then `REMOVED`; emit degraded event | `PATH_FAILURE` | repeated failure is no-op; removed slot cannot be reused | release failed slot key/replay/binding/queue |
| last active slot + path failure | no remaining active slot | close whole session | `PATH_FAILURE` | no fallback | release all session resources |
| any + session close/restart | session release condition | stop sends and erase paths, queues, dedup and key material | `RESTART_REQUIRED` locally on restart | no persistence/retry | enter `RELEASED` |

A receiver checks delivery forward-gap eligibility before insertion but after successful AEAD; an obviously invalid ID does not mutate dedup state. The dedup entry stores application bytes or a collision-safe full digest plus byte length sufficient to distinguish every accepted payload; it must never treat unequal bytes as equal. Divergence is detected only after each candidate packet has separately passed the corresponding path's AEAD and replay checks.

## 4. Degradation and errors

With both slots active, each logical delivery is sent over both. With exactly one active slot, the session remains protected but is `DEGRADED`; it emits one bounded degraded event on transition and one recovered event only when a newly admitted slot becomes active. Degraded intervals must be labeled as single-path in measurement output. No silent switch to an unprotected carrier or unauthenticated path is permitted.

Internal reason tags are externally reported only as registry categories: candidate/admission failure is `E-CANDIDATE`; queue/dedup/divergence/path authorization failure is `E-PATH`; capacity is `E-CAPACITY`; replay is `E-REPLAY`; counter exhaustion is `E-COUNTER`; and budget failure is `E-BUDGET`. Telemetry is bounded by these categories plus queue/window high-water marks, dedup suppression, divergence, and degradation/recovery transitions. It contains no application bytes, keys, cookies, tokens, raw pins, EIDs, SCIDs, LOCs, IPs, or MACs.
