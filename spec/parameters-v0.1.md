# R8 fixed parameters v0.1

> Status: **Gate-0 frozen experimental contract.** This registry applies only to the private, isolated R8 closed lab. R8 is not an Internet standard or “IPv8”. A value may change only through a reviewed amendment made before implementation or measured trials; vectors and acceptance tests MUST assert the ID and exact value below.

## 1. Interpretation and failure behavior

A parameter identifier (`P-*`) names the sole normative value or formula. A receiver or sender that cannot satisfy an applicable limit MUST fail closed: reject the input, drop the packet, close the affected session, or refuse startup as specified. It MUST NOT fragment, evict established state, weaken authentication, persist session state, or fall back to an insecure mode.

Implementations MUST expose only the following finite, stable error categories for registry-enforced failures. Detail may be recorded locally, but it MUST map to one category and MUST NOT include secrets.

| ID | Category | Required outcome |
|---|---|---|
| `E-BUDGET` | serialized, binding, or application budget exceeded; fragmentation unavailable | reject serialization or drop; report a structured path failure for `EMSGSIZE`/budget decrease |
| `E-COOKIE` | invalid, expired, future, wrongly bound, or unavailable cookie/rate capacity | silently drop before session allocation or expensive cryptography |
| `E-CAPACITY` | fixed pending, established, candidate, path, table, or queue capacity exceeded | reject new work; queue overflow drops newest with telemetry |
| `E-TIMEOUT` | fixed handshake, pending, idle, challenge, or cache lifetime expired | expire/release the affected transient state |
| `E-SCID` | zero, collision, non-idempotent retry, or restart-invalid SCID | reject or close; never replace occupied state |
| `E-COUNTER` | reserved, exhausted, wrapped, or non-atomic counter use | close and require a fresh cookie-authenticated handshake |
| `E-REPLAY` | too old, too far, duplicate, or outside replay/dedup window | never deliver; prechecks do not mutate state |
| `E-CANDIDATE` | candidate rate, epoch, proof, binding, expiry, or slot rule violated | reject candidate/path admission; retain the last valid binding |
| `E-PATH` | path authorization, divergent duplicate, or path queue rule violated | reject admission; divergent duplicate closes the session |
| `E-FUZZ` | hostile-input CPU, RSS, allocation, or case-time bound exceeded | terminate the case/job as failed and retain a minimized regression where applicable |
| `E-RESIDUAL` | residual-memory, secret-handling, or benchmark-isolation rule violated | fail the run; do not claim wiping or isolated benchmark evidence |

## 2. Packet and binding budgets

| ID | Exact value or formula |
|---|---|
| `P-SERIALIZED-R8-MAX` | `1280 bytes` maximum serialized R8 packet |
| `P-UDP-BINDING-BUDGET` | `min(P-SERIALIZED-R8-MAX, configured_or_discovered_PMTU - IP_header - UDP_header)` |
| `P-NATIVE-BINDING-BUDGET` | `min(P-SERIALIZED-R8-MAX, Ethernet_payload_budget_after_VLAN)` |
| `P-IPV4-UDP-DEFAULT-BUDGET` | `1252 bytes` at PMTU `1280 bytes` |
| `P-IPV6-UDP-DEFAULT-BUDGET` | `1232 bytes` at PMTU `1280 bytes` |
| `P-BASE-HEADER-BYTES` | `48 bytes` |
| `P-AEAD-TAG-BYTES` | `16 bytes` |
| `P-APPLICATION-BUDGET` | `effective_binding_budget - P-BASE-HEADER-BYTES - selected_SES_or_DGRAM_framing - P-AEAD-TAG-BYTES - mobility_or_multipath_metadata` |

Serializers MUST reject packets above the applicable binding or serialized budget rather than fragmenting. IP fragmentation MUST be disabled where supported. `EMSGSIZE` or a reduced binding budget is `E-BUDGET`, never an insecure fallback. Each selected SES/DGRAM framing and mobility/multipath metadata definition MUST publish its exact constant and boundary vectors before it is used in `P-APPLICATION-BUDGET`. Primary benchmarks MUST equalize application payload bytes; a separately labeled sensitivity run MAY equalize total wire bytes.

## 3. Cookie and prevalidation limits

| ID | Exact value |
|---|---|
| `P-COOKIE-BUCKET` | `10 seconds` |
| `P-COOKIE-ACCEPTED-BUCKETS` | current bucket and immediately previous bucket only |
| `P-COOKIE-MAX-NOMINAL-AGE` | `<20 seconds` |
| `P-COOKIE-FUTURE-BUCKETS` | `0` |
| `P-COOKIE-KEY-ROTATION` | `10 minutes` |
| `P-COOKIE-PRIOR-KEY-RETENTION` | `20 seconds` only |
| `P-VERIFY-COOKIE-MAX-RESPONSE` | at most triggering request bytes and at most `256 bytes` |
| `P-PREVALIDATION-CUMULATIVE-RATIO` | cumulative emitted response bytes `<=` cumulative triggering request bytes per exact observed source binding in fixed `20-second` accounting windows |
| `P-PREVALIDATION-SOURCE-TABLE-MAX` | `4096` exact-observed-source-binding accounting entries; an entry expires `20 seconds` after its last triggering request or response, and new entries are reject-new while full |
| `P-PREVALIDATION-GLOBAL-BURST` | `2000` `VERIFY_COOKIE` response tokens; consume one token per emitted response |
| `P-PREVALIDATION-GLOBAL-REFILL` | `1000` `VERIFY_COOKIE` response tokens per elapsed second; fractional tokens do not exist |
| `P-OPEN-TOTAL-TIMEOUT` | `5 seconds` from initial `OPEN` send through `SESSION_ACCEPT` send |
| `P-POST-COOKIE-PENDING-TIMEOUT` | `5 seconds` from server `PENDING` allocation |
| `P-HANDSHAKE-RETRY-SCHEDULE` | at most `3` retransmissions with sequential waits of `0.5 seconds`, `1 second`, then `2 seconds` (cumulative elapsed offsets `0.5`, `1.5`, and `3.5 seconds` after the initial `OPEN`) |
| `P-PENDING-SESSIONS-MAX` | `256` server `PENDING` sessions; reject-new while full |
| `P-ESTABLISHED-SESSIONS-MAX` | `1024` sessions in `ESTABLISHED` or `CLOSING`; reject-new while full |
| `P-SESSION-IDLE-TIMEOUT` | `120 seconds` after the last first-accepted authenticated protected packet |

## 4. Session counter and replay limits

| ID | Exact value |
|---|---|
| `P-SESSION-COUNTER-MAX` | `u64::MAX - 1`; `u64::MAX` reserved |
| `P-REPLAY-WINDOW` | `4096` counters |
| `P-REPLAY-FORWARD-GAP-MAX` | `65,536` counters |
| `P-COUNTER-RESERVED` | exactly `u64::MAX` |
| `P-COUNTER-USABLE-RANGE` | exactly `1..u64::MAX - 1`, inclusive |
| `P-REPLAY-FORWARD-JUMP-MAX` | alias of `P-REPLAY-FORWARD-GAP-MAX`, exactly `65,536` counters |

A sender MUST atomically reserve a counter before concurrent send. Too-old and too-far checks MUST not mutate replay state; authentication MUST succeed before atomic marking. Duplicate and outside-window packets are `E-REPLAY` and are never delivered.

## 5. Candidate, mobility, and multipath limits

| ID | Exact value |
|---|---|
| `P-LIVE-CANDIDATES-MAX` | `2` per session |
| `P-CANDIDATE-PROPOSAL-SLOTS` | `2` signed-update proposal cache slots per session |
| `P-CANDIDATE-RESULT-CACHE-SLOTS` | `2` candidate-result cache slots per session |
| `P-CANDIDATE-RESULT-CACHE-EXPIRY` | `10 seconds` |
| `P-CANDIDATE-PROPOSAL-BUCKET-INITIAL` | `2` integer tokens |
| `P-CANDIDATE-PROPOSAL-BUCKET-REFILL` | `1` integer token per elapsed `1000 ms`; fractional tokens do not exist |
| `P-CANDIDATE-PROPOSAL-DUPLICATE-CONSUME` | `0` tokens for a byte-identical cached `LOC_UPDATE` |
| `P-CANDIDATE-UPDATE-NOT-BEFORE` | `0 ms` |
| `P-CANDIDATE-UPDATE-VALID-FOR` | `5000 ms` |
| `P-CANDIDATE-SECRET-BYTES` | `32 bytes` |
| `P-CANDIDATE-CHALLENGE-EXPIRY` | `3 seconds` |
| `P-CANDIDATE-COHORT-ARBITRATION` | greatest proposed epoch, then lexicographically smallest 16-byte candidate ID; at most one promotion |
| `P-OLD-BINDING-GRACE` | `10 seconds`, inbound-only |
| `P-CANDIDATE-EPOCH` | strictly increasing `u64`; no wrap |
| `P-PATH-SLOTS` | `0` and `1` only |
| `P-PATH-SLOT-REUSE` | prohibited in-session after removal |
| `P-VALIDATED-BINDINGS-MAX` | `2` |
| `P-PROFILE3-ADMISSION-OWNER` | exactly one opaque, non-cloneable owner capability issued per Profile-3 session for one SCID and policy; only a committed mobility result may move it into a one-shot slot-one admission |
| `P-REDUNDANT-RECEIVE-PREVIEWS-MAX` | exactly `1` outstanding transactional authenticated receive preview per Profile-3 redundant session; reject-new while occupied |
| `P-DELIVERY-ID` | atomically increasing `u64` in exactly `1..u64::MAX - 1`, inclusive; zero invalid, `u64::MAX` reserved, no wrap |
| `P-DELIVERY-FORWARD-GAP-MAX` | `65,536` |
| `P-DELIVERY-IDENTITY-WINDOW` | sliding numeric window containing at most the latest `4096` delivery IDs relative to the delivery high-water mark; each present ID retains a full SHA-256 digest and byte length |
| `P-DEDUP-CACHE-IDS` | at most `4096` full-plaintext entries for IDs still in `P-DELIVERY-IDENTITY-WINDOW` |
| `P-DEDUP-CACHE-EXPIRY` | `30 seconds` full-plaintext cache lifetime only; expiry never removes an identity still inside `P-DELIVERY-IDENTITY-WINDOW` |
| `P-PER-PATH-QUEUE-PACKETS-MAX` | `256 packets` |
| `P-PER-PATH-QUEUE-BYTES-MAX` | `256 KiB` |
| `P-PER-PATH-QUEUE-OVERFLOW` | drop newest with telemetry |

A candidate record exists only after a valid AEAD `BIND_PROBE`; challenge/response MUST arrive on the exact typed observed binding before application use or promotion. Candidate capacity is reject-new. Configuration or passive receipt does not authorize a path. A same delivery ID with different authenticated application bytes is `E-PATH` and closes the session.

## 6. Hostile-input and residual-memory limits

| ID | Exact value |
|---|---|
| `P-FUZZ-INPUT-MAX` | `1281 bytes` |
| `P-FUZZ-CPU-PER-TARGET` | `60 seconds` |
| `P-FUZZ-RSS-PER-JOB` | `512 MiB` |
| `P-FUZZ-CASE-TIMEOUT` | `5 seconds` |
| `P-PARSE-ALLOCATION-MAX` | `64 KiB` per single parse allocation |
| `P-CPYTHON-SECRET-WIPE-CLAIM` | prohibited |
| `P-CPYTHON-LIVE-REFERENCE-BOUND` | remove live session references at close or timeout |
| `P-CPYTHON-SECRET-LOGS` | prohibited |
| `P-CPYTHON-SECRET-CORE-ARTIFACTS` | prohibited |
| `P-BENCHMARK-PROCESS-ISOLATION` | process teardown required |
| `P-RUST-OWNED-SECRET-BUFFERS` | library-supported zeroization required |

Longer nightly/manual fuzz campaigns MUST be labeled as such and retain minimized regressions. CPython cannot guarantee memory wiping: `P-CPYTHON-LIVE-REFERENCE-BOUND`, bounded lifetimes, no secret logs/core artifacts, and `P-BENCHMARK-PROCESS-ISOLATION` are the observable residual controls. No bespoke Python wiping claim or code is permitted.

## 7. Frozen benchmark protocol limits

| ID | Exact value |
|---|---|
| `P-Q1-WARMUPS` | `20` per mechanism/arm |
| `P-Q1-MEASURED-TRIALS` | `200` per mechanism/arm |
| `P-Q1-BLOCK-SIZE` | `20 trials` per balanced randomized host-epoch block |
| `P-Q1-MAKE-BEFORE-BREAK-NOTICE` | activation at `T−2 seconds`; cutover at `T` |
| `P-Q1-READINESS-DELIVERIES` | first `10` consecutive on-schedule post-T deliveries |
| `P-Q1-SUPPORTED-QUANTILES` | p50 and p95 only |
| `P-Q1-BOUNDARY-SKEW-NS` | `100000000 nanoseconds` |
| `P-Q1-BLOCK-BOOTSTRAP-RESAMPLES` | `10,000` |
| `P-Q2-SEED-IDS` | exact integers `0..219`, inclusive |
| `P-Q2-WARMUP-SEEDS` | seeds `0..19` (block `0`); excluded from analysis |
| `P-Q2-MEASURED-SEEDS` | seeds `20..219` (blocks `1..10`); included in analysis |
| `P-Q2-CONDITIONS` | `no-flap` (`0`), `flap-A` (`1`), and `flap-B` (`2`) |
| `P-Q2-MECHANISMS` | `REDUNDANT`, `single-A`, and `single-B` |
| `P-Q2-MECHANISM-ORDER` | SHA-256 of ASCII domain `r8-q2-v3-mechanism-order` + seed `u32be` + condition `u8` + exact mechanism UTF-8; ascending digest then UTF-8 lexical mechanism order |
| `P-Q2-BLOCKS` | `seed // 20`; block `0` warmup, blocks `1..10` measured |
| `P-Q2-CANONICAL-PLAN` | exactly `1,980` rows in seed ascending, condition code ascending, execution-rank ascending order; each row includes `condition_code`, SHA-256 `mechanism_digest`, and `execution_ordinal = seed × 9 + condition_code × 3 + execution_rank`; canonical JSON SHA-256 is `477db21557cd9ff0349c8e9630261d35ea6dda42a53f1fcf50c7936ba7a70f75` |
| `P-Q2-TRIAL-TABLE` | exactly `1,980` strict rows conforming to `bench/protocols/q2-trial-v5.schema.json`; schema SHA-256 is `02f4a204840f216e6b453103696f0ea8bfc0bc6272b92b87e5fdddea93bbe30c` |
| `P-Q2-LOGICAL-PACKET-TABLE` | exactly `792,000` strict rows (`1,980 × 400`; `72,000` warmup; `720,000` measured) conforming to `bench/protocols/q2-packet-v5.schema.json`; schema SHA-256 is `6db0bf37dead1602d6ff67d0278e484356cf1a68dd89c9c4e65e1ab9038a6594` |
| `P-Q2-EVIDENCE` | exactly one strict evidence row per trial conforming to `bench/protocols/q2-evidence-v5.schema.json`; schema SHA-256 is `649d4368dcab8305f9db7479537d4e2c896e50b94cf7fad0737379306f696771`; evidence uses only closed ordinal/digest records and closed role/path objects, never free maps, raw MAC/LOC/interface/namespace/PID/argv/host epoch values |
| `P-Q2-IDENTITY-TOKENS` | locator tokens exactly `source-slot-0`, `destination-slot-0`, `source-slot-1`, `destination-slot-1`; MAC tokens exactly `source-A-egress`, `hop-A-ingress`, `hop-A-egress`, `destination-A-ingress`, `source-B-egress`, `hop-B-ingress`, `hop-B-egress`, `destination-B-ingress` |
| `P-Q2-LOCATOR-MAC` | locator SHA-256 domain `r8-q2-v4-locator-id` + seed `u32be` + exact locator UTF-8 token, first `16` bytes as `32` lowercase hex; MAC SHA-256 domain `r8-q2-v4-mac` + seed `u32be` + exact interface UTF-8 token, first six bytes with byte 0 `(byte0 OR 0x02) AND 0xfe` (locally administered unicast); actual values never stored |
| `P-Q2-TOPOLOGY` | exactly four namespace roles and four veth pairs forming disjoint IP-free two-hop paths A and B; evidence uses closed interface/path/role ordinal-digest record arrays only |
| `P-Q2-PROFILE3-SLOTS` | REDUNDANT proves A in slot `0` and B in slot `1`; single-A and single-B use their selected path in slot `0` only; synthetic pins required |
| `P-Q2-LINK-MTU` | `1500 bytes`; native budget `1280 bytes` |
| `P-Q2-PAYLOAD` | `64 bytes` application payload |
| `P-Q2-SCHEDULE` | CLOCK_MONOTONIC_RAW; stored ns relative to T; packet `i=0..399` at `T−1 s + i×10 ms`, interval `[T−1 s,T+3 s)`, never early; on-schedule `[scheduled,scheduled+20 ms]` |
| `P-Q2-READINESS` | exactly ten consecutive pre-T on-schedule authenticated deliveries |
| `P-Q2-FLAP` | flap-A/B requests 100% bidirectional egress-qdisc loss from `T` to `T+1 s`; actual start/end is first successful post-command state read; each absolute start/end deviation is `<=100 ms` and inter-end skew `<=100 ms`, else retain finite `flap-timing` failure; no-flap has no mutation and null flap/recovery fields |
| `P-Q2-RECOVERY` | flap conditions only: valid later end origin enters at `0`; tenth consecutive on-schedule authenticated delivery is event; otherwise censor at `min(2 s, observed follow-up)`; missing/invalid origin enters and censors at `0`, nonestimable for RMST; report eligibility |
| `P-Q2-FAILURE-LOSS` | failure numerator is `status != completed`, denominator `200` per mechanism/condition; loss numerator is all `400` logical schedules per trial without authenticated delivery by `T+3 s`, including `not_sent`/failed/timeout, denominator `80,000` per mechanism/condition; contrasts are paired per-seed REDUNDANT minus each single control |
| `P-Q2-TRIAL-TIMEOUT` | `10 seconds` |
| `P-Q2-SUPERVISOR-TIMEOUT` | `20 seconds` |
| `P-Q2-RMST` | recovery RMST restricted to `2 seconds`, Kaplan–Meier only for eligible flap trials; no success-only substitution |
| `P-Q2-BOOTSTRAP` | for `r=0..9999`, `pos=0..9`, SHA-256 ASCII `r8-q2-v4-block-draw` + `r u32be` + `pos u8`; block `1 + (first 8 digest bytes as u64be mod 10)`; no PRNG; percentile index/nonestimable rule in Q2 v5 |
| `P-Q2-SUPPORTED-QUANTILES` | type-7 p50 and p95 only; p99 unsupported |
| `P-Q3-WARMUPS` | `50` per mechanism |
| `P-Q3-MEASURED-HANDSHAKES` | `1000` full handshakes per mechanism |
| `P-Q3-BLOCK-SIZE` | `20 trials` per randomized host-epoch block |
| `P-Q3-TIMEOUT` | `5 seconds` |
| `P-Q3-BOOTSTRAP-RESAMPLES` | `10,000` with fixed preregistered seed |
| `P-Q3-SUPPORTED-QUANTILES` | p50, p90, and p99 only; p99 is unsupported when its CI spans timeout or effective successes are insufficient |

Q1, Q2, and Q3 preregistrations MUST also fix hypotheses, randomization seed, readiness/outage trigger, payload/load, censoring, estimators/CI, trust, clocks, environment, and exclusion policy before measured data. They retain every timeout and failure row.
