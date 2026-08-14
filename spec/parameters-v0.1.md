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

## 4. Session counter and replay limits

| ID | Exact value |
|---|---|
| `P-SESSION-COUNTER-MAX` | `u64::MAX - 1`; `u64::MAX` reserved |
| `P-REPLAY-WINDOW` | `4096` counters |
| `P-REPLAY-FORWARD-GAP-MAX` | `65,536` counters |

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
| `P-DELIVERY-ID` | nonzero atomically increasing `u64`; no wrap |
| `P-DELIVERY-FORWARD-GAP-MAX` | `65,536` |
| `P-DEDUP-CACHE-IDS` | `4096` |
| `P-DEDUP-CACHE-EXPIRY` | `30 seconds` |
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
| `P-Q1-BLOCK-BOOTSTRAP-RESAMPLES` | `10,000` |
| `P-Q2-WARMUPS` | `20` |
| `P-Q2-MEASURED-TRIALS` | `200` paired trials per flap target |
| `P-Q2-FLAP-DURATION` | `1 second` after steady state |
| `P-Q2-SUPPORTED-QUANTILES` | p50 and p95 only |
| `P-Q3-WARMUPS` | `50` per mechanism |
| `P-Q3-MEASURED-HANDSHAKES` | `1000` full handshakes per mechanism |
| `P-Q3-BLOCK-SIZE` | `20 trials` per randomized host-epoch block |
| `P-Q3-TIMEOUT` | `5 seconds` |
| `P-Q3-BOOTSTRAP-RESAMPLES` | `10,000` with fixed preregistered seed |
| `P-Q3-SUPPORTED-QUANTILES` | p50, p90, and p99 only; p99 is unsupported when its CI spans timeout or effective successes are insufficient |

Q1, Q2, and Q3 preregistrations MUST also fix hypotheses, randomization seed, readiness/outage trigger, payload/load, censoring, estimators/CI, trust, clocks, environment, and exclusion policy before measured data. They retain every timeout and failure row.
