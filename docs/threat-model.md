# R8 closed-lab threat model

> Status: Gate-0 frozen experimental contract. R8 is a private, isolated research protocol, not an Internet standard and not “IPv8”. This document makes no production-security claim and does not authorize R8 native traffic on public, third-party, or non-isolated networks.

## Scope, assets, and boundaries

The protected assets are configured peer authorization, session confidentiality and integrity, fresh packet delivery, candidate/path authority, bounded endpoint resources, native-interface confinement, experiment topology, and trustworthy minimized evidence. The wire is hostile: UDP and native frames, source addresses, LOCs, SCIDs, timing, loss, reordering, duplication, and path availability are attacker controlled until the relevant checks authenticate them.

Trust boundaries are: (1) an experiment manifest containing expected role/service, EID128, and complete Ed25519 public-key pins; (2) the cookie boundary before state allocation or expensive cryptography; (3) the authenticated-session boundary; (4) the candidate-originated exact-binding proof boundary; (5) the native launcher/manifest/descriptor boundary; and (6) the benchmark controller, raw data, and publication boundary. Crossing a boundary grants no authority without its required proof.

## Attacker model and exclusions

An attacker may send arbitrary malformed or correctly structured packets, spoof underlay sources, replay, delay, reorder, duplicate, corrupt, reflect, flood, race concurrent sends, propose LOCs/candidates, passively receive frames, cause a path flap, and present a valid but unauthorized key. An attacker may attempt resource exhaustion, amplification, counter/nonce misuse, replay-window mutation, SCID collision, candidate/path hijack, divergent redundant copies, telemetry correlation, or misleading benchmark conditions.

R8 does not claim protection against endpoint compromise, compromised configured pins or experiment manifests, cryptographic primitive failure, physical access to hosts, hostile kernel/firmware/NIC, a malicious lab operator, physical/VLAN topology compromise, traffic analysis/linkability, global routing, NAT traversal, dynamic neighbor discovery, congestion control, reliable streams, fragmentation, post-quantum security, or in-session rekey. Physical and VLAN isolation cannot be proven by software; native runs need recorded operator attestation naming the switch/VLAN/interfaces and confirming no public or third-party attachment.

## Identity, pins, and possession

EID128 is `first128(SHA-256("R8 EID v1" || Ed25519 public_key))` in network order. It proves a key binding, not authorization. A valid signature, EID, or proof of key possession is insufficient alone. The expected full public key, expected EID, role, and service context from the manifest MUST all match before `ESTABLISHED` or delivery. Unknown, unpinned, wrong-role, wrong-service, EID/key mismatch, role swap, unknown-key-share, and key substitution fail closed.

Stable EIDs, full public keys, base LOC metadata, and raw labels are linkable. Fresh per-experiment identities are required unless continuity is explicitly needed. TOFU, PKI, and automatic insecure fallback are out of scope.

## Amplification and state exhaustion

Before a valid cookie, the responder has no session allocation and performs no signature verification or X25519. Cookie binding and all prevalidation limits are normative in `spec/parameters-v0.1.md`: `P-COOKIE-BUCKET` through `P-PREVALIDATION-GLOBAL-BURST`. In particular, `VERIFY_COOKIE` is bounded by `P-VERIFY-COOKIE-MAX-RESPONSE`; the fixed table, rolling cumulative `P-PREVALIDATION-CUMULATIVE-RATIO`, deterministic replacement, and global token bucket prevent amplification. Missing capacity silently drops as `E-COOKIE`.

Post-cookie work remains bounded by `P-POST-COOKIE-PENDING-MAX`, `P-ESTABLISHED-MAX`, and their exact timeouts. Reject-new behavior is deterministic and never evicts established state. The source table, session table, candidate records, path state, replay/dedup caches, and queues have no attacker-controlled unbounded growth; their limits and `E-CAPACITY` behavior are registry-defined.

## Transcript, nonce, counter, and replay

The canonical session transcript includes both EIDs and full keys, roles, intended responder/service context, SCID, versions/profile, ephemerals, and nonces. Session keys are separated by `P-HKDF-KEY-SEPARATION`; a nonce is exactly `P-NONCE`. Counter zero is forbidden, concurrent sends atomically reserve a counter, and exhaustion follows `P-COUNTER-EXHAUSTION`. Restart discards sessions, replay/candidate/path state, counters, and ephemeral keys under `P-SESSION-PERSISTENCE` and creates a fresh `P-BOOT-INSTANCE`; it never resumes an old key domain.

Replay limits are `P-REPLAY-WINDOW` and `P-REPLAY-FORWARD-JUMP-MAX`. Too-old/too-far prechecks do not mutate state; authentication precedes atomic replay marking. Duplicate/outside packets never reach delivery. Transcript, tag, associated-data, all-zero X25519, counter, and replay failures fail closed with the applicable finite `E-*` category.

## Candidate and path authorization

Candidate configuration, a claimed LOC, and passive receipt are not path authorization. A valid AEAD `BIND_PROBE` first creates a typed observed `UdpBinding` or `NativeBinding`; the challenge binds session, peer identity, candidate ID, LOC, typed binding, direction, epoch/path slot, policy, and expiry. The response must arrive on that exact binding before promotion or application use. The candidate limits are `P-LIVE-CANDIDATES-MAX` through `P-CANDIDATE-EPOCH`; failures are `E-CANDIDATE` and cannot remove the last valid binding or reset replay state.

Only path slots in `P-PATH-SLOTS` exist. Path two uses the same candidate proof, not configuration or passive traffic. A removed slot is never reused; distinct keys/counters/replay state apply per path slot. Redundant delivery enforces `P-DELIVERY-ID`, gap, dedup, cache, and queue bounds. Same-ID/different-authenticated-bytes is `E-PATH` and closes the session. R8 does not infer physical path disjointness; topology evidence limits any redundancy claim.

## Native privilege and topology

Native forwarding uses an immutable static manifest: named interfaces/descriptors, explicit LOC prefixes, deterministic longest-prefix route, next-hop MAC, source/interface anti-spoof policy, local/transit behavior, and no default route or dynamic neighbor discovery. Route, source, MTU, hop, filter, or privilege failures drop/close deterministically.

A narrow launcher validates the allowlist and isolated disposable namespace, opens only EtherType-filtered descriptors, drops groups/capabilities, sets no-new-privileges and immutable filter state where supported, then hands descriptors to a non-root daemon. Automatic mode requires no default route, no global address, no bridge/bond attachment, named entries only, non-root long-lived UID, no broad `CAP_NET_ADMIN`, and owned teardown markers. Failure to filter/drop required privilege aborts. Seccomp absence is a recorded residual, not a silently accepted control.

## Telemetry and data minimization

Telemetry uses structured monotonic timestamps and bounded counters only. It may count finite parser error categories; preauth bytes/table drops; pending/established/timeouts; auth/replay/counter closes; candidate/path transitions; dedup/divergence; route/hop/MTU/filter drops; and queue/window high-water marks. It MUST NOT log cookies, keys, plaintext, raw pins, or unbounded EID/SCID/LOC/IP/MAC labels.

Raw sensitive captures remain uncommitted and access-controlled. Committed minimized pcaps use synthetic vector identities. Published metrics/captures pseudonymize or remove EID, SCID, LOC, MAC, IP, and public-key values. This reduces disclosure; it does not provide unlinkability.

## Benchmark integrity, residuals, and stop gates

Q1–Q3 are evidence protocols, not product claims. Their frozen preregistration controls fixed N/warmups, block/randomization seed, readiness/outage trigger, payload/load, timeout/censoring, estimators/CI, supported quantiles, trust, clocks, environment, exclusions, and raw failure retention. Primary comparisons equalize application bytes under `P-APPLICATION-BUDGET`; mixed configurations, unequal event notice, or unrecorded topology/trust invalidate the comparison.

Benchmark process teardown is mandatory (`P-BENCHMARK-PROCESS-ISOLATION`). CPython’s residual-memory guarantees are limited to `P-CPYTHON-LIVE-REFERENCE-BOUND`, bounded lifetimes, no secret logs/core artifacts, and process isolation; wiping is explicitly not claimed. Rust owned secret buffers use library-supported zeroization.

Stop and review—not workaround—on wire/accepted-language ambiguity, ambiguous trust/transcript/binding bytes, unsupported maintained crypto APIs/licenses, parser crash, nonce reuse, auth/replay/binding bypass, unbounded state, secret leak, long-lived root/broad host change/non-isolated native attachment, missing path-topology evidence, or unequal benchmark triggers/trust/load. Disable only the newest explicit feature and return to the last independently usable gate; never weaken validation or silently fall back.
