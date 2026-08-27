# R8 External Comparison Benchmark Design

## Status

Approved for implementation on 2026-08-27 by the user's instruction to start. This comparison is a new series and does not modify frozen Q1, Q2, or Q3 contracts or their result claims.

## Goal

Measure R8 against deployable alternatives on identical isolated Linux network-namespace conditions. The first implementation slice compares:

1. R8 session mobility against QUIC connection migration.
2. R8 Profile-3 redundant delivery against Linux MPTCP failover.

LISP xTR comparison is a second slice because it requires a separately pinned external implementation, configuration language, and mapping service.

## Safety and integrity constraints

- Run only in disposable Linux network namespaces.
- Reject public, third-party, bridged, default-route, or non-isolated attachments.
- Never call the protocol “IPv8” except when explaining why that name is prohibited.
- Keep `bench/protocols/q1.json`, `q2.json`, and `q3.json` byte-identical.
- Store comparison contracts under `bench/compare/`, outside the Q1–Q3 manifest.
- Retain failures and timeouts as rows. Never silently retry or drop a failed trial.
- Use the same event time, payload schedule, observation window, namespace topology, MTU, and CPU accounting for mechanisms in one comparison.
- Label QUIC and MPTCP results as transport-layer alternatives, not equivalent EID/LOC implementations.

## Architecture

### Package layout

- `bench/compare/model.py`: closed row model, canonical JSON, IDs, fixed plan, summary functions.
- `bench/compare/netns.py`: isolated two-path topology lifecycle, qdisc flap, counters, cleanup proof.
- `bench/compare/quic_runner.py`: QUIC migration adapter with a narrow subprocess protocol.
- `bench/compare/mptcp_runner.py`: Linux MPTCP adapter and socket-level subflow checks.
- `bench/compare/run.py`: CLI orchestration, atomic package writing, source/environment binding.
- `bench/compare/validate.py`: independent package validation and cardinality checks.
- `bench/compare/protocol-v1.json`: frozen comparison parameters and implementation bindings.
- `tests/test_compare_model.py`: pure model/contract tests.
- `tests/test_compare_netns.py`: root-gated smoke tests for topology cleanup and event timing.

### Comparison A: mobility

Cells:

| Mechanism | Event | Warmups | Measured | Payload cadence | Observation |
|---|---:|---:|---:|---:|---:|
| R8 session mobility | client underlay switch A→B | 10 | 100 | 10 ms | event -1 s through +3 s |
| QUIC migration | client underlay switch A→B + path validation | 10 | 100 | 10 ms | event -1 s through +3 s |

Metrics:

- last authenticated delivery before event
- first sequence of two consecutive authenticated on-schedule deliveries after event
- outage duration
- lost, duplicate, and reordered payloads
- mechanism control bytes
- process CPU nanoseconds
- failure rate

The QUIC implementation uses a pinned Python package initially for portability. The adapter exposes only `ready`, `sent`, `received`, `migrated`, `failed`, and `done` JSON events. Secrets, connection IDs, IPs, and raw packet bytes are prohibited from retained output.

### Comparison B: path failover

Cells:

| Mechanism | Event | Warmups | Measured | Payload cadence | Observation |
|---|---:|---:|---:|---:|---:|
| R8 REDUNDANT | Path A 100% loss for 1 s | 10 | 100 | 10 ms | event -1 s through +3 s |
| Linux MPTCP | Path A 100% loss for 1 s | 10 | 100 | 10 ms | event -1 s through +3 s |
| UDP single path | Path A 100% loss for 1 s | 10 | 100 | 10 ms | event -1 s through +3 s |

Metrics:

- payload loss and duplicate rate
- maximum delivery gap
- first post-event recovery time
- wire bytes and packets per path
- CPU nanoseconds
- subflow/path proof
- failure rate

MPTCP eligibility requires `net.mptcp.enabled=1`, two established subflows observed before the event, and no host-global sysctl changes. Namespace-local endpoint configuration is allowed and must be restored by namespace deletion.

## Evidence package

A complete package contains:

- `manifest.json`
- `environment.json`
- `plan.jsonl`
- `trial.jsonl`
- `packet.jsonl`
- `summary.json`
- `publication_eligible.json`

Every file except `manifest.json` is SHA-256-bound by the manifest. The manifest binds the git commit, clean-tree state, implementation source map, tool versions, protocol contract hash, row counts, and limitations.

## Eligibility

A package is publication-eligible only when:

- every planned row exists exactly once
- all warmups and measured trials ran
- topology setup and cleanup proofs passed for every seed
- mechanism prerequisites were proven per trial
- no mixed host epoch, commit, source map, MTU, cadence, or payload size exists
- the independent validator returns no errors
- no sensitive retained field or value is present

A failed trial does not make a package ineligible if its failure is finite, classified, retained, and all evidence remains complete. Setup/cleanup or prerequisite failures make that trial non-estimable and remain in denominators.

## Testing

- Pure unit tests cover plan determinism, canonical IDs, summary denominators, failure retention, and sensitive-field rejection.
- Namespace smoke tests use one seed and reduced payload count.
- CI runs pure tests on every PR and a bounded root smoke on the hosted Linux runner.
- Full runs remain manual `workflow_dispatch` jobs.
