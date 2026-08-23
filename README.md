# R8 — Roobicom Network Protocol (실험 프로토타입)

> **경고**: R8은 인터넷 표준이 아닙니다. IETF/IANA와 무관한 폐쇄 시험망 전용 연구 프로토타입입니다. IANA의 IP 버전 번호 8은 과거 PIP 프로토콜에 배정됐던 Historic 번호이므로, 공개된 모든 산출물에서 이 프로토콜을 "IPv8"이라고 부르지 않습니다. 상세: `docs/naming-and-legal.md`

R8은 "신원(EID)과 위치(LOC)의 분리, 세션(SCID) 기반 이동성, 정책 기반 경로 선택"을 네트워크 계층에서 실험하는 프로토콜입니다. 목적은 새 인터넷 프로토콜의 제안이 아니라, **해당 설계 사상이 기존 대비 정량적 이득이 있는지 측정**하는 것입니다.

## 저장소 구조

```
spec/                 Gate-0 baseline·active contracts·architecture·검증 계획
  0000-baseline.md    bound commit/tree provenance and clean-v0.2 classification
  0001-wire-format-v0.1.md  offline historical emitted-byte evidence only
  0002-architecture.md
  0003-test-plan.md
  0004-wire-format-v0.2.md  single active strict wire target
  0005-session-security-v0.1.md
  0006-mobility-v0.1.md
  0007-native-binding-v0.1.md
  0008-redundant-v0.1.md
  parameters-v0.1.md  packet, binding, and resource-limit registry
tests/vectors/        shared corpus: 201 reviewed fixtures (73 wire + 41 session + 48 mobility + 39 redundant)
bench/protocols/      immutable Q1/Q2/Q3 preregistrations and manifest (no observed-result fields)
.github/workflows/    pinned least-privilege CI plus privileged closed-lab Q1/native/Q2 workflows; final-source hosted verification pending
requirements-dev.txt  pinned Python verification dependency set
reference/r8ref.py    strict v0.2 Python UDP implementation
reference/r8session.py  pinned cookie-first session reference
reference/r8mobility.py  signed mobility reference
reference/r8move.py    mobility loopback driver
rust/                 strict v0.2 Rust workspace
  crates/r8-proto       wire-format library + shared-corpus tests
  crates/r8-session     pinned cookie-first session library
  crates/r8-mobility    signed mobility library
  crates/r8d            UDP daemon plus isolated AF_PACKET native forwarder
  crates/r8ping         echo/DGRAM client
  crates/r8-redundant    authenticated Profile-3 redundant state + native endpoint
tools/
  netns-topo.sh       closed-lab network-namespace topology (setup|demo|teardown)
  wireshark/r8.lua    Wireshark dissector (udp/52808, ethertype 0x88B5)
```

## v0.2 closed-lab verification commands

`spec/0004-wire-format-v0.2.md` is the sole active wire contract. Python and Rust services default to loopback. Non-loopback use requires explicit isolated-lab authorization and an applicable binding budget; public, third-party, and non-isolated networks are forbidden. Telemetry must remain redacted and must not expose sensitive identifiers.

```bash
# Pinned Python verification dependency
python3 -m pip install --requirement requirements-dev.txt

# Python wire/session/mobility/redundant tests and bounded fuzz smoke
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tests/fuzz_reference.py
python3 -m unittest discover -s tests -p 'test_session.py'
python3 tests/fuzz_session.py
python3 -m unittest discover -s tests -p 'test_mobility.py'
python3 tests/fuzz_mobility.py
python3 tests/fuzz_redundant.py
python3 tests/fuzz_redundant_state.py

# Mandatory dissector coverage; requires tshark and fails rather than skipping when unavailable
R8_REQUIRE_TSHARK=1 python3 -m unittest discover -s tests -p 'test_dissector.py'

# Locked full Rust workspace verification, including session, mobility, native, and redundant
(cd rust && cargo fmt --all --check)
(cd rust && cargo clippy --workspace --all-targets --locked -- -D warnings)
(cd rust && cargo test --workspace --all-targets --locked)

# Build Rust apps and run bidirectional live loopback interop
python3 tests/interop.py --build
python3 tests/session_interop.py --build
python3 tests/mobility_interop.py --build

# Source identities and privileged hosted closed-lab workflows
python3 -c 'from bench import q1; print(q1.source_identity())'
python3 bench/q2_run.py source-identity
gh workflow run q1-full.yml -f host_epoch=closed-lab-epoch-NNN
gh workflow run native-full.yml -f gate3_run=Q1_SUCCESS_RUN_ID
gh workflow run q2-full.yml -f host_epoch=closed-lab-epoch-NNN -f gate5_run=NATIVE_SUCCESS_RUN_ID
```
`r8move --moving-role {1,2}` defaults to role 1; connect remains handshake role 1 and serve role 2, and the flag selects only the endpoint that initiates mobility. Both abrupt and make-before-break use a proof-gated candidate switch with old inbound-only grace, on closed loopback or an isolated lab only.

Q3 runs require a dedicated root network namespace and must not be invoked against shared-host loopback.

`spec/0001-wire-format-v0.1.md` remains offline provenance for historical emitted bytes only; it has no active parser, service, or compatibility path.

## 현재 상태와 로드맵

`spec/0000-baseline.md` binds the historical source snapshot to commit `aacadeee2a83b7639225cd11b9c020c69526fa1e` and tree `94fed3c18bbfb276c9fe5d558277b8afe1d7bca5`; those provenance facts are unchanged. `spec/0004-wire-format-v0.2.md` is the single active strict wire target. `0005-session-security-v0.1.md`, `0006-mobility-v0.1.md`, `0007-native-binding-v0.1.md`, `0008-redundant-v0.1.md`, and `parameters-v0.1.md` are frozen Gate-0 companion contracts. v0.1 is offline historical emitted-byte evidence only: active implementations do not accept it, and no compatibility shim exists.

| Stage | Scope | Status |
|---|---|---|
| Gate 0 | provenance / wire-change / budget / machine-contract baseline | ✅ durably checkpointed |
| Gate 1 / M0–M1 | strict v0.2 Python/Rust wire implementation and UDP interop | ✅ durably complete locally; latest retained hosted prior-snapshot CI is `31834671629`; final candidate verification pending |
| Gate 2 / G003 | pinned cookie-first sessions and Q3 evidence | locally complete; joined VB002 closure awaits fresh Q1 v5 evidence; canonical isolated-netns Q3 v8 evidence retained |
| Gate 3 / M3 / Q1 | signed proof-gated mobility and equal-notice Q1 | implementation/source/contract CLEAR; first publication-eligible Q1 v5 evidence retained from privileged run `31913402239` at `d62cd80` (`bench/results/q1-closed-lab-v5-run-31913402239`) |
| Gates 4–5 / M4–M5 | native forwarding and authenticated REDUNDANT | implemented and locally verified; privileged Gate 4/5 evidence pending (hosted runs currently blocked by account Actions billing) |
| Gate 6 / Q2 | paired native two-path measurement | v5 frozen with zero observations; forbidden until Gate 4/5 evidence clears |

### Q3 closed-lab result

The canonical Q3 full evidence package is immutable at `bench/results/q3-closed-lab-v8`, from hosted workflow `31835193766` at commit `881826bb64bc38bbbbffe7ab9cdcedecc98a82e2`. It is bound to source identity `sha256:6a9dea8d7f34d508d8e8b6220935a29834b5beda4cb17a52068df32d26d68ba3`, epoch `closed-lab-epoch-010`, and raw-data SHA-256 `f6234ac3d504f93511b8255b180b92da7e5a3babc342a0c7be5a65df6b19861c`. The dedicated loopback-only network namespace recorded zero failures across 4,200 rows. Cold p50/p90/p99 were R8 2.833492/2.913582/3.488101 ms and TLS 43.559856/43.975300/44.645833 ms; warm p50/p90 were R8 1.773880/1.875701 ms and TLS 41.696243/42.329702 ms. Network totals were R8 1,326 bytes and 7 packets in each direction, and TLS 3,979 bytes and 12 packets. This is closed-lab-only evidence, not an Internet or IPv8-standard claim.

Q3 v3 is historical and non-retained; v4, v6, and v7 are invalid/rejected and non-retained; no v5 exists. Gate 2/G003 remains deferred in joined VB002 until G004 closes. Q1 v2 is retained setup-only non-result evidence, Q1 v3 was cancelled without an artifact, and Q1 v4 run `31835854041` is retained as invalid diagnostic-only evidence with 63 pre-runtime readiness timeouts, `publication_eligible=false`, and an empty summary. The bounded child-liveness-aware fix is frozen as Q1 v5; no fresh full v5 result is claimed.

### Q1 closed-lab result (v5)

The first publication-eligible Q1 evidence package is immutable at `bench/results/q1-closed-lab-v5-run-31913402239`, from hosted workflow `31913402239` (workflow_dispatch, 2026-08-15, 3h13m42s) at commit `d62cd8054cf859ab85d21ddda22b02404f8d81fb`, epoch `closed-lab-epoch-260815225528`. All six cells (R8/TCP-reconnect/GARP-VIP × abrupt/make-before-break) ran 200 measured trials with zero failures under frozen preregistration v5 (`sha256:905f2eb8abd6a2927c4d3e8416574a4da9c4a9fe14eea4624a98a604b75b5b48`). Outage p50 was R8 110.038803 ms abrupt / 100.052691 ms make-before-break, TCP-reconnect 129.999624/120.000143 ms, GARP-VIP 100.002123/100.000793 ms; nearest-rank quantiles reproduce exactly from raw data. This is closed-lab-only evidence, not an Internet or IPv8-standard claim.

### Q1 retained invalid evidence

Q1 v2 remains setup-only non-result evidence. Q1 v4 is retained at `bench/results/q1-closed-lab-v4-invalid-run-31835854041/` solely as negative diagnostic evidence: all 1,320 rows are preserved, but none of its 1,257 complete runtime rows may enter an estimand.

## 설계 한계 (스스로 밝히는 것)

- SCID 참조는 어디까지가 허용 가능한 네트워크 상태인지에 대한 열린 질문을 남깁니다.
- EID→LOC 매핑 인프라의 운영 주체·조회 경로는 미해결 과제입니다 (LISP ALT/DDT의 교훈).
- 동일 가치의 상당 부분은 QUIC/MP-QUIC·SCION·RPKI 등 기존 기술이 제공합니다. R8은 대체제가 아니라 통합 실험체입니다.
