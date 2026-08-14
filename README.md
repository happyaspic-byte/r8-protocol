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
tests/vectors/        shared corpus: 162 reviewed fixtures (73 wire + 41 session + 48 mobility: 5 positive/43 negative); native/redundant families planned
bench/protocols/      immutable Q1/Q2/Q3 preregistrations and manifest (no observed-result fields)
.github/workflows/ci.yml  active least-privilege CI workflow; latest green hosted prior-snapshot CI `31803830187`; corrected dirty source awaits a new hosted CI
requirements-dev.txt  pinned Python verification dependency set
reference/r8ref.py    strict v0.2 Python UDP implementation
reference/r8session.py  pinned cookie-first session reference
reference/r8mobility.py  signed mobility reference
reference/r8move.py    mobility loopback driver
rust/                 strict v0.2 Rust workspace
  crates/r8-proto       wire-format library + shared-corpus tests
  crates/r8-session     pinned cookie-first session library
  crates/r8-mobility    signed mobility library
  crates/r8d            daemon (echo responder + DGRAM receiver)
  crates/r8ping         echo/DGRAM client
tools/
  netns-topo.sh       closed-lab network-namespace topology (setup|demo|teardown)
  wireshark/r8.lua    Wireshark dissector (udp/52808, ethertype 0x88B5)
```

## v0.2 closed-lab verification commands

`spec/0004-wire-format-v0.2.md` is the sole active wire contract. Python and Rust services default to loopback. Non-loopback use requires explicit isolated-lab authorization and an applicable binding budget; public, third-party, and non-isolated networks are forbidden. Telemetry must remain redacted and must not expose sensitive identifiers.

```bash
# Pinned Python verification dependency
python3 -m pip install --requirement requirements-dev.txt

# Python wire/session/mobility tests and fuzz smoke
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tests/fuzz_reference.py
python3 -m unittest discover -s tests -p 'test_session.py'
python3 tests/fuzz_session.py
python3 -m unittest discover -s tests -p 'test_mobility.py'
python3 tests/fuzz_mobility.py

# Mandatory dissector coverage; requires tshark and fails rather than skipping when unavailable
R8_REQUIRE_TSHARK=1 python3 -m unittest discover -s tests -p 'test_dissector.py'

# Locked Rust workspace verification, including session and mobility
(cd rust && cargo fmt --all --check)
(cd rust && cargo clippy --workspace --all-targets --locked -- -D warnings)
(cd rust && cargo test -p r8-session -p r8-mobility --locked)
(cd rust && cargo build -p r8-session -p r8-mobility --locked)

# Build Rust apps and run bidirectional live loopback interop
python3 tests/interop.py --build
python3 tests/session_interop.py --build
python3 tests/mobility_interop.py --build

# Q3: compute source identity, then request the hosted isolated-netns smoke/full workflow
python3 -c 'import runpy; print(runpy.run_path("bench/q3.py")["source_identity"]())'
gh workflow run q3-full.yml -f host_epoch=closed-lab-epoch-NNN
```
`r8move --moving-role {1,2}` defaults to role 1; connect remains handshake role 1 and serve role 2, and the flag selects only the endpoint that initiates mobility. Both abrupt and make-before-break use a proof-gated candidate switch with old inbound-only grace, on closed loopback or an isolated lab only.

Q3 runs require a dedicated root network namespace and must not be invoked against shared-host loopback.

`spec/0001-wire-format-v0.1.md` remains offline provenance for historical emitted bytes only; it has no active parser, service, or compatibility path.

## 현재 상태와 로드맵

`spec/0000-baseline.md` binds the historical source snapshot to commit `aacadeee2a83b7639225cd11b9c020c69526fa1e` and tree `94fed3c18bbfb276c9fe5d558277b8afe1d7bca5`; those provenance facts are unchanged. `spec/0004-wire-format-v0.2.md` is the single active strict wire target. `0005-session-security-v0.1.md`, `0006-mobility-v0.1.md`, `0007-native-binding-v0.1.md`, `0008-redundant-v0.1.md`, and `parameters-v0.1.md` are frozen Gate-0 companion contracts. v0.1 is offline historical emitted-byte evidence only: active implementations do not accept it, and no compatibility shim exists.

| Stage | Scope | Status |
|---|---|---|
| Gate 0 | provenance / wire-change / budget / machine-contract baseline | ✅ durably checkpointed |
| Gate 1 / M0–M1 | strict v0.2 Python/Rust wire implementation and UDP interop | ✅ durably complete locally; latest green hosted prior-snapshot CI `31803830187`; corrected dirty source awaits a new hosted CI |
| Gate 2 / G003 | pinned cookie-first sessions and Q3 evidence | deferred in joined VB002 until G004 closes; isolated-netns v8 implementation/q3-full workflow awaits a new hosted observation |
| M3 / Q1 | mobility implementation | implemented; Q1 v4 preregistered and awaits privileged smoke |
| M4–M5 / Q2 | native binding, REDUNDANT, and registered measurement protocol | ⬜ unexecuted |

### Q3 closed-lab result

No canonical Q3 result is currently retained. Q3 v7 is rejected and non-retained because host-global loopback counters were contaminated and unattributable; Q3 v6 is rejected and non-retained because expected TLS-pin setup biased its timed path. Q3 v4 is invalid and non-retained, Q3 v3 is a historical run and non-retained, and no Q3 v5 result is retained. No Q3 result package remains until the isolated-netns v8 implementation/q3-full workflow produces a new hosted observation. Any future observation remains limited to the isolated closed lab and is not an Internet or IPv8-standard claim.

The latest green hosted prior-snapshot CI is `31803830187`; the corrected dirty source awaits a new hosted CI and Q1 v4 privileged smoke. Gate 2/G003 remains deferred in joined VB002 until G004 closes. Q1 v2 is retained setup-only non-result evidence, Q1 v3 was cancelled without an artifact, and Q1 v4 is preregistered. No current hosted CI, Q3 result, full Q1, or G004 pass is claimed.

### Q1 retained failed setup evidence

Q1 v2 is retained at `bench/results/q1-setup-failure-v2/` as setup-only evidence, not a Q1 result and not canonical performance evidence. Its manifest route-ordering diagnosis is a historical unverified hypothesis, not an established root cause; current status infers none pending Q1 v4 privileged-smoke verification.

## 설계 한계 (스스로 밝히는 것)

- SCID 참조는 어디까지가 허용 가능한 네트워크 상태인지에 대한 열린 질문을 남깁니다.
- EID→LOC 매핑 인프라의 운영 주체·조회 경로는 미해결 과제입니다 (LISP ALT/DDT의 교훈).
- 동일 가치의 상당 부분은 QUIC/MP-QUIC·SCION·RPKI 등 기존 기술이 제공합니다. R8은 대체제가 아니라 통합 실험체입니다.
