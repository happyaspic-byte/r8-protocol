# R8 — Roobicom Network Protocol (실험 프로토타입)

> **경고**: R8은 인터넷 표준이 아닙니다. IETF/IANA와 무관한 폐쇄 시험망 전용 연구 프로토타입입니다. IANA의 IP 버전 번호 8은 과거 PIP 프로토콜에 배정됐던 Historic 번호이므로, 공개된 모든 산출물에서 이 프로토콜을 "IPv8"이라고 부르지 않습니다. 상세: `docs/naming-and-legal.md`

R8은 "신원(EID)과 위치(LOC)의 분리, 세션(SCID) 기반 이동성, 정책 기반 경로 선택"을 네트워크 계층에서 실험하는 프로토콜입니다. 목적은 새 인터넷 프로토콜의 제안이 아니라, **해당 설계 사상이 기존 대비 정량적 이득이 있는지 측정**하는 것입니다.

## 저장소 구조

```
spec/                 와이어 포맷·아키텍처·검증 계획 (유일한 형식 기준)
  0001-wire-format-v0.1.md
  0002-architecture.md
  0003-test-plan.md
reference/r8ref.py    파이썬 참조 구현 (stdlib 전용, udp-binding, 셀프테스트 포함)
rust/                 Rust 워크스페이스 (std 전용)
  crates/r8-proto       와이어 포맷 라이브러리 + 단위 테스트
  crates/r8d            데몬 (echo 응답 + dgram 수신)
  crates/r8ping         echo 클라이언트
tools/
  netns-topo.sh       네트워크 네임스페이스 시험 토폴로지 (setup|demo|teardown)
  wireshark/r8.lua    Wireshark 디섹터 (udp/52808, ethertype 0x88B5)
```

## 빠른 시작

```bash
# 1) 참조 구현 셀프테스트 (의존성 없음)
python3 reference/r8ref.py selftest

# 2) 단일 호스트 loopback 시연
python3 reference/r8ref.py listen --address 8:1::10 --bind 127.0.0.1 &
python3 reference/r8ref.py ping --address 8:1::20 --peer 8:1::10=127.0.0.1:52808 8:1::10

# 3) 네임스페이스 토폴로지 (라우터 통과, Linux + root 필요)
sudo tools/netns-topo.sh setup
sudo tools/netns-topo.sh demo
sudo tools/netns-topo.sh teardown

# 4) Rust (CI가 컴파일 게이트)
cd rust && cargo test --workspace
```

## 현재 상태와 로드맵

| 단계 | 내용 | 상태 |
|---|---|---|
| M0 | 와이어 포맷 v0.1 스펙 | ✅ 문서화 |
| M1 | udp-binding + ECHO/DGRAM + 디섹터 | ✅ 참조 구현 검증 / Rust 스켈레톤 CI |
| M2 | OPEN/VERIFY_COOKIE 핸드셰이크 + Ed25519 EID + AEAD | ⬜ |
| M3 | EID/LOC 분리 + LOC_UPDATE 모빌리티 측정 (Q1) | ⬜ |
| M4 | eth-binding(0x88B5) 네이티브 모드 + R8 포워더 | ⬜ |
| M5 | 멀티패스 REDUNDANT 손실률 측정 (Q2) | ⬜ |

검증 질문(Q1~Q3)과 측정 방법은 `spec/0003-test-plan.md`를 따릅니다.

## 설계 한계 (스스로 밝히는 것)

- SCID 참조는 어디까지가 허용 가능한 네트워크 상태인지에 대한 열린 질문을 남깁니다.
- EID→LOC 매핑 인프라의 운영 주체·조회 경로는 미해결 과제입니다 (LISP ALT/DDT의 교훈).
- 동일 가치의 상당 부분은 QUIC/MP-QUIC·SCION·RPKI 등 기존 기술이 제공합니다. R8은 대체제가 아니라 통합 실험체입니다.
