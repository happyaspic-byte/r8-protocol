# R8 검증 계획 (마일스톤)

> 원칙: 테스트 환경은 데모가 아니라 **가설 검증 장치**다. 각 마일스톤은 측정 가능한 질문과 베이스라인을 갖는다.

## 검증 질문 (상위 3개)

- **Q1 (모빌리티)**: 위치(LOC) 전환 시 세션 유지 시간은 TCP 재연결 또는 VIP/ARP 전환 대비 얼마나 빠른가?
  - 베이스라인: 동일 토폴로지에서 TCP 재연결 시간, GARP 기반 VIP 전환 시간.
- **Q2 (신뢰성)**: Profile 3 복제 전송은 링크 플랩(1초 주기 down/up) 상황에서 단일 경로 대비 손실률을 얼마나 줄이는가?
  - 베이스라인: 동일 조건 단일 경로 UDP 손실률.
- **Q3 (비용)**: EID/SCID 세션 수립의 왕복·암호 연산 비용은 TCP+TLS 1.3 수립 대비 어느 정도인가?
  - 베이스라인: 동일 호스트 간 TLS 1.3 핸드셰이크 시간.

## 마일스톤

| ID | 내용 | 검증 | 완료 기준 |
|---|---|---|---|
| M0 | 와이어 포맷 스펙 확정 | 없음 | `0001` 문서 동결, 두 구현체가 같은 바이트 생성 |
| M1 | udp-binding + ECHO/DGRAM + Wireshark 디섹터 | 코드 기반 동작 | loopback/netns에서 echo 왕복, Wireshark 필드 해석 |
| M2 | OPEN/VERIFY_COOKIE/OPEN_ACK/SESSION_ACCEPT + Ed25519 EID + AEAD | Q3 | 핸드셰이크 p50/p99 측정, 위조 OPEN에 무상태 유지 확인 |
| M3 | EID/LOC 분리 + LOC_UPDATE 모빌리티 | Q1 | netns 두 세그먼트 간 이동 중 ping 연속성, 전환 시간 로그 |
| M4 | eth-binding(EtherType 0x88B5) + R8 포워더 | 순수 모드 시연 | IPv4/IPv6 비활성 인터페이스에서 echo 왕복 |
| M5 | 멀티패스 REDUNDANT | Q2 | 링크 플랩 중 손실률 비교 데이터 |

## 환경 규칙

- 물리 장비 없이 Linux 네트워크 네임스페이스 + veth로 시작한다 (`tools/netns-topo.sh`).
- VM/물리망으로 옮길 때는 NIC 오프로드(checksum/TSO)를 끈다: `ethtool -K <dev> rx off tx off tso off`.
- 일부 가상 스위치·보안 스위치는 알 수 없는 EtherType을 차단할 수 있으므로 M4 전에 장비별 통과 여부를 확인한다.
- 모든 측정은 스크립트로 재현 가능해야 하며 결과는 `results/`에 커밋한다.

## 비목표 (v0.1)

- 커널 통합(AF_INET8) — 성능 필요 시 커널 모듈보다 XDP/eBPF 우선 검토
- 기존 앱(SSH/Chrome) 네이티브 지원 — 필요하면 localhost 프록시로 우회
- 공용 인터넷 연결 — 폐쇄망 전용
