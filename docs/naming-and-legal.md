# 명명·등록 관련 정책

## 왜 "IPv8"이 아니라 "R8"인가

IANA의 Internet Protocol Version Numbers 등록표에서 버전 번호 5~9의 상태:

| 번호 | 역사적 프로토콜 | 현재 상태 |
|---|---|---|
| 5 | ST/ST2 (스트리밍, RFC 1190/1819) | Reserved (Historic) |
| 6 | IPv6 | 현행 표준 |
| 7 | TP/IX (RFC 1475, 1993) | Reserved (Historic) |
| 8 | PIP (RFC 1621/1622) | Reserved (Historic) |
| 9 | TUBA | Reserved (Historic) |

버전 8은 "비어 있는 번호"가 아니라 역사적 배정이 있는 예약 번호다. 또한 2026년 4월에는 개인 자격으로 "IPv7"이라는 Internet-Draft(draft-subbiah-ipv7)가 제출된 바 있으나 이 역시 비공식이다. 따라서:

- 공개 산출물(코드, 문서, 리포지터리, 발표)에서는 **R8 (Roobicom Network Protocol)** 명칭만 사용한다.
- "IPv8"은 설계 문서에서 유래를 설명하는 별칭으로만 언급한다.
- 헤더의 Version 필드 값 8은 폐쇄망 실험 식별자일 뿐 IANA 배정을 주장하지 않는다.

## 번호 자원 사용 근거

| 자원 | 값 | 근거 | 제한 |
|---|---|---|---|
| EtherType | 0x88B5 | IEEE Local Experimental Ethertype 1 | 등록 불필요, 상호운용 주장 금지, 폐쇄망 전용 |
| UDP 포트 | 52808 | RFC 6335 동적/사설 범위 (49152–65535) | 미등록, 로컬 사용 전용 |
| LOC 주소 | `8::/16` 접두 권장 | 사설 실험 규칙 (RFC 4291 표기 재사용) | 공용 라우팅 공간과 무관 |

## 운영 규칙

1. R8 패킷을 공용 인터넷 또는 타 조직 네트워크로 보내지 않는다.
2. eth-binding(0x88B5)은 전용 VLAN/격리 스위치에서만 사용한다.
3. 표준화를 진지하게 추진하게 되면 그 시점에 새 이름과 새 버전 번호를 정식 절차로 신청한다.
4. 이 프로젝트는 IETF·IANA·IEEE와 무관하다.
