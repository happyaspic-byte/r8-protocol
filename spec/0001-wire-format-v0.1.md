# R8 와이어 포맷 v0.1

> 상태: DRAFT — 실험용. 공용 인터넷 표준이 아니며 폐쇄 시험망 전용.
> 명명 규칙과 IANA 관련 주의사항은 `docs/naming-and-legal.md` 참조.

## 1. 캐리어 바인딩

R8 패킷은 두 가지 캐리어로 운반할 수 있다. 프로토콜 로직은 캐리어와 무관하게 동일하다.

| 바인딩 | 캐리어 | 식별자 | 용도 |
|---|---|---|---|
| udp-binding | UDP 페이로드 | 목적지 포트 52808 (동적/사설 범위, RFC 6335) | 개발·디버깅·서브넷 간 시험 |
| eth-binding | Ethernet 페이로드 | EtherType 0x88B5 (IEEE 로컬 실험용) | 순수 네이티브 시연 (단일 L2 구간) |

## 2. 기본 헤더 (48바이트)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|Profile| Traffic Class |        Payload Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Next Header   |  Hop Limit    |     Flags     |   Path Slot   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                 Session Context ID (64 bit)                   +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                Source Routing Locator (128 bit)               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|              Destination Routing Locator (128 bit)            |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| 필드 | 오프셋 | 크기 | 설명 |
|---|---|---|---|
| Version | 0 (상위 4비트) | 4b | 항상 8 |
| Profile | 0 (하위 4비트) | 4b | 0=일반 1=저지연 2=산업제어 3=고신뢰복제 4=DTN 5=저전력IoT |
| Traffic Class | 1 | 8b | QoS 표시 (v0.1: 0 고정) |
| Payload Length | 2 | 16b | 헤더 이후 바이트 수 |
| Next Header | 4 | 8b | 1=CTL 2=DGRAM 3=SES 59=NONE |
| Hop Limit | 5 | 8b | 홉마다 감소, 0 도달 시 폐기 + TIME_EXCEEDED |
| Flags | 6 | 8b | bit0 V(검증된 세션) bit1 R(복제 패킷) bit2 C(Custody 요청), 나머지 예약 |
| Path Slot | 7 | 8b | 세션 내 경로 번호. 0=기본 |
| SCID | 8 | 64b | 세션 컨텍스트. 0=무세션(v0.1 정적 모드) |
| Source LOC | 16 | 128b | 출발지 라우팅 로케이터 |
| Destination LOC | 32 | 128b | 목적지 라우팅 로케이터 |

모든 정수 필드는 빅엔디언이다.

## 3. 주소 표기

- LOC와 EID는 모두 128비트이며 텍스트 표기는 RFC 4291 형식을 재사용한다.
- 시험망 LOC는 앞 첫 헥스텟을 `8:`로 시작하는 규칙을 권장한다. 예: `8:1::10`, `8:2::1`.
- EID는 v0.1에서 설정 파일로 지정한다. M2에서 공개키 해시 유도 방식으로 교체한다.
- 라우팅은 LOC에 대한 longest-prefix-match다.

## 4. CTL (Next Header = 1)

제어 메시지. 공통 헤더: Type(1) Code(1) Checksum(2) Body.

| Type | 이름 | Code | Body |
|---|---|---|---|
| 1 | ECHO_REQUEST | 0 | Identifier(2) Sequence(2) Data(n) |
| 2 | ECHO_REPLY | 0 | ECHO_REQUEST body 그대로 반사 |
| 128 | DEST_UNREACHABLE | 0=no-route 1=addr-unreach 3=port-unreach 4=admin-prohibited | 원본 패킷 앞부분(최대 512바이트) |
| 129 | TIME_EXCEEDED | 0=hop-limit 1=reassembly-timeout | 원본 패킷 앞부분 |
| 130 | PACKET_TOO_BIG | 0 | MTU(4) + 원본 패킷 앞부분 |

Type < 128은 정보성, >= 128은 오류다. 오류 메시지에 대한 오류는 생성하지 않는다.

Checksum: Source LOC + Destination LOC + Payload Length(4바이트 확장) + Next Header(4바이트 확장) + CTL 전체에 대한 16비트 1의 보수. 0x0000이면 검사 생략(v0.1 허용).

## 5. DGRAM (Next Header = 2)

비신뢰 데이터그램 전송.

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Source Port            |      Destination Port         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Length              |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Payload ...
```

Length는 DGRAM 헤더 포함 길이. Checksum 계산은 CTL과 동일하며 0x0000이면 생략. 혼잡제어·재전송·순서 보장은 상위 계층 책임이다.

## 6. SES (Next Header = 3)

세션 관리 메시지. 공통: Type(1) Flags(1) Reserved(2) Body.

| Type | 이름 | Body | 단계 |
|---|---|---|---|
| 1 | OPEN | SrcEID(16) DstEID(16) CryptoSuites(TLV) | M1 형식만, M2 구현 |
| 2 | VERIFY_COOKIE | Cookie(16) | M2 |
| 3 | OPEN_ACK | OPEN body + Cookie(16) | M2 |
| 4 | SESSION_ACCEPT | SCID(8) | M2 |
| 5 | LOC_UPDATE | EID(16) NewLOC(16) Expiry(4) Signature(64) | M3 |
| 6 | CLOSE | SCID(8) Reason(1) | M2 |

핸드셰이크 시퀀스:

```
Client                          Server
  | ------- OPEN -------------> |
  | <---- VERIFY_COOKIE ------- |   (주소 검증 전 상태 생성 금지)
  | ------- OPEN_ACK ---------> |
  | <---- SESSION_ACCEPT ------ |   (SCID 확정, 이후 SCID로 상태 참조)
```

**경고**: v0.1의 SES 구현체는 암호·서명이 없는 INSECURE 스텁이다. 토폴로지 시험 외 목적으로 사용 금지. M2에서 Ed25519 신원 증명 + AEAD(ChaCha20-Poly1305)로 교체하고, 이후 포스트퀀텀 하이브리드 협상을 추가한다.

## 7. 재전송 공격 방지 (M2 이후)

검증된 세션의 모든 데이터 패킷은 64비트 패킷 번호를 AEAD AAD에 포함하고, 수신자는 슬라이딩 윈도우로 중복을 폐기한다. v0.1 무세션 모드에는 적용되지 않는다.

## 8. MTU와 단편화

v0.1은 단편화를 제공하지 않는다. 시험망 최소 MTU는 1280바이트로 가정한다. 초과 시 송신자가 PACKET_TOO_BIG를 받고 페이로드를 줄여야 한다.

## 9. 버전 규칙

- 헤더의 Version 필드는 프로토콜 메이저 버전(8)이며, 이 문서의 v0.1은 와이어 포맷 개정 번호다.
- 와이어 포맷 개정은 이 문서의 번호를 올리고 변경 이력을 남긴다. 호환 불가 변경은 SES CryptoSuites 협상으로 감지한다.
