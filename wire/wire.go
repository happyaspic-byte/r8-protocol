// Package wire implements the strict R8 wire-format v0.2 contract.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	HeaderSize           = 48
	MaxPacketSize        = 1280
	IPv4UDPDefaultBudget = 1252
	IPv6UDPDefaultBudget = 1232

	NextHeaderCTL   uint8 = 1
	NextHeaderDGRAM uint8 = 2
	NextHeaderSES   uint8 = 3
	NextHeaderNONE  uint8 = 59
)

type WireError string

const (
	ErrTruncated      WireError = "TRUNCATED"
	ErrTrailingBytes  WireError = "TRAILING_BYTES"
	ErrPacketCap      WireError = "PACKET_CAP"
	ErrBindingBudget  WireError = "BINDING_BUDGET"
	ErrLengthOverflow WireError = "LENGTH_OVERFLOW"
	ErrVersion        WireError = "VERSION"
	ErrProfile        WireError = "PROFILE"
	ErrTrafficClass   WireError = "TRAFFIC_CLASS"
	ErrNextHeader     WireError = "NEXT_HEADER"
	ErrHopLimit       WireError = "HOP_LIMIT"
	ErrFlags          WireError = "FLAGS"
	ErrPathSlot       WireError = "PATH_SLOT"
	ErrSCID           WireError = "SCID"
	ErrNonePayload    WireError = "NONE_PAYLOAD"
	ErrCTLShort       WireError = "CTL_SHORT"
	ErrCTLType        WireError = "CTL_TYPE"
	ErrCTLCode        WireError = "CTL_CODE"
	ErrCTLBody        WireError = "CTL_BODY"
	ErrCTLChecksum    WireError = "CTL_CHECKSUM"
	ErrDGRAMShort     WireError = "DGRAM_SHORT"
	ErrDGRAMLength    WireError = "DGRAM_LENGTH"
	ErrDGRAMChecksum  WireError = "DGRAM_CHECKSUM"
)

func (e WireError) Error() string { return string(e) }

var ErrBudget = errors.New("E-BUDGET")

func ErrorCategory(err error) WireError {
	var category WireError
	if errors.As(err, &category) {
		return category
	}
	return ""
}

type Header struct {
	Profile        uint8
	TrafficClass   uint8
	NextHeader     uint8
	HopLimit       uint8
	Flags          uint8
	PathSlot       uint8
	SCID           uint64
	SourceLOC      [16]byte
	DestinationLOC [16]byte
}

type Packet struct {
	Header  Header
	Payload []byte
}

type PacketInput struct {
	Header         Header
	SourceLOC      []byte
	DestinationLOC []byte
	Payload        []byte
}

func Parse(data []byte, bindingBudget int) (*Packet, error) {
	if len(data) > MaxPacketSize {
		return nil, ErrPacketCap
	}
	if bindingBudget < HeaderSize || bindingBudget > MaxPacketSize || len(data) > bindingBudget {
		return nil, ErrBindingBudget
	}
	if len(data) < HeaderSize {
		return nil, ErrTruncated
	}
	payloadLength := int(binary.BigEndian.Uint16(data[2:4]))
	expected := HeaderSize + payloadLength
	if expected > MaxPacketSize {
		return nil, ErrPacketCap
	}
	if expected > bindingBudget {
		return nil, ErrBindingBudget
	}
	if len(data) < expected {
		return nil, ErrTruncated
	}
	if len(data) > expected {
		return nil, ErrTrailingBytes
	}
	profile := data[0] & 0x0f
	if data[0]>>4 != 8 {
		return nil, ErrVersion
	}
	next := data[4]
	if next != NextHeaderCTL && next != NextHeaderDGRAM && next != NextHeaderSES && next != NextHeaderNONE {
		return nil, ErrNextHeader
	}
	h := Header{Profile: profile, TrafficClass: data[1], NextHeader: next, HopLimit: data[5], Flags: data[6], PathSlot: data[7], SCID: binary.BigEndian.Uint64(data[8:16])}
	copy(h.SourceLOC[:], data[16:32])
	copy(h.DestinationLOC[:], data[32:48])
	payload := data[HeaderSize:]
	if next == NextHeaderSES {
		if err := validateSES(h, payload); err != nil {
			return nil, err
		}
	} else {
		if err := validateGeneric(h); err != nil {
			return nil, err
		}
	}
	switch next {
	case NextHeaderNONE:
		if len(payload) != 0 {
			return nil, ErrNonePayload
		}
	case NextHeaderCTL:
		if err := validateCTL(h, payload); err != nil {
			return nil, err
		}
	case NextHeaderDGRAM:
		if err := validateDGRAM(h, payload); err != nil {
			return nil, err
		}
	}
	return &Packet{Header: h, Payload: append([]byte(nil), payload...)}, nil
}

func validateGeneric(h Header) error {
	if h.Profile > 3 {
		return ErrProfile
	}
	if h.TrafficClass != 0 {
		return ErrTrafficClass
	}
	if h.HopLimit == 0 {
		return ErrHopLimit
	}
	if h.Flags&^uint8(0x03) != 0 {
		return ErrFlags
	}
	if h.Profile != 0 {
		return ErrProfile
	}
	if h.Flags != 0 {
		return ErrFlags
	}
	if h.PathSlot != 0 {
		return ErrPathSlot
	}
	if h.SCID != 0 {
		return ErrSCID
	}
	return nil
}

func validateSES(h Header, payload []byte) error {
	if h.SCID == 0 {
		return ErrSCID
	}
	if len(payload) < 4 {
		return ErrTruncated
	}
	typeValue, sessionVersion, sessionProfile, sessionFlags := payload[0], payload[1], payload[2], payload[3]
	if typeValue < 1 || typeValue > 7 || sessionVersion != 1 {
		return ErrNextHeader
	}
	if h.Profile > 3 || sessionProfile > 3 || sessionProfile != h.Profile {
		return ErrProfile
	}
	if h.TrafficClass != 0 {
		return ErrTrafficClass
	}
	if h.HopLimit == 0 {
		return ErrHopLimit
	}
	allowedFlags := uint8(0)
	allowedSlot := uint8(0)
	if typeValue == 5 || typeValue == 6 || typeValue == 7 {
		allowedFlags = 1
	}
	if (typeValue == 6 || typeValue == 7) && h.Profile == 3 && h.Flags == 3 {
		allowedFlags = 3
		allowedSlot = 1
	}
	if sessionFlags != 0 || h.Flags&^uint8(0x03) != 0 || h.Flags != allowedFlags {
		return ErrFlags
	}
	if h.PathSlot != allowedSlot {
		return ErrPathSlot
	}
	return nil
}

type CTL struct {
	Type uint8
	Code uint8
	Body []byte
}

type DGRAM struct {
	SourcePort      uint16
	DestinationPort uint16
	Data            []byte
}

func ParseCTL(header Header, payload []byte) (CTL, error) {
	if err := validateCTL(header, payload); err != nil {
		return CTL{}, err
	}
	return CTL{Type: payload[0], Code: payload[1], Body: append([]byte(nil), payload[4:]...)}, nil
}

func ParseDGRAM(header Header, payload []byte) (DGRAM, error) {
	if err := validateDGRAM(header, payload); err != nil {
		return DGRAM{}, err
	}
	return DGRAM{
		SourcePort:      binary.BigEndian.Uint16(payload[0:2]),
		DestinationPort: binary.BigEndian.Uint16(payload[2:4]),
		Data:            append([]byte(nil), payload[8:]...),
	}, nil
}

func validateCTL(h Header, payload []byte) error {
	if len(payload) < 4 {
		return ErrCTLShort
	}
	typeValue, code := payload[0], payload[1]
	body := payload[4:]
	switch typeValue {
	case 1, 2:
		if code != 0 {
			return ErrCTLCode
		}
		if len(body) < 4 {
			return ErrCTLBody
		}
	case 128:
		if code != 0 && code != 1 && code != 3 && code != 4 {
			return ErrCTLCode
		}
		if len(body) > 512 {
			return ErrCTLBody
		}
	case 129:
		if code != 0 {
			return ErrCTLCode
		}
		if len(body) > 512 {
			return ErrCTLBody
		}
	case 130:
		if code != 0 {
			return ErrCTLCode
		}
		if len(body) < 4 || len(body)-4 > 512 {
			return ErrCTLBody
		}
	default:
		return ErrCTLType
	}
	if binary.BigEndian.Uint16(payload[2:4]) == 0 || checksum(h, payload, 2) != binary.BigEndian.Uint16(payload[2:4]) {
		return ErrCTLChecksum
	}
	return nil
}

func validateDGRAM(h Header, payload []byte) error {
	if len(payload) < 8 {
		return ErrDGRAMShort
	}
	if int(binary.BigEndian.Uint16(payload[4:6])) != len(payload) {
		return ErrDGRAMLength
	}
	if binary.BigEndian.Uint16(payload[6:8]) == 0 || checksum(h, payload, 6) != binary.BigEndian.Uint16(payload[6:8]) {
		return ErrDGRAMChecksum
	}
	return nil
}

func checksum(h Header, payload []byte, checksumOffset int) uint16 {
	input := make([]byte, 40+len(payload))
	copy(input[0:16], h.SourceLOC[:])
	copy(input[16:32], h.DestinationLOC[:])
	binary.BigEndian.PutUint32(input[32:36], uint32(len(payload)))
	binary.BigEndian.PutUint32(input[36:40], uint32(h.NextHeader))
	copy(input[40:], payload)
	input[40+checksumOffset], input[40+checksumOffset+1] = 0, 0
	var sum uint32
	for i := 0; i+1 < len(input); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(input[i : i+2]))
	}
	if len(input)%2 != 0 {
		sum += uint32(input[len(input)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	value := ^uint16(sum)
	if value == 0 {
		return 0xffff
	}
	return value
}

func Build(header Header, payload []byte, bindingBudget int) ([]byte, error) {
	if len(payload) > 65535 {
		return nil, ErrLengthOverflow
	}
	total := HeaderSize + len(payload)
	if bindingBudget < HeaderSize || bindingBudget > MaxPacketSize || total > MaxPacketSize || total > bindingBudget {
		return nil, ErrBudget
	}
	if header.Profile > 15 {
		return nil, ErrLengthOverflow
	}
	out := make([]byte, total)
	out[0] = 0x80 | header.Profile
	out[1] = header.TrafficClass
	binary.BigEndian.PutUint16(out[2:4], uint16(len(payload)))
	out[4], out[5], out[6], out[7] = header.NextHeader, header.HopLimit, header.Flags, header.PathSlot
	binary.BigEndian.PutUint64(out[8:16], header.SCID)
	copy(out[16:32], header.SourceLOC[:])
	copy(out[32:48], header.DestinationLOC[:])
	copy(out[48:], payload)
	if _, err := Parse(out, bindingBudget); err != nil {
		return nil, err
	}
	return out, nil
}

func BuildPacket(input PacketInput, bindingBudget int) ([]byte, error) {
	if len(input.SourceLOC) != 16 || len(input.DestinationLOC) != 16 || len(input.Payload) > 65535 {
		return nil, ErrLengthOverflow
	}
	copy(input.Header.SourceLOC[:], input.SourceLOC)
	copy(input.Header.DestinationLOC[:], input.DestinationLOC)
	return Build(input.Header, input.Payload, bindingBudget)
}

func BuildCTL(header Header, typeValue, code uint8, body []byte, bindingBudget int) ([]byte, error) {
	if len(body) > MaxPacketSize-HeaderSize-4 {
		return nil, ErrBudget
	}
	header.NextHeader, header.Profile, header.Flags, header.PathSlot, header.SCID = NextHeaderCTL, 0, 0, 0, 0
	payload := make([]byte, 4+len(body))
	payload[0], payload[1] = typeValue, code
	copy(payload[4:], body)
	binary.BigEndian.PutUint16(payload[2:4], checksum(header, payload, 2))
	return Build(header, payload, bindingBudget)
}

func BuildDGRAM(header Header, sourcePort, destinationPort uint16, data []byte, bindingBudget int) ([]byte, error) {
	if len(data) > 65527 {
		return nil, ErrLengthOverflow
	}
	header.NextHeader, header.Profile, header.Flags, header.PathSlot, header.SCID = NextHeaderDGRAM, 0, 0, 0, 0
	payload := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(payload[0:2], sourcePort)
	binary.BigEndian.PutUint16(payload[2:4], destinationPort)
	binary.BigEndian.PutUint16(payload[4:6], uint16(len(payload)))
	copy(payload[8:], data)
	binary.BigEndian.PutUint16(payload[6:8], checksum(header, payload, 6))
	return Build(header, payload, bindingBudget)
}

func BuildNONE(header Header, bindingBudget int) ([]byte, error) {
	header.NextHeader, header.Profile, header.Flags, header.PathSlot, header.SCID = NextHeaderNONE, 0, 0, 0, 0
	return Build(header, nil, bindingBudget)
}

func CanonicalSessionAssociatedData(serializedHeader []byte) ([]byte, error) {
	if len(serializedHeader) != HeaderSize {
		return nil, fmt.Errorf("header length %d: %w", len(serializedHeader), ErrLengthOverflow)
	}
	canonical := append([]byte(nil), serializedHeader...)
	canonical[5] = 0
	return canonical, nil
}
