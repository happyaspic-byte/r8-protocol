package wire_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/happyaspic-byte/r8-protocol/wire"
)

type vectorFile struct {
	Positive        []vectorCase `json:"positive_cases"`
	Negative        []vectorCase `json:"negative_cases"`
	BindingBoundary []vectorCase `json:"binding_boundary_cases"`
}

type vectorCase struct {
	ID                       string            `json:"id"`
	PacketHex                string            `json:"packet_hex"`
	ExpectedError            string            `json:"expected_error"`
	BindingBudget            int               `json:"binding_budget_bytes"`
	SerializerBudgetOutcomes map[string]string `json:"serializer_budget_outcomes"`
	CarrierExpectations      map[string]string `json:"carrier_expectations"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "tests", "vectors", "wire-v0.2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func packetBytes(t *testing.T, value string) []byte {
	t.Helper()
	packet, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestSharedVectors(t *testing.T) {
	vectors := loadVectors(t)
	if total := len(vectors.Positive) + len(vectors.Negative) + len(vectors.BindingBoundary); total != 73 {
		t.Fatalf("shared vector count = %d, want 73", total)
	}
	for _, tc := range vectors.Positive {
		t.Run(tc.ID, func(t *testing.T) {
			if _, err := wire.Parse(packetBytes(t, tc.PacketHex), wire.MaxPacketSize); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
		})
	}
	for _, tc := range vectors.Negative {
		t.Run(tc.ID, func(t *testing.T) {
			budget := wire.MaxPacketSize
			if tc.BindingBudget != 0 {
				budget = tc.BindingBudget
			}
			_, err := wire.Parse(packetBytes(t, tc.PacketHex), budget)
			if tc.ExpectedError == "" {
				t.Fatalf("missing expected_error")
			}
			if got := wire.ErrorCategory(err); got != wire.WireError(tc.ExpectedError) {
				t.Fatalf("Parse() category = %q, want %q (err %v)", got, tc.ExpectedError, err)
			}
		})
	}
	for _, tc := range vectors.BindingBoundary {
		t.Run(tc.ID, func(t *testing.T) {
			packet := packetBytes(t, tc.PacketHex)
			parsed, err := wire.Parse(packet, wire.MaxPacketSize)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			for name, outcome := range tc.SerializerBudgetOutcomes {
				budget := map[string]int{"ipv4_udp_1252": wire.IPv4UDPDefaultBudget, "ipv6_udp_1232": wire.IPv6UDPDefaultBudget, "serialized_1280": wire.MaxPacketSize}[name]
				encoded, err := wire.Build(parsed.Header, parsed.Payload, budget)
				if outcome == "accept" {
					if err != nil {
						t.Fatalf("Build(%s) error = %v", name, err)
					}
					if string(encoded) != string(packet) {
						t.Fatalf("Build(%s) differs", name)
					}
				} else if !errors.Is(err, wire.ErrBudget) {
					t.Fatalf("Build(%s) error = %v, want ErrBudget", name, err)
				}
			}
		})
	}
}

func TestBindingSpecificParseOutcome(t *testing.T) {
	vectors := loadVectors(t)
	var tc vectorCase
	for _, candidate := range vectors.Negative {
		if candidate.ID == "ses-binding-budget-before-version" {
			tc = candidate
			break
		}
	}
	packet := packetBytes(t, tc.PacketHex)
	for carrier, expected := range tc.CarrierExpectations {
		budget := map[string]int{"udp4": wire.IPv4UDPDefaultBudget, "udp6": wire.IPv6UDPDefaultBudget, "native": wire.MaxPacketSize}[carrier]
		_, err := wire.Parse(packet, budget)
		if got := wire.ErrorCategory(err); got != wire.WireError(expected) {
			t.Fatalf("Parse(%s) = %q, want %q", carrier, got, expected)
		}
	}
}

func TestBuildersRoundTrip(t *testing.T) {
	header := wire.Header{HopLimit: 64}
	for name, build := range map[string]func() ([]byte, error){
		"ctl": func() ([]byte, error) {
			return wire.BuildCTL(header, 1, 0, []byte{0x12, 0x34, 0, 1}, wire.MaxPacketSize)
		},
		"dgram": func() ([]byte, error) {
			return wire.BuildDGRAM(header, 0x1234, 0x5678, []byte("abc"), wire.MaxPacketSize)
		},
		"none": func() ([]byte, error) { return wire.BuildNONE(header, wire.MaxPacketSize) },
	} {
		t.Run(name, func(t *testing.T) {
			packet, err := build()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wire.Parse(packet, wire.MaxPacketSize); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPayloadParsers(t *testing.T) {
	header := wire.Header{HopLimit: 64}
	ctlPacket, err := wire.BuildCTL(header, 1, 0, []byte{0x12, 0x34, 0, 1}, wire.MaxPacketSize)
	if err != nil {
		t.Fatal(err)
	}
	parsedCTLPacket, err := wire.Parse(ctlPacket, wire.MaxPacketSize)
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := wire.ParseCTL(parsedCTLPacket.Header, parsedCTLPacket.Payload)
	if err != nil || ctl.Type != 1 || ctl.Code != 0 || len(ctl.Body) != 4 {
		t.Fatalf("ParseCTL() = %+v, %v", ctl, err)
	}

	dgramPacket, err := wire.BuildDGRAM(header, 0x1234, 0x5678, []byte("abc"), wire.MaxPacketSize)
	if err != nil {
		t.Fatal(err)
	}
	parsedDGRAMPacket, err := wire.Parse(dgramPacket, wire.MaxPacketSize)
	if err != nil {
		t.Fatal(err)
	}
	dgram, err := wire.ParseDGRAM(parsedDGRAMPacket.Header, parsedDGRAMPacket.Payload)
	if err != nil || dgram.SourcePort != 0x1234 || dgram.DestinationPort != 0x5678 || string(dgram.Data) != "abc" {
		t.Fatalf("ParseDGRAM() = %+v, %v", dgram, err)
	}
}

func TestBuildRejectsInvalidSourceLengths(t *testing.T) {
	_, err := wire.BuildPacket(wire.PacketInput{Header: wire.Header{HopLimit: 64}, SourceLOC: make([]byte, 15), DestinationLOC: make([]byte, 16)}, wire.MaxPacketSize)
	if !errors.Is(err, wire.ErrLengthOverflow) {
		t.Fatalf("BuildPacket() error = %v, want ErrLengthOverflow", err)
	}
}

func TestInvalidBindingBudget(t *testing.T) {
	_, err := wire.Parse(make([]byte, wire.HeaderSize), wire.HeaderSize-1)
	if got := wire.ErrorCategory(err); got != wire.ErrBindingBudget {
		t.Fatalf("Parse() category = %q, want %q", got, wire.ErrBindingBudget)
	}
}

func TestCanonicalSessionAssociatedData(t *testing.T) {
	header := make([]byte, wire.HeaderSize)
	header[5] = 64
	canonical, err := wire.CanonicalSessionAssociatedData(header)
	if err != nil {
		t.Fatal(err)
	}
	if canonical[5] != 0 || header[5] != 64 {
		t.Fatalf("canonical hop=%d original hop=%d", canonical[5], header[5])
	}
}
