package ethernet

import (
	"bytes"
	"testing"

	"github.com/utkarsh5026/net/pkg/commons"
)

func serializeFrame(frame *Frame, t *testing.T) []byte {
	var buf bytes.Buffer

	if err := frame.Serialize(&buf); err != nil {
		t.Fatalf("Serialize() error = %v", err)
	}

	return buf.Bytes()
}

func TestParse(t *testing.T) {
	// Create a test Ethernet frame
	data := []byte{
		// Destination MAC (6 bytes)
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		// Source MAC (6 bytes)
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		// EtherType (2 bytes) - IPv4
		0x08, 0x00,
		// Payload
		0x45, 0x00, 0x00, 0x54,
	}

	frame, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// Check destination MAC
	expectedDst := commons.BroadCastMAC
	if frame.Destination != expectedDst {
		t.Errorf("Destination = %v, want %v", frame.Destination, expectedDst)
	}

	// Check source MAC
	expectedSrc := commons.MACAddress{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	if frame.Source != expectedSrc {
		t.Errorf("Source = %v, want %v", frame.Source, expectedSrc)
	}

	// Check EtherType
	if frame.EtherType != EtherTypeIPv4 {
		t.Errorf("EtherType = %v, want %v", frame.EtherType, EtherTypeIPv4)
	}

	// Check payload
	expectedPayload := []byte{0x45, 0x00, 0x00, 0x54}
	if !bytes.Equal(frame.Payload, expectedPayload) {
		t.Errorf("Payload = %v, want %v", frame.Payload, expectedPayload)
	}
}

func TestParseTooShort(t *testing.T) {
	// Frame too short (less than 14 bytes)
	data := []byte{0x00, 0x11, 0x22}

	_, err := Parse(data)
	if err == nil {
		t.Error("Parse() should return error for too short frame")
	}
}

func TestSerialize(t *testing.T) {
	dst := commons.MACAddress{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	src := commons.MACAddress{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	payload := []byte{0x45, 0x00, 0x00, 0x54, 0x12, 0x34}

	frame := NewFrame(dst, src, EtherTypeIPv4, payload)
	data := serializeFrame(frame, t)

	// Check minimum size (header + minimum payload)
	if len(data) < HeaderSize+MinPayloadSize {
		t.Errorf("Serialized frame size = %d, want at least %d", len(data), HeaderSize+MinPayloadSize)
	}

	// Check destination MAC
	for i := range 6 {
		if data[i] != dst[i] {
			t.Errorf("Destination byte %d = 0x%02X, want 0x%02X", i, data[i], dst[i])
		}
	}

	// Check source MAC
	for i := range 6 {
		if data[6+i] != src[i] {
			t.Errorf("Source byte %d = 0x%02X, want 0x%02X", i, data[6+i], src[i])
		}
	}

	// Check EtherType
	if data[12] != 0x08 || data[13] != 0x00 {
		t.Errorf("EtherType = 0x%02X%02X, want 0x0800", data[12], data[13])
	}

	// Check payload
	for i := range payload {
		if data[HeaderSize+i] != payload[i] {
			t.Errorf("Payload byte %d = 0x%02X, want 0x%02X", i, data[HeaderSize+i], payload[i])
		}
	}
}

func TestSerializeWithPadding(t *testing.T) {
	dst := commons.MACAddress{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	src := commons.MACAddress{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}
	payload := []byte{0x01, 0x02} // Very small payload

	frame := NewFrame(dst, src, EtherTypeARP, payload)

	data := serializeFrame(frame, t)

	// Should be padded to minimum size
	expectedSize := HeaderSize + MinPayloadSize
	if len(data) != expectedSize {
		t.Errorf("Serialized frame size = %d, want %d", len(data), expectedSize)
	}

	// Verify padding is zeros
	for i := HeaderSize + len(payload); i < len(data); i++ {
		if data[i] != 0 {
			t.Errorf("Padding byte %d = 0x%02X, want 0x00", i, data[i])
		}
	}
}

func TestParseSerializeRoundtrip(t *testing.T) {
	dst := commons.MACAddress{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	src := commons.MACAddress{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}
	payload := make([]byte, 100) // Large enough to not need padding
	for i := range payload {
		payload[i] = byte(i)
	}

	// Create frame
	original := NewFrame(dst, src, EtherTypeIPv4, payload)

	var w bytes.Buffer
	err := original.Serialize(&w)
	if err != nil {
		t.Fatalf("Serialize() error = %v", err)
	}

	data := w.Bytes()

	// Parse back
	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// Compare
	if parsed.Destination != original.Destination {
		t.Errorf("Destination mismatch: %v != %v", parsed.Destination, original.Destination)
	}
	if parsed.Source != original.Source {
		t.Errorf("Source mismatch: %v != %v", parsed.Source, original.Source)
	}
	if parsed.EtherType != original.EtherType {
		t.Errorf("EtherType mismatch: %v != %v", parsed.EtherType, original.EtherType)
	}
	if !bytes.Equal(parsed.Payload, original.Payload) {
		t.Error("Payload mismatch")
	}
}

func TestFrameSize(t *testing.T) {
	tests := []struct {
		name        string
		payloadSize int
		wantSize    int
	}{
		{
			name:        "small payload (needs padding)",
			payloadSize: 10,
			wantSize:    HeaderSize + MinPayloadSize,
		},
		{
			name:        "minimum payload",
			payloadSize: MinPayloadSize,
			wantSize:    HeaderSize + MinPayloadSize,
		},
		{
			name:        "large payload",
			payloadSize: 1000,
			wantSize:    HeaderSize + 1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := make([]byte, tt.payloadSize)
			frame := NewFrame(
				commons.MACAddress{},
				commons.MACAddress{},
				EtherTypeIPv4,
				payload,
			)

			if frame.Size() != tt.wantSize {
				t.Errorf("Frame.Size() = %d, want %d", frame.Size(), tt.wantSize)
			}
		})
	}
}

func TestFrameIsBroadcast(t *testing.T) {
	frame := NewFrame(
		commons.BroadCastMAC,
		commons.MACAddress{},
		EtherTypeIPv4,
		nil,
	)

	if !frame.IsBroadcast() {
		t.Error("Frame.IsBroadcast() = false, want true")
	}
}

func TestFrameIsMulticast(t *testing.T) {
	multicastMAC := commons.MACAddress{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}
	frame := NewFrame(
		multicastMAC,
		commons.MACAddress{},
		EtherTypeIPv4,
		nil,
	)

	if !frame.IsMulticast() {
		t.Error("Frame.IsMulticast() = false, want true")
	}
}

func TestFrameIsUnicast(t *testing.T) {
	unicastMAC := commons.MACAddress{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	frame := NewFrame(
		unicastMAC,
		commons.MACAddress{},
		EtherTypeIPv4,
		nil,
	)

	if !frame.IsUnicast() {
		t.Error("Frame.IsUnicast() = false, want true")
	}

	if frame.IsBroadcast() {
		t.Error("Frame.IsBroadcast() = true, want false")
	}

	if frame.IsMulticast() {
		t.Error("Frame.IsMulticast() = true, want false")
	}
}

func TestFrameString(t *testing.T) {
	dst := commons.MACAddress{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	src := commons.MACAddress{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}
	payload := []byte{0x01, 0x02, 0x03}

	frame := NewFrame(dst, src, EtherTypeIPv4, payload)
	str := frame.String()

	// Just verify it produces a non-empty string
	if len(str) == 0 {
		t.Error("Frame.String() returned empty string")
	}
}
