package arp

import (
	"bytes"
	"testing"

	"github.com/utkarsh5026/net/pkg/commons"
)

func TestOperationString(t *testing.T) {
	tests := []struct {
		name string
		op   Operation
		want string
	}{
		{"Request", OperationRequest, "Request"},
		{"Reply", OperationReply, "Reply"},
		{"Unknown", Operation(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.op.String(); got != tt.want {
				t.Errorf("Operation.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    *Packet
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid ARP request",
			data: []byte{
				0x00, 0x01, // Hardware Type: Ethernet (1)
				0x08, 0x00, // Protocol Type: IPv4 (0x0800)
				0x06,       // Hardware Length: 6
				0x04,       // Protocol Length: 4
				0x00, 0x01, // Operation: Request (1)
				0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Sender MAC
				0xc0, 0xa8, 0x01, 0x02, // Sender IP: 192.168.1.2
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
				0xc0, 0xa8, 0x01, 0x01, // Target IP: 192.168.1.1
			},
			want: &Packet{
				HardwareType:   HardwareTypeEthernet,
				ProtocolType:   ProtocolTypeIPv4,
				HardwareLength: 6,
				ProtocolLength: 4,
				Operation:      OperationRequest,
				SenderMAC:      commons.MACAddress{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
				SenderIP:       commons.IPv4Address{192, 168, 1, 2},
				TargetMAC:      commons.MACAddress{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				TargetIP:       commons.IPv4Address{192, 168, 1, 1},
			},
			wantErr: false,
		},
		{
			name: "valid ARP reply",
			data: []byte{
				0x00, 0x01, // Hardware Type: Ethernet (1)
				0x08, 0x00, // Protocol Type: IPv4 (0x0800)
				0x06,       // Hardware Length: 6
				0x04,       // Protocol Length: 4
				0x00, 0x02, // Operation: Reply (2)
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // Sender MAC
				0xc0, 0xa8, 0x01, 0x01, // Sender IP: 192.168.1.1
				0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Target MAC
				0xc0, 0xa8, 0x01, 0x02, // Target IP: 192.168.1.2
			},
			want: &Packet{
				HardwareType:   HardwareTypeEthernet,
				ProtocolType:   ProtocolTypeIPv4,
				HardwareLength: 6,
				ProtocolLength: 4,
				Operation:      OperationReply,
				SenderMAC:      commons.MACAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
				SenderIP:       commons.IPv4Address{192, 168, 1, 1},
				TargetMAC:      commons.MACAddress{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
				TargetIP:       commons.IPv4Address{192, 168, 1, 2},
			},
			wantErr: false,
		},
		{
			name:    "packet too short",
			data:    []byte{0x00, 0x01, 0x08, 0x00}, // Only 4 bytes
			wantErr: true,
			errMsg:  "ARP packet too short",
		},
		{
			name: "unsupported hardware type",
			data: []byte{
				0x00, 0x06, // Hardware Type: 6 (not Ethernet)
				0x08, 0x00, // Protocol Type: IPv4
				0x06, 0x04, // Lengths
				0x00, 0x01, // Operation
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sender MAC
				0x00, 0x00, 0x00, 0x00, // Sender IP
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
				0x00, 0x00, 0x00, 0x00, // Target IP
			},
			wantErr: true,
			errMsg:  "unsupported hardware type",
		},
		{
			name: "unsupported protocol type",
			data: []byte{
				0x00, 0x01, // Hardware Type: Ethernet
				0x86, 0xdd, // Protocol Type: IPv6 (0x86dd)
				0x06, 0x04, // Lengths
				0x00, 0x01, // Operation
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sender MAC
				0x00, 0x00, 0x00, 0x00, // Sender IP
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
				0x00, 0x00, 0x00, 0x00, // Target IP
			},
			wantErr: true,
			errMsg:  "unsupported protocol type",
		},
		{
			name: "invalid hardware length",
			data: []byte{
				0x00, 0x01, // Hardware Type: Ethernet
				0x08, 0x00, // Protocol Type: IPv4
				0x08,       // Hardware Length: 8 (invalid)
				0x04,       // Protocol Length: 4
				0x00, 0x01, // Operation
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sender MAC
				0x00, 0x00, 0x00, 0x00, // Sender IP
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
				0x00, 0x00, 0x00, 0x00, // Target IP
			},
			wantErr: true,
			errMsg:  "invalid hardware address length",
		},
		{
			name: "invalid protocol length",
			data: []byte{
				0x00, 0x01, // Hardware Type: Ethernet
				0x08, 0x00, // Protocol Type: IPv4
				0x06,       // Hardware Length: 6
				0x06,       // Protocol Length: 6 (invalid)
				0x00, 0x01, // Operation
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sender MAC
				0x00, 0x00, 0x00, 0x00, // Sender IP
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
				0x00, 0x00, 0x00, 0x00, // Target IP
			},
			wantErr: true,
			errMsg:  "invalid protocol address length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Parse() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Parse() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Errorf("Parse() unexpected error: %v", err)
				return
			}
			if !packetsEqual(got, tt.want) {
				t.Errorf("Parse() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSerialize(t *testing.T) {
	packet := &Packet{
		HardwareType:   HardwareTypeEthernet,
		ProtocolType:   ProtocolTypeIPv4,
		HardwareLength: 6,
		ProtocolLength: 4,
		Operation:      OperationRequest,
		SenderMAC:      commons.MACAddress{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		SenderIP:       commons.IPv4Address{192, 168, 1, 2},
		TargetMAC:      commons.MACAddress{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		TargetIP:       commons.IPv4Address{192, 168, 1, 1},
	}

	expected := []byte{
		0x00, 0x01, // Hardware Type: Ethernet (1)
		0x08, 0x00, // Protocol Type: IPv4 (0x0800)
		0x06,       // Hardware Length: 6
		0x04,       // Protocol Length: 4
		0x00, 0x01, // Operation: Request (1)
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Sender MAC
		0xc0, 0xa8, 0x01, 0x02, // Sender IP: 192.168.1.2
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
		0xc0, 0xa8, 0x01, 0x01, // Target IP: 192.168.1.1
	}

	got := packet.Serialize()
	if !bytes.Equal(got, expected) {
		t.Errorf("Serialize() = %v, want %v", got, expected)
	}

	if len(got) != PacketSize {
		t.Errorf("Serialize() length = %d, want %d", len(got), PacketSize)
	}
}

func TestParseSerializeRoundTrip(t *testing.T) {
	original := &Packet{
		HardwareType:   HardwareTypeEthernet,
		ProtocolType:   ProtocolTypeIPv4,
		HardwareLength: 6,
		ProtocolLength: 4,
		Operation:      OperationReply,
		SenderMAC:      commons.MACAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		SenderIP:       commons.IPv4Address{10, 0, 0, 1},
		TargetMAC:      commons.MACAddress{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		TargetIP:       commons.IPv4Address{10, 0, 0, 2},
	}

	serialized := original.Serialize()
	parsed, err := Parse(serialized)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if !packetsEqual(parsed, original) {
		t.Errorf("Round trip failed: got %+v, want %+v", parsed, original)
	}
}

func TestPacketString(t *testing.T) {
	packet := &Packet{
		HardwareType:   HardwareTypeEthernet,
		ProtocolType:   ProtocolTypeIPv4,
		HardwareLength: 6,
		ProtocolLength: 4,
		Operation:      OperationRequest,
		SenderMAC:      commons.MACAddress{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		SenderIP:       commons.IPv4Address{192, 168, 1, 2},
		TargetMAC:      commons.MACAddress{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		TargetIP:       commons.IPv4Address{192, 168, 1, 1},
	}

	got := packet.String()
	if got == "" {
		t.Error("String() returned empty string")
	}

	// Check that the string contains key information
	if !contains(got, "Request") {
		t.Errorf("String() = %v, want to contain 'Request'", got)
	}
}

func TestIsRequest(t *testing.T) {
	tests := []struct {
		name string
		op   Operation
		want bool
	}{
		{"request packet", OperationRequest, true},
		{"reply packet", OperationReply, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Packet{Operation: tt.op}
			if got := p.IsRequest(); got != tt.want {
				t.Errorf("IsRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsReply(t *testing.T) {
	tests := []struct {
		name string
		op   Operation
		want bool
	}{
		{"reply packet", OperationReply, true},
		{"request packet", OperationRequest, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Packet{Operation: tt.op}
			if got := p.IsReply(); got != tt.want {
				t.Errorf("IsReply() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRequest(t *testing.T) {
	senderMAC := commons.MACAddress{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	senderIP := commons.IPv4Address{192, 168, 1, 2}
	targetIP := commons.IPv4Address{192, 168, 1, 1}

	packet := NewRequest(senderMAC, senderIP, targetIP)

	if packet.HardwareType != HardwareTypeEthernet {
		t.Errorf("HardwareType = %d, want %d", packet.HardwareType, HardwareTypeEthernet)
	}
	if packet.ProtocolType != ProtocolTypeIPv4 {
		t.Errorf("ProtocolType = 0x%04x, want 0x%04x", packet.ProtocolType, ProtocolTypeIPv4)
	}
	if packet.HardwareLength != 6 {
		t.Errorf("HardwareLength = %d, want 6", packet.HardwareLength)
	}
	if packet.ProtocolLength != 4 {
		t.Errorf("ProtocolLength = %d, want 4", packet.ProtocolLength)
	}
	if packet.Operation != OperationRequest {
		t.Errorf("Operation = %v, want %v", packet.Operation, OperationRequest)
	}
	if packet.SenderMAC != senderMAC {
		t.Errorf("SenderMAC = %v, want %v", packet.SenderMAC, senderMAC)
	}
	if packet.SenderIP != senderIP {
		t.Errorf("SenderIP = %v, want %v", packet.SenderIP, senderIP)
	}
	if packet.TargetIP != targetIP {
		t.Errorf("TargetIP = %v, want %v", packet.TargetIP, targetIP)
	}
	// Target MAC should be zero (unknown)
	zeroMAC := commons.MACAddress{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if packet.TargetMAC != zeroMAC {
		t.Errorf("TargetMAC = %v, want %v (zero MAC)", packet.TargetMAC, zeroMAC)
	}

	if !packet.IsRequest() {
		t.Error("NewRequest() packet should be a request")
	}
	if packet.IsReply() {
		t.Error("NewRequest() packet should not be a reply")
	}
}

// Helper functions

func packetsEqual(a, b *Packet) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.HardwareType == b.HardwareType &&
		a.ProtocolType == b.ProtocolType &&
		a.HardwareLength == b.HardwareLength &&
		a.ProtocolLength == b.ProtocolLength &&
		a.Operation == b.Operation &&
		a.SenderMAC == b.SenderMAC &&
		a.SenderIP == b.SenderIP &&
		a.TargetMAC == b.TargetMAC &&
		a.TargetIP == b.TargetIP
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && indexOf(s, substr) >= 0))
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
