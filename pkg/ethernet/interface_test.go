//go:build linux
// +build linux

package ethernet

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/utkarsh5026/net/pkg/commons"
)

// isRoot checks if the test is running with root privileges
func isRoot() bool {
	return os.Geteuid() == 0
}

// requiresRoot skips the test if not running as root
func requiresRoot(t *testing.T) {
	if !isRoot() {
		t.Skip("This test requires root privileges")
	}
}

func TestHtons(t *testing.T) {
	tests := []struct {
		name     string
		input    uint16
		expected uint16
	}{
		{
			name:     "zero value",
			input:    0x0000,
			expected: 0x0000,
		},
		{
			name:     "swap bytes",
			input:    0x1234,
			expected: 0x3412,
		},
		{
			name:     "all ones",
			input:    0xFFFF,
			expected: 0xFFFF,
		},
		{
			name:     "ETH_P_ALL",
			input:    0x0003,
			expected: 0x0300,
		},
		{
			name:     "single byte high",
			input:    0x0100,
			expected: 0x0001,
		},
		{
			name:     "single byte low",
			input:    0x0001,
			expected: 0x0100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := htons(tt.input)
			if result != tt.expected {
				t.Errorf("htons(0x%04x) = 0x%04x, want 0x%04x", tt.input, result, tt.expected)
			}
		})
	}
}

func TestListInterfaces(t *testing.T) {
	interfaces, err := ListInterfaces()
	if err != nil {
		t.Fatalf("ListInterfaces() failed: %v", err)
	}

	// We should have at least some interfaces on a Linux system
	// Even if they're down, the system should have something
	if len(interfaces) == 0 {
		t.Error("Expected at least some interfaces")
	}

	// Verify no loopback interfaces are in the list
	for _, iface := range interfaces {
		if strings.Contains(strings.ToLower(iface), "lo") {
			t.Errorf("ListInterfaces() should not include loopback interface: %s", iface)
		}
	}
}

func TestGetInterfaceInfo(t *testing.T) {
	tests := []struct {
		name      string
		ifname    string
		wantError bool
	}{
		{
			name:      "nonexistent interface",
			ifname:    "nonexistent12345",
			wantError: true,
		},
		{
			name:      "empty interface name",
			ifname:    "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := GetInterfaceInfo(tt.ifname)
			if tt.wantError {
				if err == nil {
					t.Errorf("GetInterfaceInfo(%q) expected error, got nil", tt.ifname)
				}
				return
			}

			if err != nil {
				t.Errorf("GetInterfaceInfo(%q) unexpected error: %v", tt.ifname, err)
				return
			}

			// Check that the output contains expected fields
			expectedFields := []string{"Name:", "Index:", "MTU:", "HardwareAddr:", "Flags:"}
			for _, field := range expectedFields {
				if !strings.Contains(info, field) {
					t.Errorf("GetInterfaceInfo(%q) output missing field %q", tt.ifname, field)
				}
			}
		})
	}

	// Test with loopback interface (should always exist)
	t.Run("loopback interface", func(t *testing.T) {
		info, err := GetInterfaceInfo("lo")
		if err != nil {
			t.Skipf("Loopback interface not available: %v", err)
		}

		if !strings.Contains(info, "Name: lo") {
			t.Error("Expected interface name 'lo' in output")
		}
	})
}

func TestOpenInterface(t *testing.T) {
	requiresRoot(t)

	interfaces, err := ListInterfaces()
	if err != nil {
		t.Fatalf("Failed to list interfaces: %v", err)
	}

	if len(interfaces) == 0 {
		t.Skip("No available interfaces to test with")
	}

	// Test with the first available interface
	ifname := interfaces[0]

	t.Run("valid interface", func(t *testing.T) {
		iface, err := OpenInterface(ifname)
		if err != nil {
			t.Fatalf("OpenInterface(%q) failed: %v", ifname, err)
		}
		defer iface.Close()

		if iface == nil {
			t.Fatal("OpenInterface() returned nil interface")
		}

		if iface.Name() != ifname {
			t.Errorf("Interface name = %q, want %q", iface.Name(), ifname)
		}

		if iface.Index() <= 0 {
			t.Errorf("Interface index = %d, want > 0", iface.Index())
		}

		mac := iface.MACAddress()
		if mac == (commons.MACAddress{}) {
			t.Error("Interface has zero MAC address")
		}
	})

	t.Run("nonexistent interface", func(t *testing.T) {
		iface, err := OpenInterface("nonexistent12345")
		if err == nil {
			if iface != nil {
				iface.Close()
			}
			t.Error("OpenInterface() with invalid interface expected error, got nil")
		}
	})

	t.Run("empty interface name", func(t *testing.T) {
		iface, err := OpenInterface("")
		if err == nil {
			if iface != nil {
				iface.Close()
			}
			t.Error("OpenInterface() with empty name expected error, got nil")
		}
	})
}

func TestInterface_Getters(t *testing.T) {
	requiresRoot(t)

	interfaces, err := ListInterfaces()
	if err != nil || len(interfaces) == 0 {
		t.Skip("No available interfaces to test with")
	}

	iface, err := OpenInterface(interfaces[0])
	if err != nil {
		t.Fatalf("OpenInterface() failed: %v", err)
	}
	defer iface.Close()

	t.Run("Name", func(t *testing.T) {
		name := iface.Name()
		if name != interfaces[0] {
			t.Errorf("Name() = %q, want %q", name, interfaces[0])
		}
	})

	t.Run("Index", func(t *testing.T) {
		index := iface.Index()
		if index <= 0 {
			t.Errorf("Index() = %d, want > 0", index)
		}
	})

	t.Run("MACAddress", func(t *testing.T) {
		mac := iface.MACAddress()
		if mac == (commons.MACAddress{}) {
			t.Error("MACAddress() returned zero address")
		}

		// Check that it's a valid 6-byte MAC
		macStr := mac.String()
		parts := strings.Split(macStr, ":")
		if len(parts) != 6 {
			t.Errorf("MACAddress() returned invalid format: %s", macStr)
		}
	})
}

func TestInterface_Close(t *testing.T) {
	requiresRoot(t)

	interfaces, err := ListInterfaces()
	if err != nil || len(interfaces) == 0 {
		t.Skip("No available interfaces to test with")
	}

	iface, err := OpenInterface(interfaces[0])
	if err != nil {
		t.Fatalf("OpenInterface() failed: %v", err)
	}

	// Close once
	err = iface.Close()
	if err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	// Closing again should be safe (double close)
	err = iface.Close()
	if err != nil {
		t.Errorf("Second Close() failed: %v", err)
	}
}

func TestInterface_WriteFrame(t *testing.T) {
	requiresRoot(t)

	interfaces, err := ListInterfaces()
	if err != nil || len(interfaces) == 0 {
		t.Skip("No available interfaces to test with")
	}

	iface, err := OpenInterface(interfaces[0])
	if err != nil {
		t.Fatalf("OpenInterface() failed: %v", err)
	}
	defer iface.Close()

	// Create a test frame
	srcMAC := iface.MACAddress()
	dstMAC := commons.MACAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	payload := []byte("test payload")

	frame := NewFrame(dstMAC, srcMAC, EtherTypeIPv4, payload)

	t.Run("valid frame", func(t *testing.T) {
		err := iface.WriteFrame(frame)
		if err != nil {
			t.Errorf("WriteFrame() failed: %v", err)
		}
	})

	t.Run("frame with large payload", func(t *testing.T) {
		largePayload := make([]byte, MaxPayloadSize)
		largeFrame := NewFrame(dstMAC, srcMAC, EtherTypeIPv4, largePayload)

		err := iface.WriteFrame(largeFrame)
		if err != nil {
			t.Errorf("WriteFrame() with max payload failed: %v", err)
		}
	})

	t.Run("frame with oversized payload", func(t *testing.T) {
		oversizedPayload := make([]byte, MaxPayloadSize+1)
		oversizedFrame := NewFrame(dstMAC, srcMAC, EtherTypeIPv4, oversizedPayload)

		err := iface.WriteFrame(oversizedFrame)
		if err == nil {
			t.Error("WriteFrame() with oversized payload expected error, got nil")
		}
	})

	t.Run("broadcast frame", func(t *testing.T) {
		broadcastFrame := NewFrame(commons.BroadCastMAC, srcMAC, EtherTypeARP, payload)
		err := iface.WriteFrame(broadcastFrame)
		if err != nil {
			t.Errorf("WriteFrame() with broadcast address failed: %v", err)
		}
	})
}

func TestInterface_ReadFrame(t *testing.T) {
	requiresRoot(t)

	interfaces, err := ListInterfaces()
	if err != nil || len(interfaces) == 0 {
		t.Skip("No available interfaces to test with")
	}

	iface, err := OpenInterface(interfaces[0])
	if err != nil {
		t.Fatalf("OpenInterface() failed: %v", err)
	}
	defer iface.Close()

	// Note: This test is tricky because we need network traffic to read.
	// In a real environment, we might want to send a frame first, then read it.
	// For now, we'll just test that the method doesn't crash.
	t.Run("read frame timeout", func(t *testing.T) {
		// We can't reliably test this without generating traffic
		// This test would block indefinitely waiting for a frame
		t.Skip("Skipping ReadFrame test - requires active network traffic")
	})
}

func TestInterface_ReadWriteRoundTrip(t *testing.T) {
	requiresRoot(t)

	interfaces, err := ListInterfaces()
	if err != nil || len(interfaces) == 0 {
		t.Skip("No available interfaces to test with")
	}

	// This test requires two interfaces or loopback capability
	// It's complex and may not work in all environments
	t.Skip("Round-trip test requires specific network setup")
}

// TestInterface_SerializeAndWrite tests that frames are properly serialized before writing
func TestInterface_SerializeAndWrite(t *testing.T) {
	requiresRoot(t)

	interfaces, err := ListInterfaces()
	if err != nil || len(interfaces) == 0 {
		t.Skip("No available interfaces to test with")
	}

	iface, err := OpenInterface(interfaces[0])
	if err != nil {
		t.Fatalf("OpenInterface() failed: %v", err)
	}
	defer iface.Close()

	tests := []struct {
		name      string
		frame     *Frame
		wantError bool
	}{
		{
			name: "small payload with padding",
			frame: NewFrame(
				commons.MACAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
				iface.MACAddress(),
				EtherTypeIPv4,
				[]byte{0x01, 0x02, 0x03},
			),
			wantError: false,
		},
		{
			name: "minimum payload",
			frame: NewFrame(
				commons.MACAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
				iface.MACAddress(),
				EtherTypeIPv4,
				make([]byte, MinPayloadSize),
			),
			wantError: false,
		},
		{
			name: "empty payload",
			frame: NewFrame(
				commons.MACAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
				iface.MACAddress(),
				EtherTypeIPv4,
				[]byte{},
			),
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test serialization
			var buf bytes.Buffer
			err := tt.frame.Serialize(&buf)
			if err != nil {
				t.Fatalf("Serialize() failed: %v", err)
			}

			// Test writing
			err = iface.WriteFrame(tt.frame)
			if (err != nil) != tt.wantError {
				t.Errorf("WriteFrame() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestInterface_ClosedSocket tests operations on a closed interface
func TestInterface_ClosedSocket(t *testing.T) {
	requiresRoot(t)

	interfaces, err := ListInterfaces()
	if err != nil || len(interfaces) == 0 {
		t.Skip("No available interfaces to test with")
	}

	iface, err := OpenInterface(interfaces[0])
	if err != nil {
		t.Fatalf("OpenInterface() failed: %v", err)
	}

	// Close the interface
	if err := iface.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	t.Run("write to closed interface", func(t *testing.T) {
		frame := NewFrame(
			commons.MACAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			iface.MACAddress(),
			EtherTypeIPv4,
			[]byte("test"),
		)

		err := iface.WriteFrame(frame)
		if err == nil {
			t.Error("WriteFrame() on closed interface expected error, got nil")
		}
	})

	t.Run("read from closed interface", func(t *testing.T) {
		_, err := iface.ReadFrame()
		if err == nil {
			t.Error("ReadFrame() on closed interface expected error, got nil")
		}
	})

	t.Run("getters on closed interface", func(t *testing.T) {
		// Getters should still work even after close
		if iface.Name() == "" {
			t.Error("Name() returned empty string after close")
		}
		if iface.Index() == 0 {
			t.Error("Index() returned 0 after close")
		}
		if iface.MACAddress() == (commons.MACAddress{}) {
			t.Error("MACAddress() returned zero address after close")
		}
	})
}
