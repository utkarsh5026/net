// Ethernet frame format (IEEE 802.3):
// +-------------------+-------------------+----------+---------+-----+
// | Destination (6B)  | Source (6B)       | Type (2B)| Payload | FCS |
// +-------------------+-------------------+----------+---------+-----+
//
// Minimum frame size: 64 bytes (including FCS)
// Maximum frame size: 1518 bytes (including FCS)
package ethernet

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/utkarsh5026/net/pkg/commons"
)

const (
	// HeaderSize is the size of an Ethernet header (14 bytes).
	HeaderSize = 14

	// MinFrameSize is the minimum Ethernet frame size including FCS (64 bytes).
	MinFrameSize = 64

	// MaxFrameSize is the maximum Ethernet frame size including FCS (1518 bytes).
	MaxFrameSize = 1518

	// MinPayloadSize is the minimum payload size (46 bytes).
	MinPayloadSize = 46

	// MaxPayloadSize is the maximum payload size (1500 bytes, MTU).
	MaxPayloadSize = 1500
)

// EtherType represents the protocol type in an Ethernet frame.
type EtherType uint16

// Common EtherType values.
const (
	EtherTypeIPv4 EtherType = 0x0800 // Internet Protocol version 4
	EtherTypeARP  EtherType = 0x0806 // Address Resolution Protocol
	EtherTypeIPv6 EtherType = 0x86DD // Internet Protocol version 6
)

// String returns a human-readable name for the EtherType.
func (et EtherType) String() string {
	switch et {
	case EtherTypeIPv4:
		return "IPv4"
	case EtherTypeARP:
		return "ARP"
	case EtherTypeIPv6:
		return "IPv6"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", uint16(et))
	}
}

// Frame represents an Ethernet II frame.
type Frame struct {
	Destination, Source commons.MACAddress
	EtherType           EtherType
	Payload             []byte
}

// NewFrame creates a new Ethernet frame.
func NewFrame(dst, src commons.MACAddress, etherType EtherType, payload []byte) *Frame {
	return &Frame{
		Destination: dst,
		Source:      src,
		EtherType:   etherType,
		Payload:     payload,
	}
}

// Parse parses raw bytes into an Ethernet frame.
// Returns an error if the data is too short to be a valid frame.
func Parse(data []byte) (*Frame, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("data too short to be a valid Ethernet frame")
	}

	macLen := commons.MACLength

	var frame = &Frame{}
	copy(frame.Destination[:], data[0:macLen])
	copy(frame.Source[:], data[macLen:2*macLen])
	frame.EtherType = EtherType(binary.BigEndian.Uint16(data[12:14]))
	frame.Payload = data[HeaderSize:]
	return frame, nil
}

// Serialize writes the Ethernet frame to the given writer.
// Returns an error if the payload size exceeds the maximum allowed size.
func (f *Frame) Serialize(w io.Writer) error {
	if len(f.Payload) > MaxPayloadSize {
		return fmt.Errorf("payload size must not exceed %d bytes", MaxPayloadSize)
	}

	write := func(data any) error {
		return binary.Write(w, binary.BigEndian, data)
	}

	if err := write(f.Destination); err != nil {
		return err
	}

	if err := write(f.Source); err != nil {
		return err
	}

	if err := write(uint16(f.EtherType)); err != nil {
		return err
	}

	if _, err := w.Write(f.Payload); err != nil {
		return err
	}

	if len(f.Payload) < MinPayloadSize {
		padding := make([]byte, MinPayloadSize-len(f.Payload))
		if _, err := w.Write(padding); err != nil {
			return err
		}
	}

	return nil
}

// IsBroadcast returns true if this is a broadcast frame.
func (f *Frame) IsBroadcast() bool {
	return f.Destination.IsBroadcast()
}

// IsMulticast returns true if this is a multicast frame.
func (f *Frame) IsMulticast() bool {
	return f.Destination.IsMulticast()
}

// IsUnicast returns true if this is a unicast frame.
func (f *Frame) IsUnicast() bool {
	return !f.IsBroadcast() && !f.IsMulticast()
}

func (f *Frame) Size() int {
	size := HeaderSize + len(f.Payload)
	if len(f.Payload) < MinPayloadSize {
		size = HeaderSize + MinPayloadSize
	}
	return size
}

func (f *Frame) String() string {
	return fmt.Sprintf("Ethernet{Dst=%s, Src=%s, Type=%s, PayloadLen=%d}",
		f.Destination, f.Source, f.EtherType, len(f.Payload))
}
