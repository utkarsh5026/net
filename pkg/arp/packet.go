// ARP packet format (RFC 826):
//
//	0                   1                   2                   3
//	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        Hardware Type          |        Protocol Type          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | HW Addr Len | Proto Addr Len|          Operation              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Sender Hardware Address (6 bytes)             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Sender Protocol Address (4 bytes)             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Target Hardware Address (6 bytes)             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Target Protocol Address (4 bytes)             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
package arp

import (
	"encoding/binary"
	"fmt"

	"github.com/utkarsh5026/net/pkg/commons"
)

const (
	// PacketSize is the size of an ARP packet for Ethernet/IPv4 (28 bytes).
	PacketSize = 28

	// HardwareTypeEthernet represents Ethernet hardware type.
	HardwareTypeEthernet = 1

	// ProtocolTypeIPv4 represents IPv4 protocol type (same as EtherType).
	ProtocolTypeIPv4 = 0x0800
)

// Operation represents the ARP operation type.
type Operation uint16

const (
	// OperationRequest is an ARP request (who has this IP?).
	OperationRequest Operation = 1

	// OperationReply is an ARP reply (I have this IP, here's my MAC).
	OperationReply Operation = 2
)

func (o Operation) String() string {
	switch o {
	case OperationRequest:
		return "Request"
	case OperationReply:
		return "Reply"
	default:
		return fmt.Sprintf("Unknown(%d)", o)
	}
}

type Packet struct {
	HardwareType         uint16              // Hardware type (1 for Ethernet)
	ProtocolType         uint16              // Protocol type (0x0800 for IPv4)
	HardwareLength       uint8               // Hardware address length (6 for Ethernet)
	ProtocolLength       uint8               // Protocol address length (4 for IPv4)
	Operation            Operation           // ARP operation (request or reply)
	SenderMAC, TargetMAC commons.MACAddress  // Sender and target MAC addresses
	SenderIP, TargetIP   commons.IPv4Address // Sender and target IP addresses
}

func Parse(data []byte) (*Packet, error) {
	if len(data) < PacketSize {
		return nil, fmt.Errorf("ARP packet too short: %d bytes (expected %d)", len(data), PacketSize)
	}

	p := &Packet{}
	p.HardwareType = binary.BigEndian.Uint16(data[0:2])
	p.ProtocolType = binary.BigEndian.Uint16(data[2:4])
	p.HardwareLength = data[4]
	p.ProtocolLength = data[5]
	p.Operation = Operation(binary.BigEndian.Uint16(data[6:8]))

	if p.HardwareType != HardwareTypeEthernet {
		return nil, fmt.Errorf("unsupported hardware type: %d", p.HardwareType)
	}
	if p.ProtocolType != ProtocolTypeIPv4 {
		return nil, fmt.Errorf("unsupported protocol type: 0x%04x", p.ProtocolType)
	}
	if p.HardwareLength != 6 {
		return nil, fmt.Errorf("invalid hardware address length: %d", p.HardwareLength)
	}
	if p.ProtocolLength != 4 {
		return nil, fmt.Errorf("invalid protocol address length: %d", p.ProtocolLength)
	}

	copy(p.SenderMAC[:], data[8:14])
	copy(p.SenderIP[:], data[14:18])
	copy(p.TargetMAC[:], data[18:24])
	copy(p.TargetIP[:], data[24:28])

	return p, nil
}

func (p *Packet) Serialize() []byte {
	data := make([]byte, PacketSize)

	binary.BigEndian.PutUint16(data[0:2], p.HardwareType)
	binary.BigEndian.PutUint16(data[2:4], p.ProtocolType)
	data[4] = p.HardwareLength
	data[5] = p.ProtocolLength
	binary.BigEndian.PutUint16(data[6:8], uint16(p.Operation))

	// Write addresses
	copy(data[8:14], p.SenderMAC[:])
	copy(data[14:18], p.SenderIP[:])
	copy(data[18:24], p.TargetMAC[:])
	copy(data[24:28], p.TargetIP[:])

	return data
}

func (p *Packet) String() string {
	return fmt.Sprintf("ARP{Op=%s, Sender=%s(%s), Target=%s(%s)}",
		p.Operation,
		p.SenderIP,
		p.SenderMAC,
		p.TargetIP,
		p.TargetMAC,
	)
}

// IsRequest returns true if this is an ARP request.
func (p *Packet) IsRequest() bool {
	return p.Operation == OperationRequest
}

// IsReply returns true if this is an ARP reply.
func (p *Packet) IsReply() bool {
	return p.Operation == OperationReply
}

// NewRequest creates a new ARP request packet.
// This is used to ask "who has targetIP? Tell senderIP".
func NewRequest(senderMAC commons.MACAddress, senderIP, targetIP commons.IPv4Address) *Packet {
	return newBasePacket(senderMAC, commons.UnknownMAC, senderIP, targetIP, OperationRequest)
}

// NewReply creates a new ARP reply packet.
// This is used to respond "targetIP is at targetMAC".
func NewReply(senderMAC, targetMAC commons.MACAddress, senderIP, targetIP commons.IPv4Address) *Packet {
	return newBasePacket(senderMAC, targetMAC, senderIP, targetIP, OperationReply)
}

// newBasePacket is a helper to create a base ARP packet with common fields.
// It sets the hardware/protocol types and lengths.
func newBasePacket(senderMAC, targetMAC commons.MACAddress, senderIP, targetIP commons.IPv4Address, op Operation) *Packet {
	return &Packet{
		HardwareType:   HardwareTypeEthernet,
		ProtocolType:   ProtocolTypeIPv4,
		HardwareLength: commons.MACLength,
		ProtocolLength: commons.IPv4Length,
		Operation:      op,
		SenderMAC:      senderMAC,
		SenderIP:       senderIP,
		TargetMAC:      targetMAC,
		TargetIP:       targetIP,
	}
}
