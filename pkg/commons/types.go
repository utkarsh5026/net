package commons

import (
	"bytes"
	"fmt"
	"net"
)

const (
	// IPv6Length defines the number of bytes in an IPv6 address (128 bits).
	IPv6Length = 16

	// IPv4Length defines the number of bytes in an IPv4 address (32 bits).
	IPv4Length = 4

	// MACLength defines the number of bytes in a MAC address (48 bits).
	MACLength = 6
)

var (
	// BroadCastMAC represents the Ethernet broadcast MAC address (FF:FF:FF:FF:FF:FF).
	// It is used to send packets to all devices on the local network segment.
	BroadCastMAC = MACAddress{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	// UnknownMAC represents an uninitialized or unknown MAC address (all bytes set to 0).
	// This can be used as a placeholder when the actual MAC address is not known.
	UnknownMAC = MACAddress{}
)

// MACAddress represents a MAC (Media Access Control) address.
// It is a 6-byte array used to uniquely identify network interfaces.
type MACAddress [6]byte

func (mac MACAddress) String() string {
	var buff bytes.Buffer
	for i, b := range mac {
		if i > 0 {
			_, _ = buff.WriteString(":")
		}
		_, _ = buff.WriteString(hexByte(b))
	}
	return buff.String()
}

func (mac MACAddress) IsBroadcast() bool {
	for _, b := range mac {
		if b != 0xFF {
			return false
		}
	}
	return true
}

func (mac MACAddress) IsMulticast() bool {
	return (mac[0] & 0x01) != 0
}

func (mac MACAddress) IsUnicast() bool {
	return !mac.IsMulticast()
}

func ParseMac(s string) (MACAddress, error) {
	var mac MACAddress
	hw, err := net.ParseMAC(s)
	if err != nil {
		return MACAddress{}, err
	}
	if len(hw) != 6 {
		return MACAddress{}, fmt.Errorf("invalid MAC address length: %d", len(hw))
	}
	copy(mac[:], hw)
	return mac, nil
}

func hexByte(b byte) string {
	const hexChars = "0123456789ABCDEF"
	return string([]byte{hexChars[b>>4], hexChars[b&0x0F]})
}

type IPv4Address [4]byte

func (ip IPv4Address) String() string {
	var buff bytes.Buffer
	for i, b := range ip {
		if i > 0 {
			_, _ = buff.WriteString(".")
		}
		_, _ = buff.WriteString(fmt.Sprintf("%d", b))
	}
	return buff.String()
}

func ParseIPv4(s string) (IPv4Address, error) {
	var ip IPv4Address
	parsedIP := net.ParseIP(s)
	if parsedIP == nil {
		return IPv4Address{}, fmt.Errorf("invalid IP address: %s", s)
	}

	parsedIP = parsedIP.To4()
	if parsedIP == nil {
		return IPv4Address{}, fmt.Errorf("not an IPv4 address: %s", s)
	}
	copy(ip[:], parsedIP)
	return ip, nil
}

type IPv6Address [16]byte

func (ip IPv6Address) String() string {
	var buff bytes.Buffer
	for i := 0; i < 16; i += 2 {
		if i > 0 {
			_, _ = buff.WriteString(":")
		}
		segment := uint16(ip[i])<<8 | uint16(ip[i+1])
		_, _ = buff.WriteString(fmt.Sprintf("%x", segment))
	}
	return buff.String()
}

func ParseIPv6(s string) (IPv6Address, error) {
	var ip IPv6Address
	parsedIP := net.ParseIP(s)

	if parsedIP == nil {
		return IPv6Address{}, fmt.Errorf("invalid IP address: %s", s)
	}

	parsedIP = parsedIP.To16()
	if parsedIP == nil || parsedIP.To4() != nil {
		return IPv6Address{}, fmt.Errorf("not an IPv6 address: %s", s)
	}
	copy(ip[:], parsedIP)
	return ip, nil
}

func (ip IPv6Address) IsLoopback() bool {
	for i := range IPv6Length - 1 {
		if ip[i] != 0 {
			return false
		}
	}
	return ip[15] == 1
}

// Protocol represents common IP protocol numbers.
type Protocol uint8

// Common protocol numbers.
const (
	ProtocolICMP Protocol = 1  // Internet Control Message Protocol
	ProtocolTCP  Protocol = 6  // Transmission Control Protocol
	ProtocolUDP  Protocol = 17 // User Datagram Protocol
)

// String returns a human-readable name for the protocol.
func (p Protocol) String() string {
	switch p {
	case ProtocolICMP:
		return "ICMP"
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(p))
	}
}
