//go:build linux
// +build linux

package ethernet

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/utkarsh5026/net/pkg/commons"
	"golang.org/x/sys/unix"
)

type Interface struct {
	name     string
	fileDesc int
	macAddr  commons.MACAddress
	index    int
}

// OpenInterface opens a network interface for raw packet capture and transmission.
// This requires root/sudo privileges on Linux.
//
// The interface parameter is the name of the network interface (e.g., "eth0", "wlan0").
func OpenInterface(ifname string) (*Interface, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", ifname, err)
	}

	if len(iface.HardwareAddr) != commons.MACLength {
		return nil, fmt.Errorf("interface %s does not have a valid MAC address", ifname)
	}

	var mac commons.MACAddress
	copy(mac[:], iface.HardwareAddr)

	// Create raw socket
	// AF_PACKET: Packet socket for device level access
	// SOCK_RAW: Raw protocol access
	// ETH_P_ALL: Capture all protocols
	fd, err := syscall.Socket(unix.AF_PACKET, syscall.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %w (you may need root/sudo)", err)
	}

	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}

	if err := unix.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to bind raw socket to interface %s: %w", ifname, err)
	}

	return &Interface{
		name:     ifname,
		fileDesc: fd,
		macAddr:  mac,
		index:    iface.Index,
	}, nil
}

// Close closes the network interface.
func (i *Interface) Close() error {
	if i.fileDesc >= 0 {
		return syscall.Close(i.fileDesc)
	}
	return nil
}

// Name returns the name of the network interface.
func (i *Interface) Name() string {
	return i.name
}

// MACAddress returns the MAC address of the network interface.
func (i *Interface) MACAddress() commons.MACAddress {
	return i.macAddr
}

// Index returns the index of the network interface.
func (i *Interface) Index() int {
	return i.index
}

// ReadFrame reads a single Ethernet frame from the network interface.
// It returns the parsed Frame or an error if reading or parsing fails.
func (i *Interface) ReadFrame() (*Frame, error) {
	buf := make([]byte, MaxFrameSize)

	// Read from socket
	n, _, err := syscall.Recvfrom(i.fileDesc, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to receive packet: %w", err)
	}

	frame, err := Parse(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("failed to parse frame: %w", err)
	}

	return frame, nil
}

// WriteFrame writes an Ethernet frame to the network interface.
// It returns an error if serialization or sending fails.
func (i *Interface) WriteFrame(frame *Frame) error {
	var buf bytes.Buffer
	if err := frame.Serialize(&buf); err != nil {
		return fmt.Errorf("failed to serialize frame: %w", err)
	}

	addr := &unix.SockaddrLinklayer{
		Ifindex:  i.index,
		Protocol: htons(uint16(frame.EtherType)),
		Halen:    commons.MACLength,
	}

	copy(addr.Addr[:], frame.Destination[:])

	if err := unix.Sendto(i.fileDesc, buf.Bytes(), 0, addr); err != nil {
		return fmt.Errorf("failed to send frame: %w", err)
	}

	return nil
}

// htons converts a 16-bit integer from host byte order to network byte order (big endian).
func htons(v uint16) uint16 {
	// On little-endian systems, we need to swap bytes
	// On big-endian systems, this is a no-op
	// Go's binary.BigEndian handles this correctly
	return (v << 8) | (v >> 8)
}

// ListInterfaces returns a list of all network interfaces on the system.
func ListInterfaces() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		names = append(names, iface.Name)
	}

	return names, nil
}

// GetInterfaceInfo retrieves detailed information about a network interface.
// It returns a formatted string containing the interface's attributes.
func GetInterfaceInfo(ifname string) (string, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return "", fmt.Errorf("failed to get interface %s: %w", ifname, err)
	}

	var buffer strings.Builder
	buffer.WriteString(fmt.Sprintf("Name: %s\n", iface.Name))
	buffer.WriteString(fmt.Sprintf("Index: %d\n", iface.Index))
	buffer.WriteString(fmt.Sprintf("MTU: %d\n", iface.MTU))
	buffer.WriteString(fmt.Sprintf("HardwareAddr: %s\n", iface.HardwareAddr.String()))
	buffer.WriteString(fmt.Sprintf("Flags: %s\n", iface.Flags.String()))

	addrs, err := iface.Addrs()
	if err == nil && len(addrs) > 0 {
		buffer.WriteString("Addresses:\n")
		for _, addr := range addrs {
			buffer.WriteString(fmt.Sprintf("  - %s\n", addr.String()))
		}
	}

	return buffer.String(), nil
}
