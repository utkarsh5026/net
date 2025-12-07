//go:build linux
// +build linux

// ARP Network Scanner - Discover all devices on your local network
//
// This tool scans your entire subnet using ARP requests to discover
// all active devices, showing their IP addresses, MAC addresses, and vendors.
//
// Usage:
//   sudo go run examples/arp/main.go <interface> <local-ip>
//
// Example:
//   sudo go run examples/arp/main.go eth0 192.168.1.100

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/utkarsh5026/net/pkg/arp"
	"github.com/utkarsh5026/net/pkg/commons"
	"github.com/utkarsh5026/net/pkg/ethernet"
)

// scannedDevice represents a discovered device on the network.
// It contains the IP address, MAC address, and vendor information
// of a device that responded to an ARP request.
type scannedDevice struct {
	IP, MAC, Vendor string
}

// scanner manages the ARP scanning process and coordinates concurrent
// scanning of multiple IP addresses. It maintains statistics about the
// scan progress and collects information about discovered devices.
type scanner struct {
	handler *arp.Handler
	scanned int64
	total   int
	mu      sync.Mutex
	devices map[string]scannedDevice
}

// newScanner creates and initializes a new scanner instance with the given ARP handler.
func newScanner(handler *arp.Handler) *scanner {
	return &scanner{
		handler: handler,
		devices: make(map[string]scannedDevice),
	}
}

// generateIPAddresses generates a list of all valid host IP addresses within the given subnet.
// It excludes the network address (first IP) and broadcast address (last IP).
//
//	For subnet "192.168.1.0/24", generates IPs from 192.168.1.1 to 192.168.1.254
func (s *scanner) generateIPAddresses(subnet string) ([]commons.IPv4Address, error) {
	baseIP, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subnet: %w", err)
	}

	var ips []commons.IPv4Address
	for ip := baseIP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		if ip[3] == 0 || ip[3] == 255 {
			continue
		}

		var ipv4 commons.IPv4Address
		copy(ipv4[:], ip.To4())
		ips = append(ips, ipv4)
	}
	return ips, nil
}

// scan performs a concurrent ARP scan of all valid IPs in the specified subnet.
func (s *scanner) scan(ctx context.Context, subnet string) ([]scannedDevice, error) {
	ips, err := s.generateIPAddresses(subnet)
	if err != nil {
		return nil, err
	}
	s.total = len(ips)
	fmt.Printf("Scanning %d IPs in subnet %s...\n\n", s.total, subnet)

	done := make(chan struct{})
	go s.reportProgress(done)

	numWorkers := runtime.NumCPU()
	ipChan := make(chan commons.IPv4Address, numWorkers)

	var wg sync.WaitGroup

	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				select {
				case <-ctx.Done():
					return
				default:
					mac, err := s.handler.Resolve(ip)
					if err == nil {
						s.addDevice(ip, mac)
					}
					atomic.AddInt64(&s.scanned, 1)
				}
			}
		}()
	}

	go func() {
		defer close(ipChan)
		for _, targetIP := range ips {
			select {
			case <-ctx.Done():
				return
			case ipChan <- targetIP:
			}
		}
	}()

	wg.Wait()
	close(done)

	return s.getSortedDevices(), nil
}

// addDevice safely adds a discovered device to the scanner's device map.
func (s *scanner) addDevice(ip commons.IPv4Address, mac commons.MACAddress) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ipStr := ip.String()
	s.devices[ipStr] = scannedDevice{
		IP:     ipStr,
		MAC:    mac.String(),
		Vendor: commons.GetVendor(mac),
	}
}

// getSortedDevices returns all discovered devices sorted by IP address.
// The devices are sorted in ascending order by their numeric IP value.
func (s *scanner) getSortedDevices() []scannedDevice {
	s.mu.Lock()
	defer s.mu.Unlock()

	devices := make([]scannedDevice, 0, len(s.devices))
	for _, dev := range s.devices {
		devices = append(devices, dev)
	}

	sort.Slice(devices, func(i, j int) bool {
		return ipToInt(devices[i].IP) < ipToInt(devices[j].IP)
	})

	return devices
}

// reportProgress continuously prints scan progress updates to stdout.
// It updates every 500ms showing the number of IPs scanned and devices found.
func (s *scanner) reportProgress(done chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			scanned := atomic.LoadInt64(&s.scanned)
			s.mu.Lock()
			found := len(s.devices)
			s.mu.Unlock()
			fmt.Printf("\rProgress: %d/%d IPs scanned, %d devices found", scanned, s.total, found)
		}
	}
}

// incIP increments an IP address by one in-place.
// It treats the IP address as a big-endian integer and adds 1,
// handling carry-over between octets.
// Example:
//
//	192.168.1.1 becomes 192.168.1.2
//	192.168.1.255 becomes 192.168.2.0
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ipToInt converts an IPv4 address string to its 32-bit integer representation.
// This is useful for sorting IP addresses numerically.
//
//	"192.168.1.1" returns 3232235777 (0xC0A80101)
func ipToInt(ip string) uint32 {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0
	}
	var a, b, c, d uint32
	fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)
	return (a << 24) | (b << 16) | (c << 8) | d
}

// getInterfaceIPv4AndSubnet retrieves the first IPv4 address and its CIDR subnet from a network interface.
// This is used to automatically determine the local IP and subnet to scan.
func getInterfaceIPv4AndSubnet(ifaceName string) (commons.IPv4Address, string, error) {
	var zero commons.IPv4Address
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return zero, "", fmt.Errorf("failed to get interface %s: %w", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return zero, "", fmt.Errorf("failed to get addresses for %s: %w", ifaceName, err)
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipv4 := ipNet.IP.To4(); ipv4 != nil {
				var localIP commons.IPv4Address
				copy(localIP[:], ipv4)

				subnet := ipNet.String()
				return localIP, subnet, nil
			}
		}
	}

	return commons.IPv4Address{}, "", fmt.Errorf("no IPv4 address found on interface %s", ifaceName)
}

// printResults displays a formatted summary of the scan results.
func printResults(devices []scannedDevice, duration time.Duration) {
	fmt.Printf("\n\n")
	fmt.Printf("========================================\n")
	fmt.Printf("         SCAN COMPLETE\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Duration: %v\n", duration.Round(time.Millisecond))
	fmt.Printf("Devices Found: %d\n\n", len(devices))

	if len(devices) == 0 {
		fmt.Printf("No devices found on the network.\n")
		return
	}

	fmt.Printf("%-18s  %-20s  %-30s\n", "IP Address", "MAC Address", "Vendor")
	fmt.Printf("%s\n", strings.Repeat("-", 70))

	for _, dev := range devices {
		vendor := dev.Vendor
		if vendor == "" {
			vendor = "Unknown"
		}
		fmt.Printf("%-18s  %-20s  %-30s\n", dev.IP, dev.MAC, vendor)
	}
	fmt.Printf("\n")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "ARP Network Scanner - Discover devices on your local network\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s <interface>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  sudo %s eth0\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nThe scanner will automatically detect your IP address and subnet\n")
		fmt.Fprintf(os.Stderr, "from the interface and scan all IPs in that range.\n\n")
		fmt.Fprintf(os.Stderr, "Note: This program requires root/sudo privileges.\n")
		os.Exit(1)
	}

	ifaceName := os.Args[1]
	localIP, subnet, err := getInterfaceIPv4AndSubnet(ifaceName)
	if err != nil {
		log.Fatalf("Failed to get IP/subnet from interface: %v", err)
	}

	fmt.Printf("ARP Network Scanner\n")
	fmt.Printf("==================\n")
	fmt.Printf("Interface: %s\n", ifaceName)
	fmt.Printf("Local IP: %s\n", localIP.String())
	fmt.Printf("Subnet: %s\n\n", subnet)

	iface, err := ethernet.OpenInterface(ifaceName)
	if err != nil {
		log.Fatalf("Failed to open interface: %v", err)
	}
	defer iface.Close()

	handler := arp.NewHandler(iface, localIP)
	handler.SetTimeout(500 * time.Millisecond)
	handler.SetMaxRetries(2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go handler.Start(ctx)

	time.Sleep(100 * time.Millisecond)

	sc := newScanner(handler)
	startTime := time.Now()

	devices, err := sc.scan(ctx, subnet)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	duration := time.Since(startTime)
	printResults(devices, duration)
}
