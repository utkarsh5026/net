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

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

// Styles for the TUI
var (
	// Color palette
	primaryColor   = lipgloss.Color("#00D9FF")
	secondaryColor = lipgloss.Color("#7C3AED")
	successColor   = lipgloss.Color("#10B981")
	warningColor   = lipgloss.Color("#F59E0B")
	errorColor     = lipgloss.Color("#EF4444")
	textColor      = lipgloss.Color("#E5E7EB")
	mutedColor     = lipgloss.Color("#9CA3AF")
	bgColor        = lipgloss.Color("#1F2937")

	// Title styles
	titleStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true).
			Padding(0, 1).
			MarginTop(1).
			MarginBottom(1)

	headerStyle = lipgloss.NewStyle().
			Foreground(textColor).
			Background(secondaryColor).
			Padding(0, 2).
			Bold(true)

	// Info box styles
	infoBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(primaryColor).
			Padding(1, 2).
			MarginBottom(1)

	infoLabelStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			Width(12)

	infoValueStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true)

	// Progress styles
	progressBarStyle = lipgloss.NewStyle().
				Foreground(successColor)

	progressTextStyle = lipgloss.NewStyle().
				Foreground(textColor).
				Bold(true)

	// Table styles
	tableHeaderStyle = lipgloss.NewStyle().
				Foreground(bgColor).
				Background(primaryColor).
				Bold(true).
				Padding(0, 1)

	tableCellStyle = lipgloss.NewStyle().
			Foreground(textColor).
			Padding(0, 1)

	tableRowAltStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#374151")).
				Foreground(textColor).
				Padding(0, 1)

	// Status styles
	statusScanningStyle = lipgloss.NewStyle().
				Foreground(warningColor).
				Bold(true)

	statusCompleteStyle = lipgloss.NewStyle().
				Foreground(successColor).
				Bold(true)

	// Footer styles
	footerStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			MarginTop(1).
			Italic(true)
)

// scanner manages the ARP scanning process and coordinates concurrent
// scanning of multiple IP addresses. It maintains statistics about the
// scan progress and collects information about discovered devices.
type scanner struct {
	handler *arp.Handler
	scanned int64
	total   int
	mu      sync.Mutex
	devices map[string]scannedDevice
	prog    *tea.Program // Add reference to tea program for updates
}

// newScanner creates and initializes a new scanner instance with the given ARP handler.
func newScanner(handler *arp.Handler, prog *tea.Program) *scanner {
	return &scanner{
		handler: handler,
		devices: make(map[string]scannedDevice),
		prog:    prog,
	}
}

// scanProgressMsg is sent when scan progress updates
type scanProgressMsg struct {
	scanned int64
	found   int
}

// scanCompleteMsg is sent when scanning completes
type scanCompleteMsg struct {
	devices  []scannedDevice
	duration time.Duration
}

// deviceFoundMsg is sent when a new device is discovered
type deviceFoundMsg struct {
	device scannedDevice
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
func (s *scanner) scan(ctx context.Context, subnet string, startTime time.Time) error {
	ips, err := s.generateIPAddresses(subnet)
	if err != nil {
		return err
	}
	s.total = len(ips)

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
						dev := s.addDevice(ip, mac)
						if s.prog != nil {
							s.prog.Send(deviceFoundMsg{device: dev})
						}
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

	if s.prog != nil {
		duration := time.Since(startTime)
		s.prog.Send(scanCompleteMsg{
			devices:  s.getSortedDevices(),
			duration: duration,
		})
	}

	return nil
}

// addDevice safely adds a discovered device to the scanner's device map.
func (s *scanner) addDevice(ip commons.IPv4Address, mac commons.MACAddress) scannedDevice {
	s.mu.Lock()
	defer s.mu.Unlock()

	ipStr := ip.String()
	dev := scannedDevice{
		IP:     ipStr,
		MAC:    mac.String(),
		Vendor: commons.GetVendor(mac),
	}
	s.devices[ipStr] = dev
	return dev
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

// reportProgress continuously sends scan progress updates to the TUI.
// It updates every 200ms showing the number of IPs scanned and devices found.
func (s *scanner) reportProgress(done chan struct{}) {
	ticker := time.NewTicker(200 * time.Millisecond)
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
			if s.prog != nil {
				s.prog.Send(scanProgressMsg{scanned: scanned, found: found})
			}
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

// Model represents the Bubble Tea model for the TUI
type model struct {
	ifaceName string
	localIP   string
	subnet    string
	totalIPs  int
	scanned   int64
	found     int
	devices   []scannedDevice
	scanning  bool
	complete  bool
	duration  time.Duration
	width     int
	height    int
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case scanProgressMsg:
		m.scanned = msg.scanned
		m.found = msg.found
		return m, nil

	case deviceFoundMsg:
		m.devices = append(m.devices, msg.device)
		sort.Slice(m.devices, func(i, j int) bool {
			return ipToInt(m.devices[i].IP) < ipToInt(m.devices[j].IP)
		})
		return m, nil

	case scanCompleteMsg:
		m.complete = true
		m.scanning = false
		m.devices = msg.devices
		m.duration = msg.duration
		return m, tea.Quit

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m model) View() string {
	return m.renderScanning()
}

func (m model) renderScanning() string {
	var b strings.Builder

	// Title
	title := titleStyle.Render("⚡ ARP NETWORK SCANNER")
	b.WriteString(title)
	b.WriteString("\n\n")

	// Info box
	infoContent := strings.Builder{}
	infoContent.WriteString(infoLabelStyle.Render("Interface:") + "  " + infoValueStyle.Render(m.ifaceName) + "\n")
	infoContent.WriteString(infoLabelStyle.Render("Local IP:") + "  " + infoValueStyle.Render(m.localIP) + "\n")
	infoContent.WriteString(infoLabelStyle.Render("Subnet:") + "  " + infoValueStyle.Render(m.subnet) + "\n")
	infoContent.WriteString(infoLabelStyle.Render("Target IPs:") + "  " + infoValueStyle.Render(fmt.Sprintf("%d", m.totalIPs)))

	b.WriteString(infoBoxStyle.Render(infoContent.String()))
	b.WriteString("\n\n")

	status := statusScanningStyle.Render("● SCANNING")
	b.WriteString(status)
	b.WriteString("\n\n")

	progress := m.renderProgressBar()
	b.WriteString(progress)
	b.WriteString("\n\n")

	statsText := fmt.Sprintf("Scanned: %d/%d IPs  •  Devices Found: %d", m.scanned, m.totalIPs, m.found)
	stats := progressTextStyle.Render(statsText)
	b.WriteString(stats)
	b.WriteString("\n\n")

	if len(m.devices) > 0 {
		b.WriteString(headerStyle.Render(" DISCOVERED DEVICES "))
		b.WriteString("\n\n")
		table := m.renderDeviceTable()
		b.WriteString(table)
		b.WriteString("\n")
	}

	footer := footerStyle.Render("Press Ctrl+C or q to quit")
	b.WriteString("\n")
	b.WriteString(footer)

	return b.String()
}

func (m model) renderProgressBar() string {
	width := 50
	if m.totalIPs == 0 {
		return ""
	}

	percent := float64(m.scanned) / float64(m.totalIPs)
	filled := int(percent * float64(width))

	bar := strings.Builder{}
	bar.WriteString("[")

	for i := range width {
		if i < filled {
			bar.WriteString(progressBarStyle.Render("█"))
		} else {
			bar.WriteString(lipgloss.NewStyle().Foreground(mutedColor).Render("░"))
		}
	}

	bar.WriteString("]")

	percentText := fmt.Sprintf(" %.1f%%", percent*100)
	bar.WriteString(progressBarStyle.Render(percentText))

	return bar.String()
}

func (m model) renderDeviceTable() string {
	if len(m.devices) == 0 {
		return ""
	}

	var b strings.Builder

	ipHeader := tableHeaderStyle.Width(18).Render("IP Address")
	macHeader := tableHeaderStyle.Width(20).Render("MAC Address")
	vendorHeader := tableHeaderStyle.Width(35).Render("Vendor")

	b.WriteString(ipHeader)
	b.WriteString(macHeader)
	b.WriteString(vendorHeader)
	b.WriteString("\n")

	maxRows := 15
	displayDevices := m.devices
	if len(displayDevices) > maxRows {
		displayDevices = displayDevices[len(displayDevices)-maxRows:]
	}

	for i, dev := range displayDevices {
		vendor := dev.Vendor
		if vendor == "" {
			vendor = "Unknown"
		}

		var ipCell, macCell, vendorCell string
		if i%2 == 0 {
			ipCell = tableRowAltStyle.Width(18).Render(dev.IP)
			macCell = tableRowAltStyle.Width(20).Render(dev.MAC)
			vendorCell = tableRowAltStyle.Width(35).Render(vendor)
		} else {
			ipCell = tableCellStyle.Width(18).Render(dev.IP)
			macCell = tableCellStyle.Width(20).Render(dev.MAC)
			vendorCell = tableCellStyle.Width(35).Render(vendor)
		}

		b.WriteString(ipCell)
		b.WriteString(macCell)
		b.WriteString(vendorCell)
		b.WriteString("\n")
	}

	if len(m.devices) > maxRows {
		more := lipgloss.NewStyle().
			Foreground(mutedColor).
			Italic(true).
			Render(fmt.Sprintf("... and %d more devices", len(m.devices)-maxRows))
		b.WriteString("\n")
		b.WriteString(more)
	}

	return b.String()
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

	// Calculate total IPs
	tempScanner := &scanner{devices: make(map[string]scannedDevice)}
	ips, err := tempScanner.generateIPAddresses(subnet)
	if err != nil {
		log.Fatalf("Failed to generate IP addresses: %v", err)
	}

	m := model{
		ifaceName: ifaceName,
		localIP:   localIP.String(),
		subnet:    subnet,
		totalIPs:  len(ips),
		scanning:  true,
		devices:   []scannedDevice{},
	}

	p := tea.NewProgram(m, tea.WithAltScreen())

	sc := newScanner(handler, p)
	sc.total = len(ips)
	startTime := time.Now()

	go func() {
		if err := sc.scan(ctx, subnet, startTime); err != nil {
			log.Printf("Scan failed: %v", err)
			p.Quit()
		}
	}()

	if _, err := p.Run(); err != nil {
		log.Fatalf("Error running program: %v", err)
	}
}
