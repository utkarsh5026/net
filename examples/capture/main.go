//go:build linux
// +build linux

// Package main provides an example of capturing and displaying Ethernet frames.
// This program demonstrates the Phase 1 capabilities: raw socket packet capture
// and Ethernet frame parsing with a beautiful TUI interface.
//
// Usage:
//
//	sudo go run examples/capture/main.go [options]
//
// Options:
//
//	-i string    Network interface to capture on (e.g., eth0, wlan0)
//	-c int       Number of packets to capture (0 = unlimited)
//	-v           Verbose output (show each packet detail)
//
// If no interface is specified, it will list available interfaces and use the first one.
//
// Note: This program requires root/sudo privileges to access raw sockets.
//
// Examples:
//
//	sudo go run examples/capture/main.go -i eth0 -c 100
//	sudo go run examples/capture/main.go -v
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/utkarsh5026/net/pkg/commons"
	"github.com/utkarsh5026/net/pkg/ethernet"
)

var (
	ifaceFlag   = flag.String("i", "", "Network interface to capture on (e.g., eth0, wlan0)")
	countFlag   = flag.Int("c", 0, "Number of packets to capture (0 = unlimited)")
	verboseFlag = flag.Bool("v", true, "Verbose output (show packet details)")
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205")).
			Background(lipgloss.Color("235")).
			Padding(0, 1).
			MarginBottom(1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39")).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(1, 2)

	statsBoxStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(1, 2).
			MarginRight(1)

	packetBoxStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("205")).
			Padding(0, 1).
			MarginTop(1)

	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	valueStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("86"))

	protocolStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("212"))

	ipStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("39"))

	portStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("226"))
)

type frameMsg struct {
	frame *ethernet.Frame
}

type tickMsg time.Time

type model struct {
	iface       *ethernet.Interface
	stats       *captureStats
	packets     []string
	maxPackets  int
	targetCount int
	verbose     bool
	running     bool
	err         error
}

type captureStats struct {
	totalPackets int
	totalBytes   int64
	startTime    time.Time
	ipv4Count    int
	ipv6Count    int
	arpCount     int
	broadcast    int
	multicast    int
	unicast      int
	tcpCount     int
	udpCount     int
	icmpCount    int
}

func newCaptureStats() *captureStats {
	return &captureStats{
		startTime: time.Now(),
	}
}

func (s *captureStats) update(frame *ethernet.Frame) {
	s.totalPackets++
	s.totalBytes += int64(len(frame.Payload))

	if frame.IsBroadcast() {
		s.broadcast++
	} else if frame.IsMulticast() {
		s.multicast++
	} else {
		s.unicast++
	}

	switch frame.EtherType {
	case ethernet.EtherTypeIPv4:
		s.ipv4Count++
		if len(frame.Payload) >= 20 {
			protocol := frame.Payload[9]
			switch commons.Protocol(protocol) {
			case commons.ProtocolTCP:
				s.tcpCount++
			case commons.ProtocolUDP:
				s.udpCount++
			case commons.ProtocolICMP:
				s.icmpCount++
			}
		}
	case ethernet.EtherTypeIPv6:
		s.ipv6Count++
	case ethernet.EtherTypeARP:
		s.arpCount++
	}
}

func initialModel(iface *ethernet.Interface, targetCount int, verbose bool) model {
	return model{
		iface:       iface,
		stats:       newCaptureStats(),
		packets:     []string{},
		maxPackets:  50,
		targetCount: targetCount,
		verbose:     verbose,
		running:     true,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		tickCmd(),
		captureCmd(m.iface),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func captureCmd(iface *ethernet.Interface) tea.Cmd {
	return func() tea.Msg {
		frame, err := iface.ReadFrame()
		if err != nil {
			return nil
		}
		return frameMsg{frame: frame}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.running = false
			return m, tea.Quit
		}

	case frameMsg:
		if msg.frame != nil {
			m.stats.update(msg.frame)

			if m.verbose {
				packetStr := formatPacket(m.stats.totalPackets, msg.frame)
				m.packets = append(m.packets, packetStr)
				if len(m.packets) > m.maxPackets {
					m.packets = m.packets[1:]
				}
			}

			if m.targetCount > 0 && m.stats.totalPackets >= m.targetCount {
				m.running = false
				return m, tea.Quit
			}
		}
		return m, captureCmd(m.iface)

	case tickMsg:
		if m.running {
			return m, tickCmd()
		}
	}

	return m, nil
}

func (m model) View() string {
	if !m.running {
		return m.renderSummary()
	}

	var sections []string

	// Title
	title := titleStyle.Render("🌐 ETHERNET FRAME CAPTURE TOOL 🌐")
	sections = append(sections, title)

	// Header with interface info
	header := m.renderHeader()
	sections = append(sections, header)

	// Stats dashboard
	stats := m.renderStats()
	sections = append(sections, stats)

	// Protocol breakdown
	protocols := m.renderProtocols()
	sections = append(sections, protocols)

	// Recent packets (if verbose)
	if m.verbose && len(m.packets) > 0 {
		recentPackets := m.renderRecentPackets()
		sections = append(sections, recentPackets)
	}

	// Footer
	footer := labelStyle.Render("Press 'q' or 'Ctrl+C' to quit")
	sections = append(sections, "\n"+footer)

	return strings.Join(sections, "\n")
}

func (m model) renderHeader() string {
	elapsed := time.Since(m.stats.startTime)
	info := fmt.Sprintf("Interface: %s | MAC: %s | Running: %v",
		m.iface.Name(),
		m.iface.MACAddress(),
		elapsed.Round(time.Second))
	return headerStyle.Render(info)
}

func (m model) renderStats() string {
	elapsed := time.Since(m.stats.startTime).Seconds()
	if elapsed == 0 {
		elapsed = 1
	}

	pps := float64(m.stats.totalPackets) / elapsed
	bps := float64(m.stats.totalBytes) / elapsed

	stats1 := statsBoxStyle.Render(fmt.Sprintf(
		"%s\n%s\n\n%s\n%s",
		labelStyle.Render("Total Packets:"),
		valueStyle.Render(fmt.Sprintf("%d", m.stats.totalPackets)),
		labelStyle.Render("Total Bytes:"),
		valueStyle.Render(formatBytes(m.stats.totalBytes)),
	))

	stats2 := statsBoxStyle.Render(fmt.Sprintf(
		"%s\n%s\n\n%s\n%s",
		labelStyle.Render("Packet Rate:"),
		valueStyle.Render(fmt.Sprintf("%.1f pkt/s", pps)),
		labelStyle.Render("Bandwidth:"),
		valueStyle.Render(fmt.Sprintf("%.2f KB/s", bps/1024)),
	))

	stats3 := statsBoxStyle.Render(fmt.Sprintf(
		"%s\n%s\n%s\n%s",
		labelStyle.Render("Unicast:   ")+valueStyle.Render(fmt.Sprintf("%d", m.stats.unicast)),
		labelStyle.Render("Broadcast: ")+valueStyle.Render(fmt.Sprintf("%d", m.stats.broadcast)),
		labelStyle.Render("Multicast: ")+valueStyle.Render(fmt.Sprintf("%d", m.stats.multicast)),
		labelStyle.Render(""),
	))

	return lipgloss.JoinHorizontal(lipgloss.Top, stats1, stats2, stats3)
}

func (m model) renderProtocols() string {
	protocols := fmt.Sprintf(
		"%s  %s  %s  %s  %s  %s",
		labelStyle.Render("IPv4:")+protocolStyle.Render(fmt.Sprintf(" %d", m.stats.ipv4Count)),
		labelStyle.Render("IPv6:")+protocolStyle.Render(fmt.Sprintf(" %d", m.stats.ipv6Count)),
		labelStyle.Render("ARP:")+protocolStyle.Render(fmt.Sprintf(" %d", m.stats.arpCount)),
		labelStyle.Render("TCP:")+protocolStyle.Render(fmt.Sprintf(" %d", m.stats.tcpCount)),
		labelStyle.Render("UDP:")+protocolStyle.Render(fmt.Sprintf(" %d", m.stats.udpCount)),
		labelStyle.Render("ICMP:")+protocolStyle.Render(fmt.Sprintf(" %d", m.stats.icmpCount)),
	)

	return statsBoxStyle.Copy().MarginTop(1).Render(protocols)
}

func (m model) renderRecentPackets() string {
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("205")).
		Render("Recent Packets")

	maxDisplay := 10
	start := max(len(m.packets)-maxDisplay, 0)

	content := title + "\n\n" + strings.Join(m.packets[start:], "\n")
	return packetBoxStyle.Render(content)
}

func (m model) renderSummary() string {
	elapsed := time.Since(m.stats.startTime)

	summary := titleStyle.Render("📊 CAPTURE SUMMARY")
	summary += "\n\n"

	summary += statsBoxStyle.Copy().Width(60).Render(fmt.Sprintf(
		"%s\n%s\n\n%s\n%s\n\n%s\n%s",
		labelStyle.Render("Duration:"),
		valueStyle.Render(elapsed.Round(time.Millisecond).String()),
		labelStyle.Render("Total Packets:"),
		valueStyle.Render(fmt.Sprintf("%d", m.stats.totalPackets)),
		labelStyle.Render("Total Bytes:"),
		valueStyle.Render(formatBytes(m.stats.totalBytes)),
	))

	summary += "\n\n"

	if m.stats.totalPackets > 0 {
		summary += statsBoxStyle.Copy().Width(60).Render(fmt.Sprintf(
			"%s\n"+
				"  Unicast:   %d (%.1f%%)\n"+
				"  Broadcast: %d (%.1f%%)\n"+
				"  Multicast: %d (%.1f%%)\n\n"+
				"%s\n"+
				"  IPv4: %d | IPv6: %d | ARP: %d\n\n"+
				"%s\n"+
				"  TCP: %d | UDP: %d | ICMP: %d",
			labelStyle.Render("Frame Types:"),
			m.stats.unicast, percent(m.stats.unicast, m.stats.totalPackets),
			m.stats.broadcast, percent(m.stats.broadcast, m.stats.totalPackets),
			m.stats.multicast, percent(m.stats.multicast, m.stats.totalPackets),
			labelStyle.Render("Protocols:"),
			m.stats.ipv4Count, m.stats.ipv6Count, m.stats.arpCount,
			labelStyle.Render("Transport:"),
			m.stats.tcpCount, m.stats.udpCount, m.stats.icmpCount,
		))
	}

	return summary + "\n"
}

func formatPacket(num int, frame *ethernet.Frame) string {
	timestamp := time.Now().Format("15:04:05")

	var proto string
	switch frame.EtherType {
	case ethernet.EtherTypeIPv4:
		proto = "IPv4"
		if len(frame.Payload) >= 20 {
			protocol := frame.Payload[9]
			srcIP := commons.IPv4Address{frame.Payload[12], frame.Payload[13], frame.Payload[14], frame.Payload[15]}
			dstIP := commons.IPv4Address{frame.Payload[16], frame.Payload[17], frame.Payload[18], frame.Payload[19]}

			switch commons.Protocol(protocol) {
			case commons.ProtocolTCP:
				proto = "TCP "
				if len(frame.Payload) >= 24 {
					ihl := frame.Payload[0] & 0x0F
					srcPort := uint16(frame.Payload[ihl*4])<<8 | uint16(frame.Payload[ihl*4+1])
					dstPort := uint16(frame.Payload[ihl*4+2])<<8 | uint16(frame.Payload[ihl*4+3])
					proto += portStyle.Render(fmt.Sprintf("[%d→%d]", srcPort, dstPort))
				}
			case commons.ProtocolUDP:
				proto = "UDP "
				if len(frame.Payload) >= 24 {
					ihl := frame.Payload[0] & 0x0F
					srcPort := uint16(frame.Payload[ihl*4])<<8 | uint16(frame.Payload[ihl*4+1])
					dstPort := uint16(frame.Payload[ihl*4+2])<<8 | uint16(frame.Payload[ihl*4+3])
					proto += portStyle.Render(fmt.Sprintf("[%d→%d]", srcPort, dstPort))
				}
			case commons.ProtocolICMP:
				proto = "ICMP"
			}
			proto += " " + ipStyle.Render(fmt.Sprintf("%s→%s", srcIP, dstIP))
		}
	case ethernet.EtherTypeARP:
		proto = "ARP "
		if len(frame.Payload) >= 28 {
			opcode := uint16(frame.Payload[6])<<8 | uint16(frame.Payload[7])

			switch opcode {
			case 1:
				proto += "Request"
			case 2:
				proto += "Reply"
			}
		}
	case ethernet.EtherTypeIPv6:
		proto = "IPv6"
	default:
		proto = fmt.Sprintf("0x%04x", uint16(frame.EtherType))
	}

	return fmt.Sprintf("[%s] #%d %s %s %db",
		labelStyle.Render(timestamp),
		num,
		protocolStyle.Render(proto),
		labelStyle.Render(fmt.Sprintf("%s→%s", frame.Source, frame.Destination)),
		len(frame.Payload),
	)
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func percent(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}

func getInterface() string {
	ifname := *ifaceFlag
	if ifname == "" {
		interfaces, err := ethernet.ListInterfaces()
		if err != nil {
			log.Fatalf("Failed to list interfaces: %v", err)
		}

		if len(interfaces) == 0 {
			log.Fatal("No network interfaces found")
		}

		fmt.Println("╔════════════════════════════════════════════════════════╗")
		fmt.Println("║     ETHERNET FRAME CAPTURE - Interface Selection      ║")
		fmt.Println("╚════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("Available network interfaces:")
		fmt.Println()

		for i, name := range interfaces {
			info, err := ethernet.GetInterfaceInfo(name)
			if err == nil {
				fmt.Printf("  [%d] %s\n", i+1, name)
				lines := strings.SplitSeq(strings.TrimSpace(info), "\n")
				for line := range lines {
					if strings.Contains(line, "HardwareAddr:") ||
						strings.Contains(line, "Flags:") ||
						strings.Contains(line, "- ") {
						fmt.Printf("      %s\n", line)
					}
				}
				fmt.Println()
			} else {
				fmt.Printf("  [%d] %s\n", i+1, name)
			}
		}

		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Printf("Select an interface (1-%d), or press Enter for [1]: ", len(interfaces))

		var input string
		fmt.Scanln(&input)
		input = strings.TrimSpace(input)

		if input == "" {
			ifname = interfaces[0]
			fmt.Printf("Using default interface: %s\n\n", ifname)
		} else {
			var selection int
			_, err := fmt.Sscanf(input, "%d", &selection)
			if err != nil || selection < 1 || selection > len(interfaces) {
				log.Fatalf("Invalid selection: %s. Please enter a number between 1 and %d", input, len(interfaces))
			}
			ifname = interfaces[selection-1]
			fmt.Printf("Selected interface: %s\n\n", ifname)
		}

		fmt.Println("💡 Tip: You can directly specify an interface next time using: -i", ifname)
		fmt.Println()
		time.Sleep(2 * time.Second) // Give user time to read
	}

	return ifname
}

func main() {
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Fatal("This program requires root privileges. Please run with sudo.")
	}

	ifname := getInterface()

	iface, err := ethernet.OpenInterface(ifname)
	if err != nil {
		log.Fatalf("Failed to open interface: %v", err)
	}
	defer iface.Close()

	m := initialModel(iface, *countFlag, *verboseFlag)
	p := tea.NewProgram(m, tea.WithAltScreen())

	if _, err := p.Run(); err != nil {
		log.Fatalf("Error running program: %v", err)
	}
}
