//go:build linux
// +build linux

package arp

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/utkarsh5026/net/pkg/commons"
	"github.com/utkarsh5026/net/pkg/ethernet"
)

// DefaultRequestTimeout is the default timeout for ARP requests.
const DefaultRequestTimeout = 3 * time.Second

// DefaultMaxRetries is the default number of retries for ARP requests.
const DefaultMaxRetries = 3

// Handler handles ARP protocol operations including resolving IP addresses,
// responding to requests, and maintaining the ARP cache.
type Handler struct {
	iface        *ethernet.Interface
	cache        *cache
	myIp         commons.IPv4Address
	requestQueue map[commons.IPv4Address]chan commons.MACAddress
	mu           sync.RWMutex
	timeout      time.Duration
	maxRetries   int
}

// NewHandler creates a new ARP handler for the given interface.
func NewHandler(iface *ethernet.Interface, myIp commons.IPv4Address) *Handler {
	return &Handler{
		iface:        iface,
		cache:        newDefaultCache(),
		myIp:         myIp,
		requestQueue: make(map[commons.IPv4Address]chan commons.MACAddress),
		timeout:      DefaultRequestTimeout,
		maxRetries:   DefaultMaxRetries,
	}
}

// Resolve resolves an IP address to a MAC address using ARP.
// It first checks the cache, and if not found, sends an ARP request.
// This function blocks until a response is received or timeout occurs.
func (h *Handler) Resolve(targetIP commons.IPv4Address) (commons.MACAddress, error) {
	if mac, found := h.cache.Get(targetIP); found {
		return mac, nil
	}

	return h.sendRequestAndWait(targetIP)
}

func (h *Handler) sendRequestAndWait(targetIP commons.IPv4Address) (commons.MACAddress, error) {
	h.mu.Lock()
	responseChan, exists := h.requestQueue[targetIP]
	if !exists {
		responseChan = make(chan commons.MACAddress, 1)
		h.requestQueue[targetIP] = responseChan
	}
	h.mu.Unlock()

	// If another goroutine is already waiting for this IP, just wait with it
	if exists {
		select {
		case mac := <-responseChan:
			return mac, nil
		case <-time.After(h.timeout):
			return commons.MACAddress{}, fmt.Errorf("ARP request timeout for %s", targetIP)
		}
	}

	// Clean up when done
	defer func() {
		h.mu.Lock()
		delete(h.requestQueue, targetIP)
		close(responseChan)
		h.mu.Unlock()
	}()

	var lastErr error
	for attempt := 0; attempt < h.maxRetries; attempt++ {
		if err := h.sendRequest(targetIP); err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Wait for response
		select {
		case mac := <-responseChan:
			return mac, nil
		case <-time.After(h.timeout / time.Duration(h.maxRetries)):
			lastErr = fmt.Errorf("ARP request timeout for %s (attempt %d/%d)", targetIP, attempt+1, h.maxRetries)
		}
	}

	return commons.MACAddress{}, lastErr

}

// Announce sends a gratuitous ARP announcement for the local IP address.
func (h *Handler) Announce() error {
	return h.sendRequest(h.myIp)
}

// SetTimeout sets the timeout for ARP requests.
func (h *Handler) SetTimeout(timeout time.Duration) {
	h.timeout = timeout
}

// SetMaxRetries sets the maximum number of retries for ARP requests.
func (h *Handler) SetMaxRetries(retries int) {
	h.maxRetries = retries
}

// GetAllCachedDevices returns all non-expired entries from the ARP cache.
func (h *Handler) GetAllCachedDevices() map[commons.IPv4Address]commons.MACAddress {
	return h.cache.GetAll()
}

func (h *Handler) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return

			default:
				f, err := h.iface.ReadFrame()
				if err != nil {
					log.Printf("ARP handler: failed to read frame: %v", err)
					continue
				}

				if f.EtherType != ethernet.EtherTypeARP {
					log.Printf("ARP handler: ignoring non-ARP frame with EtherType: %v", f.EtherType)
					continue
				}

				packet, err := Parse(f.Payload)
				if err != nil {
					log.Printf("ARP handler: failed to parse ARP packet: %v", err)
					continue
				}

				if err := h.handlePacket(packet); err != nil {
					log.Printf("ARP handler: failed to handle ARP packet: %v", err)
				}
			}
		}
	}()
}

func (h *Handler) handlePacket(packet *Packet) error {
	if packet.IsRequest() {
		return h.handleRequest(packet)
	}

	if packet.IsReply() {
		return h.handleReply(packet)
	}

	return fmt.Errorf("unknown ARP operation: %d", packet.Operation)
}

// handleRequest processes an ARP request.
// If the request is for our IP, send a reply.
func (h *Handler) handleRequest(packet *Packet) error {
	h.cache.Add(packet.SenderIP, packet.SenderMAC)

	// Check if the request is for our IP
	if packet.TargetIP != h.myIp {
		return nil
	}

	return h.sendReply(packet.SenderMAC, packet.SenderIP)
}

func (h *Handler) handleReply(packet *Packet) error {
	h.cache.Add(packet.SenderIP, packet.SenderMAC)

	h.mu.RLock()
	responseChan, exists := h.requestQueue[packet.SenderIP]
	h.mu.RUnlock()

	if exists {
		select {
		case responseChan <- packet.SenderMAC:
		default:
		}
	}

	return nil
}

// SendReply sends an ARP reply to the given MAC/IP address.
func (h *Handler) sendReply(targetMAC commons.MACAddress, targetIP commons.IPv4Address) error {
	arpPacket := NewReply(h.iface.MACAddress(), targetMAC, h.myIp, targetIP)
	return h.writeFrame(arpPacket, targetMAC)
}

func (h *Handler) sendRequest(targetIP commons.IPv4Address) error {
	arpPacket := NewRequest(h.iface.MACAddress(), h.myIp, targetIP)
	return h.writeFrame(arpPacket, commons.BroadCastMAC)
}

func (h *Handler) writeFrame(p *Packet, dst commons.MACAddress) error {
	frame := ethernet.NewFrame(
		dst,
		h.iface.MACAddress(),
		ethernet.EtherTypeARP,
		p.Serialize(),
	)

	return h.iface.WriteFrame(frame)
}
