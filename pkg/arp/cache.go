package arp

import (
	"sync"
	"time"

	"github.com/utkarsh5026/net/pkg/commons"
)

// DefaultCacheTimeout is the default time after which an ARP cache entry expires.
// RFC 826 doesn't specify a timeout, but typical implementations use 60-300 seconds.
const DefaultCacheTimeout = 5 * time.Minute

// CacheEntry represents a single entry in the ARP cache.
type CacheEntry struct {
	MAC       commons.MACAddress
	ExpiresAt time.Time
}

// IsExpired returns true if this cache entry has expired.
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// cache implements a thread-safe ARP cache that maps IP addresses to MAC addresses.
// Entries automatically expire after a configured timeout.
type cache struct {
	mu      sync.RWMutex
	entries map[commons.IPv4Address]*CacheEntry
	timeout time.Duration
}

// NewCache creates a new ARP cache with the specified timeout.
func newCache(timeout time.Duration) *cache {
	return &cache{
		entries: make(map[commons.IPv4Address]*CacheEntry),
		timeout: timeout,
	}
}

// newDefaultCache creates a new ARP cache with the default timeout.
func newDefaultCache() *cache {
	return newCache(DefaultCacheTimeout)
}

// Add adds or updates an entry in the ARP cache.
func (c *cache) Add(ip commons.IPv4Address, mac commons.MACAddress) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[ip] = &CacheEntry{
		MAC:       mac,
		ExpiresAt: time.Now().Add(c.timeout),
	}
}

// Get retrieves a MAC address for the given IP address.
// Returns the MAC address and true if found and not expired, or zero MAC and false otherwise.
func (c *cache) Get(ip commons.IPv4Address) (commons.MACAddress, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[ip]
	if !exists {
		return commons.MACAddress{}, false
	}

	if entry.IsExpired() {
		return commons.MACAddress{}, false
	}

	return entry.MAC, true
}

// GetAll returns all non-expired entries in the cache.
func (c *cache) GetAll() map[commons.IPv4Address]commons.MACAddress {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[commons.IPv4Address]commons.MACAddress)
	for ip, entry := range c.entries {
		if !entry.IsExpired() {
			result[ip] = entry.MAC
		}
	}
	return result
}
