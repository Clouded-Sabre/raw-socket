//go:build darwin || freebsd || windows
// +build darwin freebsd windows

package lib

import (
	"log"
	"net"
	"sync"
	"time"
)

type ARPEntry struct {
	MacAddress net.HardwareAddr
	Expiry     time.Time
}

type ARPCache struct {
	mu           sync.RWMutex
	entries      map[string]ARPEntry
	timeout      time.Duration
	timeoutTimer *time.Timer
	stopChan     chan struct{}
	isClosed     bool
	wg           sync.WaitGroup
}

func NewARPCache(timeout time.Duration) *ARPCache {
	cache := &ARPCache{
		entries:      make(map[string]ARPEntry),
		timeout:      timeout,
		timeoutTimer: time.NewTimer(timeout), // Initialize the timer
		stopChan:     make(chan struct{}),    // Initialize the stop channel
		wg:           sync.WaitGroup{},
	}

	cache.wg.Add(1)
	go cache.cleanup() // Start background cleanup process

	return cache
}

func (cache *ARPCache) Add(ip string, mac net.HardwareAddr) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.entries[ip] = ARPEntry{
		MacAddress: mac,
		Expiry:     time.Now().Add(cache.timeout),
	}
}

func (cache *ARPCache) Lookup(ip string) (net.HardwareAddr, bool) {
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	entry, found := cache.entries[ip]
	if !found || time.Now().After(entry.Expiry) {
		return nil, false
	}
	return entry.MacAddress, true
}

func (cache *ARPCache) cleanup() {
	defer cache.wg.Done()

	for {
		select {
		case <-cache.timeoutTimer.C:
			cache.mu.Lock()
			now := time.Now()
			for ip, entry := range cache.entries {
				if now.After(entry.Expiry) {
					delete(cache.entries, ip)
				}
			}
			cache.mu.Unlock()
			if !cache.isClosed {
				cache.timeoutTimer.Reset(time.Minute) // Reset the timer for the next interval
			}
		case <-cache.stopChan:
			return // Graceful shutdown
		}
	}
}

func (cache *ARPCache) Close() {
	if cache.isClosed {
		return
	}
	cache.isClosed = true

	close(cache.stopChan) // Signal the stop channel
	cache.wg.Wait()

	cache.timeoutTimer.Stop()
	log.Println("arp cache stopped.")
}
