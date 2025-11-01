package ptr

import (
	"net"
	"strings"
	"sync"
	"time"
)

// LookupFunc is a function type for DNS PTR lookups.
// This allows mocking in tests.
type LookupFunc func(ip string) ([]string, error)

// PtrManager handles PTR lookups with simple caching
type PtrManager struct {
	cache      map[string]string
	mu         sync.RWMutex
	lookupFunc LookupFunc
	retries    int
	retryDelay time.Duration
}

// NewPtrManager creates a new PtrManager with default settings
func NewPtrManager() *PtrManager {
	return &PtrManager{
		cache:      make(map[string]string),
		lookupFunc: net.LookupAddr,
		retries:    3,
		retryDelay: 100 * time.Millisecond,
	}
}

// normalizePTR removes the trailing dot from a PTR record
func normalizePTR(ptr string) string {
	return strings.TrimSuffix(ptr, ".")
}

// isCached checks if a PTR record is already cached
func (pm *PtrManager) isCached(ip string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	_, exists := pm.cache[ip]
	return exists
}

// markInProgress marks a lookup as in progress
func (pm *PtrManager) markInProgress(ip string) {
	pm.mu.Lock()
	pm.cache[ip] = ""
	pm.mu.Unlock()
}

// setCached stores a PTR record in the cache
func (pm *PtrManager) setCached(ip, ptr string) {
	pm.mu.Lock()
	pm.cache[ip] = ptr
	pm.mu.Unlock()
}

// performLookup attempts to lookup a PTR record with retries
func (pm *PtrManager) performLookup(ip string) (string, bool) {
	for range pm.retries {
		ptrs, err := pm.lookupFunc(ip)
		if err == nil && len(ptrs) > 0 {
			return normalizePTR(ptrs[0]), true
		}
		if pm.retryDelay > 0 {
			time.Sleep(pm.retryDelay)
		}
	}
	return "", false
}

// RequestPTR initiates a PTR lookup for the given IP address if not cached
func (pm *PtrManager) RequestPTR(ip string) {
	if pm.isCached(ip) {
		return
	}

	pm.markInProgress(ip)

	if ptr, ok := pm.performLookup(ip); ok {
		pm.setCached(ip, ptr)
	}
}

// GetPTR retrieves the cached PTR result for the given IP address
// Returns the PTR and a boolean indicating if it was found
func (pm *PtrManager) GetPTR(ip string) (string, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	ptr, exists := pm.cache[ip]
	if ptr == "" {
		return "", false
	}
	return ptr, exists
}
