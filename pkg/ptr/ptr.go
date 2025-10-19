package ptr

import (
	"net"
	"sync"
	"time"
)

// PtrManager handles PTR lookups with simple caching
type PtrManager struct {
	cache map[string]string
	mu    sync.RWMutex
}

// NewPtrManager creates a new PtrManager
func NewPtrManager() *PtrManager {
	return &PtrManager{
		cache: make(map[string]string),
	}
}

// RequestPTR initiates a PTR lookup for the given IP address if not cached
func (pm *PtrManager) RequestPTR(ip string) {
	pm.mu.Lock()
	if _, exists := pm.cache[ip]; exists {
		pm.mu.Unlock()
		return
	}
	pm.cache[ip] = "" // Mark as "in progress" to avoid duplicate lookups
	pm.mu.Unlock()

	attempts := 3
	for range attempts {
		ptr, err := net.LookupAddr(ip)
		if err == nil && len(ptr) > 0 {
			pm.mu.Lock()
			pm.cache[ip] = ptr[0][:len(ptr[0])-1] // Remove trailing dot
			pm.mu.Unlock()
			return
		}
		time.Sleep(100 * time.Millisecond) // Retry after a short delay
	}
}

// GetPTR retrieves the cached PTR result for the given IP address
// Returns the PTR and a boolean indicating if it was found
func (pm *PtrManager) GetPTR(ip string) (string, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	ptr, exists := pm.cache[ip]
	if ptr == "" {
		return ptr, false
	}
	return ptr, exists
}
