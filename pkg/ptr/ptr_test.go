package ptr

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func Test_normalizePTR(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "PTR with trailing dot",
			input: "example.com.",
			want:  "example.com",
		},
		{
			name:  "PTR without trailing dot",
			input: "example.com",
			want:  "example.com",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "just a dot",
			input: ".",
			want:  "",
		},
		{
			name:  "multiple dots at end",
			input: "example.com..",
			want:  "example.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePTR(tt.input)
			if got != tt.want {
				t.Errorf("normalizePTR() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewPtrManager(t *testing.T) {
	pm := NewPtrManager()

	if pm == nil {
		t.Fatal("NewPtrManager() returned nil")
	}

	if pm.cache == nil {
		t.Error("cache is nil")
	}

	if pm.lookupFunc == nil {
		t.Error("lookupFunc is nil")
	}

	if pm.retries != 3 {
		t.Errorf("retries = %d, want 3", pm.retries)
	}

	if pm.retryDelay != 100*time.Millisecond {
		t.Errorf("retryDelay = %v, want 100ms", pm.retryDelay)
	}
}

func TestPtrManager_isCached(t *testing.T) {
	pm := NewPtrManager()

	// Empty cache
	if pm.isCached("192.0.2.1") {
		t.Error("isCached() should return false for empty cache")
	}

	// Add entry
	pm.cache["192.0.2.1"] = "example.com"
	if !pm.isCached("192.0.2.1") {
		t.Error("isCached() should return true for cached entry")
	}

	// In-progress entry (empty string)
	pm.cache["192.0.2.2"] = ""
	if !pm.isCached("192.0.2.2") {
		t.Error("isCached() should return true for in-progress entry")
	}
}

func TestPtrManager_markInProgress(t *testing.T) {
	pm := NewPtrManager()

	pm.markInProgress("192.0.2.1")

	pm.mu.RLock()
	val, exists := pm.cache["192.0.2.1"]
	pm.mu.RUnlock()

	if !exists {
		t.Error("markInProgress() did not add entry to cache")
	}

	if val != "" {
		t.Errorf("markInProgress() set value to %q, want empty string", val)
	}
}

func TestPtrManager_setCached(t *testing.T) {
	pm := NewPtrManager()

	pm.setCached("192.0.2.1", "example.com")

	pm.mu.RLock()
	val, exists := pm.cache["192.0.2.1"]
	pm.mu.RUnlock()

	if !exists {
		t.Error("setCached() did not add entry to cache")
	}

	if val != "example.com" {
		t.Errorf("setCached() set value to %q, want %q", val, "example.com")
	}
}

func TestPtrManager_performLookup(t *testing.T) {
	tests := []struct {
		name       string
		mockFunc   LookupFunc
		retries    int
		retryDelay time.Duration
		wantPTR    string
		wantOK     bool
	}{
		{
			name: "successful lookup first try",
			mockFunc: func(ip string) ([]string, error) {
				return []string{"example.com."}, nil
			},
			retries:    3,
			retryDelay: 0,
			wantPTR:    "example.com",
			wantOK:     true,
		},
		{
			name: "successful lookup without trailing dot",
			mockFunc: func(ip string) ([]string, error) {
				return []string{"example.com"}, nil
			},
			retries:    3,
			retryDelay: 0,
			wantPTR:    "example.com",
			wantOK:     true,
		},
		{
			name: "lookup fails all attempts",
			mockFunc: func(ip string) ([]string, error) {
				return nil, errors.New("lookup failed")
			},
			retries:    3,
			retryDelay: 0,
			wantPTR:    "",
			wantOK:     false,
		},
		{
			name: "empty result",
			mockFunc: func(ip string) ([]string, error) {
				return []string{}, nil
			},
			retries:    3,
			retryDelay: 0,
			wantPTR:    "",
			wantOK:     false,
		},
		{
			name: "retry succeeds on second attempt",
			mockFunc: func() LookupFunc {
				attempts := 0
				return func(ip string) ([]string, error) {
					attempts++
					if attempts == 1 {
						return nil, errors.New("first attempt fails")
					}
					return []string{"example.com."}, nil
				}
			}(),
			retries:    3,
			retryDelay: 0,
			wantPTR:    "example.com",
			wantOK:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &PtrManager{
				cache:      make(map[string]string),
				lookupFunc: tt.mockFunc,
				retries:    tt.retries,
				retryDelay: tt.retryDelay,
			}

			gotPTR, gotOK := pm.performLookup("192.0.2.1")

			if gotPTR != tt.wantPTR {
				t.Errorf("performLookup() PTR = %q, want %q", gotPTR, tt.wantPTR)
			}

			if gotOK != tt.wantOK {
				t.Errorf("performLookup() OK = %v, want %v", gotOK, tt.wantOK)
			}
		})
	}
}

func TestPtrManager_RequestPTR(t *testing.T) {
	tests := []struct {
		name       string
		ip         string
		mockFunc   LookupFunc
		preCache   map[string]string
		wantCached string
	}{
		{
			name: "successful lookup",
			ip:   "192.0.2.1",
			mockFunc: func(ip string) ([]string, error) {
				return []string{"example.com."}, nil
			},
			preCache:   nil,
			wantCached: "example.com",
		},
		{
			name:       "already cached - skips lookup",
			ip:         "192.0.2.1",
			mockFunc:   func(ip string) ([]string, error) { panic("should not be called") },
			preCache:   map[string]string{"192.0.2.1": "cached.com"},
			wantCached: "cached.com",
		},
		{
			name: "lookup fails",
			ip:   "192.0.2.1",
			mockFunc: func(ip string) ([]string, error) {
				return nil, errors.New("lookup failed")
			},
			preCache:   nil,
			wantCached: "", // In-progress marker remains
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &PtrManager{
				cache:      make(map[string]string),
				lookupFunc: tt.mockFunc,
				retries:    3,
				retryDelay: 0,
			}

			// Pre-populate cache if needed
			if tt.preCache != nil {
				for k, v := range tt.preCache {
					pm.cache[k] = v
				}
			}

			pm.RequestPTR(tt.ip)

			pm.mu.RLock()
			cached := pm.cache[tt.ip]
			pm.mu.RUnlock()

			if cached != tt.wantCached {
				t.Errorf("RequestPTR() cached = %q, want %q", cached, tt.wantCached)
			}
		})
	}
}

func TestPtrManager_GetPTR(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		cache     map[string]string
		wantPTR   string
		wantFound bool
	}{
		{
			name:      "found in cache",
			ip:        "192.0.2.1",
			cache:     map[string]string{"192.0.2.1": "example.com"},
			wantPTR:   "example.com",
			wantFound: true,
		},
		{
			name:      "not in cache",
			ip:        "192.0.2.1",
			cache:     map[string]string{},
			wantPTR:   "",
			wantFound: false,
		},
		{
			name:      "in-progress (empty string)",
			ip:        "192.0.2.1",
			cache:     map[string]string{"192.0.2.1": ""},
			wantPTR:   "",
			wantFound: false,
		},
		{
			name:      "different IP in cache",
			ip:        "192.0.2.1",
			cache:     map[string]string{"192.0.2.2": "other.com"},
			wantPTR:   "",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &PtrManager{
				cache: tt.cache,
			}

			gotPTR, gotFound := pm.GetPTR(tt.ip)

			if gotPTR != tt.wantPTR {
				t.Errorf("GetPTR() PTR = %q, want %q", gotPTR, tt.wantPTR)
			}

			if gotFound != tt.wantFound {
				t.Errorf("GetPTR() found = %v, want %v", gotFound, tt.wantFound)
			}
		})
	}
}

func TestPtrManager_Concurrency(t *testing.T) {
	// Test concurrent access to ensure no race conditions
	pm := &PtrManager{
		cache: make(map[string]string),
		lookupFunc: func(ip string) ([]string, error) {
			time.Sleep(1 * time.Millisecond) // Simulate network delay
			return []string{ip + ".example.com."}, nil
		},
		retries:    1,
		retryDelay: 0,
	}

	var wg sync.WaitGroup
	ips := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"}

	// Launch multiple goroutines
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for _, ip := range ips {
				pm.RequestPTR(ip)
				pm.GetPTR(ip)
			}
		}(i)
	}

	wg.Wait()

	// Verify all IPs were processed
	for _, ip := range ips {
		ptr, found := pm.GetPTR(ip)
		if !found {
			t.Errorf("IP %s not found in cache after concurrent operations", ip)
		}
		expectedPTR := ip + ".example.com"
		if ptr != expectedPTR {
			t.Errorf("IP %s has PTR %q, want %q", ip, ptr, expectedPTR)
		}
	}
}

func BenchmarkPtrManager_RequestPTR(b *testing.B) {
	pm := &PtrManager{
		cache: make(map[string]string),
		lookupFunc: func(ip string) ([]string, error) {
			return []string{"example.com."}, nil
		},
		retries:    3,
		retryDelay: 0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := "192.0.2.1"
		pm.RequestPTR(ip)
	}
}

func BenchmarkPtrManager_GetPTR(b *testing.B) {
	pm := &PtrManager{
		cache: map[string]string{
			"192.0.2.1": "example.com",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pm.GetPTR("192.0.2.1")
	}
}

func BenchmarkPtrManager_normalizePTR(b *testing.B) {
	ptr := "example.com."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = normalizePTR(ptr)
	}
}
