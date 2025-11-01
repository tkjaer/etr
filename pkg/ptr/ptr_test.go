package ptr

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func Test_normalizePTR(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com.", "example.com"},
		{"example.com", "example.com"},
		{"", ""},
		{".", ""},
	}

	for _, tt := range tests {
		if got := normalizePTR(tt.input); got != tt.want {
			t.Errorf("normalizePTR(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNewPtrManager(t *testing.T) {
	pm := NewPtrManager()

	if pm == nil || pm.cache == nil || pm.lookupFunc == nil {
		t.Fatal("NewPtrManager() returned invalid manager")
	}

	if pm.retries != 3 || pm.retryDelay != 100*time.Millisecond {
		t.Errorf("NewPtrManager() retries=%d delay=%v, want 3 and 100ms", pm.retries, pm.retryDelay)
	}
}

func TestPtrManager_RequestPTR(t *testing.T) {
	t.Run("successful lookup and cache", func(t *testing.T) {
		pm := &PtrManager{
			cache: make(map[string]string),
			lookupFunc: func(ip string) ([]string, error) {
				return []string{"example.com."}, nil
			},
			retries:    1,
			retryDelay: 0,
		}

		pm.RequestPTR("192.0.2.1")

		if ptr, found := pm.GetPTR("192.0.2.1"); !found || ptr != "example.com" {
			t.Errorf("GetPTR() = (%q, %v), want (\"example.com\", true)", ptr, found)
		}
	})

	t.Run("already cached skips lookup", func(t *testing.T) {
		pm := &PtrManager{
			cache: map[string]string{"192.0.2.1": "cached.com"},
			lookupFunc: func(ip string) ([]string, error) {
				t.Fatal("lookupFunc should not be called for cached IP")
				return nil, nil
			},
			retries:    1,
			retryDelay: 0,
		}

		pm.RequestPTR("192.0.2.1")

		if ptr, _ := pm.GetPTR("192.0.2.1"); ptr != "cached.com" {
			t.Errorf("GetPTR() = %q, want \"cached.com\"", ptr)
		}
	})

	t.Run("failed lookup marks in progress", func(t *testing.T) {
		pm := &PtrManager{
			cache: make(map[string]string),
			lookupFunc: func(ip string) ([]string, error) {
				return nil, errors.New("lookup failed")
			},
			retries:    1,
			retryDelay: 0,
		}

		pm.RequestPTR("192.0.2.1")

		if ptr, found := pm.GetPTR("192.0.2.1"); found {
			t.Errorf("GetPTR() = (%q, %v), want empty and not found", ptr, found)
		}
	})
}

func TestPtrManager_GetPTR(t *testing.T) {
	tests := []struct {
		name      string
		cache     map[string]string
		ip        string
		wantPTR   string
		wantFound bool
	}{
		{"found", map[string]string{"192.0.2.1": "example.com"}, "192.0.2.1", "example.com", true},
		{"not found", map[string]string{}, "192.0.2.1", "", false},
		{"in progress", map[string]string{"192.0.2.1": ""}, "192.0.2.1", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := &PtrManager{cache: tt.cache}
			ptr, found := pm.GetPTR(tt.ip)

			if ptr != tt.wantPTR || found != tt.wantFound {
				t.Errorf("GetPTR() = (%q, %v), want (%q, %v)", ptr, found, tt.wantPTR, tt.wantFound)
			}
		})
	}
}

func TestPtrManager_Concurrency(t *testing.T) {
	pm := &PtrManager{
		cache: make(map[string]string),
		lookupFunc: func(ip string) ([]string, error) {
			time.Sleep(time.Millisecond)
			return []string{ip + ".example.com."}, nil
		},
		retries:    1,
		retryDelay: 0,
	}

	var wg sync.WaitGroup
	ips := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}

	// Concurrent requests for same IPs
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, ip := range ips {
				pm.RequestPTR(ip)
				pm.GetPTR(ip)
			}
		}()
	}

	wg.Wait()

	// Verify all lookups completed
	for _, ip := range ips {
		if ptr, found := pm.GetPTR(ip); !found || ptr != ip+".example.com" {
			t.Errorf("IP %s: GetPTR() = (%q, %v), want (%q, true)", ip, ptr, found, ip+".example.com")
		}
	}
}
