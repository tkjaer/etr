//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package route

import (
	"net/netip"
	"testing"
)

func TestGet(t *testing.T) {
	tests := []struct {
		name string
		ip   netip.Addr
	}{
		{"IPv4", netip.MustParseAddr("8.8.8.8")},
		{"IPv6", netip.MustParseAddr("2001:4860:4860::8888")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Smoke test - just verify it doesn't panic
			_, err := Get(tt.ip)
			_ = err // Result depends on system routing table
		})
	}
}
