//go:build linux || darwin || freebsd

package ndp

import (
	"net"
	"testing"
)

func TestCheckNeighbourTable(t *testing.T) {
	tests := []struct {
		name  string
		ip    net.IP
		iface *net.Interface
	}{
		{"nil interface", net.ParseIP("fe80::1"), nil},
		{"link-local IPv6", net.ParseIP("fe80::1"), nil},
		{"global IPv6", net.ParseIP("2001:db8::1"), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Smoke test - just verify it doesn't panic
			_, err := CheckNeighbourTable(tt.ip, tt.iface)
			_ = err // Result depends on system state
		})
	}
}

func TestGet(t *testing.T) {
	t.Run("rejects IPv4", func(t *testing.T) {
		_, err := Get(net.ParseIP("192.0.2.1").To4(), nil)
		if err == nil {
			t.Error("Get() should reject IPv4 addresses")
		}
	})

	t.Run("accepts IPv6", func(t *testing.T) {
		// This will fail (no such neighbor) but should not panic
		_, err := Get(net.ParseIP("fe80::1"), nil)
		_ = err // Expected to fail without actual neighbor
	})
}
