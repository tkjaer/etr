//go:build linux || darwin
// +build linux darwin

package arp

import (
	"net"
	"testing"
)

// TestCheckARPTable is a smoke test for the CheckARPTable function.
// This function wraps platform-specific implementations that require
// network state and privileges, so we can't test actual ARP lookups reliably.
func TestCheckARPTable(t *testing.T) {
	tests := []struct {
		name  string
		ip    net.IP
		iface *net.Interface
	}{
		{
			name:  "nil interface",
			ip:    net.ParseIP("192.0.2.1"),
			iface: nil,
		},
		{
			name:  "TEST-NET-1 IPv4",
			ip:    net.ParseIP("192.0.2.1").To4(),
			iface: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call the function - we just verify it doesn't panic
			_, err := CheckARPTable(tt.ip, tt.iface)
			_ = err // Result depends on system state
		})
	}
}
