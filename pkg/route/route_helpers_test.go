//go:build linux || darwin || freebsd || netbsd || openbsd

package route

import (
	"net"
	"net/netip"
	"testing"
)

func Test_selectAddrFromList(t *testing.T) {
	newIPNet := func(addr string, prefixLen int) net.Addr {
		ip := net.ParseIP(addr)
		if ip == nil {
			t.Fatalf("failed to parse ip %s", addr)
		}
		var bits int
		if v4 := ip.To4(); v4 != nil {
			ip = v4
			bits = 32
		} else {
			bits = 128
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(prefixLen, bits)}
	}

	tests := []struct {
		name     string
		addrs    []net.Addr
		wantIPv6 bool
		prefix   netip.Prefix
		want     netip.Addr
		ok       bool
	}{
		{
			name: "prefers address inside prefix",
			addrs: []net.Addr{
				newIPNet("192.0.2.10", 24),
				newIPNet("198.51.100.1", 24),
			},
			prefix: netip.MustParsePrefix("192.0.2.0/24"),
			want:   netip.MustParseAddr("192.0.2.10"),
			ok:     true,
		},
		{
			name: "default route prefix matches any address",
			addrs: []net.Addr{
				newIPNet("198.51.100.1", 24),
			},
			prefix: netip.MustParsePrefix("0.0.0.0/0"),
			want:   netip.MustParseAddr("198.51.100.1"),
			ok:     true,
		},
		{
			name: "returns false when no address is inside prefix",
			addrs: []net.Addr{
				newIPNet("198.51.100.1", 24),
			},
			prefix: netip.MustParsePrefix("192.0.2.0/24"),
			ok:     false,
		},
		{
			name: "returns false when family missing",
			addrs: []net.Addr{
				newIPNet("192.0.2.10", 24),
			},
			wantIPv6: true,
			ok:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := selectAddrFromList(tt.addrs, tt.wantIPv6, tt.prefix)
			if ok != tt.ok {
				t.Fatalf("selectAddrFromList() ok = %v, want %v", ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Fatalf("selectAddrFromList() = %s, want %s", got, tt.want)
			}
		})
	}
}

func Test_getGlobalUnicastIPv6_Smoke(t *testing.T) {
	// Smoke test - verify it doesn't panic and returns correct error when no IPv6
	// This is a real call test that depends on system state
	if testing.Short() {
		t.Skip("skipping IPv6 global source smoke test in short mode")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skip("Cannot get interfaces:", err)
	}

	for _, iface := range ifaces {
		// Test without subnet preference
		addr, err := getGlobalUnicastIPv6(&iface, netip.Prefix{}, netip.Addr{})
		if err == nil {
			// If we found an address, verify it's actually global unicast
			if !addr.IsGlobalUnicast() {
				t.Errorf("getGlobalUnicastIPv6(%s) returned non-global address: %v", iface.Name, addr)
			}
			if addr.IsLinkLocalUnicast() {
				t.Errorf("getGlobalUnicastIPv6(%s) returned link-local address: %v", iface.Name, addr)
			}
			if !addr.Is6() {
				t.Errorf("getGlobalUnicastIPv6(%s) returned non-IPv6 address: %v", iface.Name, addr)
			}
		}
		// Error is expected for interfaces without global IPv6
	}
}
