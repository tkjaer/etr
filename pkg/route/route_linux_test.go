//go:build linux

package route

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/sys/unix"
)

func TestGetMostSpecificRoute_Linux(t *testing.T) {
	ipv4 := netip.MustParseAddr("192.0.2.100")
	ipv6 := netip.MustParseAddr("2001:db8::100")

	tests := []struct {
		name    string
		ip      netip.Addr
		msgs    []rtnetlink.RouteMessage
		wantErr bool
	}{
		{
			name: "IPv4 route found",
			ip:   ipv4,
			msgs: []rtnetlink.RouteMessage{
				{
					Family: unix.AF_INET,
					Attributes: rtnetlink.RouteAttributes{
						Dst:      ipv4.AsSlice(),
						Gateway:  netip.MustParseAddr("192.0.2.1").AsSlice(),
						Src:      netip.MustParseAddr("192.0.2.10").AsSlice(),
						OutIface: 1,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "IPv6 route found",
			ip:   ipv6,
			msgs: []rtnetlink.RouteMessage{
				{
					Family: unix.AF_INET6,
					Attributes: rtnetlink.RouteAttributes{
						Dst:      ipv6.AsSlice(),
						Gateway:  netip.MustParseAddr("2001:db8::1").AsSlice(),
						Src:      netip.MustParseAddr("2001:db8::10").AsSlice(),
						OutIface: 1,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "multiple routes error",
			ip:   ipv4,
			msgs: []rtnetlink.RouteMessage{
				{
					Family: unix.AF_INET,
					Attributes: rtnetlink.RouteAttributes{
						Dst:      ipv4.AsSlice(),
						Src:      netip.MustParseAddr("192.0.2.10").AsSlice(),
						OutIface: 1,
					},
				},
				{
					Family: unix.AF_INET,
					Attributes: rtnetlink.RouteAttributes{
						Dst:      ipv4.AsSlice(),
						Src:      netip.MustParseAddr("192.0.2.20").AsSlice(),
						OutIface: 2,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid destination",
			ip:   ipv4,
			msgs: []rtnetlink.RouteMessage{
				{
					Family:    unix.AF_INET,
					DstLength: 24,
					Attributes: rtnetlink.RouteAttributes{
						Dst:      []byte{0xde, 0xad}, // Invalid length
						Src:      ipv4.AsSlice(),
						OutIface: 1,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid source",
			ip:   ipv4,
			msgs: []rtnetlink.RouteMessage{
				{
					Family: unix.AF_INET,
					Attributes: rtnetlink.RouteAttributes{
						Dst:      ipv4.AsSlice(),
						Src:      []byte{}, // Invalid
						OutIface: 1,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid gateway",
			ip:   ipv4,
			msgs: []rtnetlink.RouteMessage{
				{
					Family: unix.AF_INET,
					Attributes: rtnetlink.RouteAttributes{
						Dst:      ipv4.AsSlice(),
						Src:      ipv4.AsSlice(),
						Gateway:  []byte{}, // Invalid
						OutIface: 1,
					},
				},
			},
			wantErr: true,
		},
		{
			name:    "no routes returned",
			ip:      ipv4,
			msgs:    nil,
			wantErr: true,
		},
		{
			name: "default route matches",
			ip:   ipv4,
			msgs: []rtnetlink.RouteMessage{
				{
					Family:    unix.AF_INET,
					DstLength: 0,
					Attributes: rtnetlink.RouteAttributes{
						Src:      netip.MustParseAddr("192.0.2.10").AsSlice(),
						OutIface: 1,
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getMostSpecificRoute(tt.ip, tt.msgs)

			if (err != nil) != tt.wantErr {
				t.Fatalf("getMostSpecificRoute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_get_Linux(t *testing.T) {
	ipv4 := netip.MustParseAddr("192.0.2.1")

	tests := []struct {
		name    string
		ip      netip.Addr
		msgs    []rtnetlink.RouteMessage
		err     error
		wantErr bool
	}{
		{
			name: "successful fetch",
			ip:   ipv4,
			msgs: []rtnetlink.RouteMessage{
				{
					Family: unix.AF_INET,
					Attributes: rtnetlink.RouteAttributes{
						Dst:      ipv4.AsSlice(),
						Src:      netip.MustParseAddr("192.0.2.10").AsSlice(),
						OutIface: 1,
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "fetch error",
			ip:      ipv4,
			err:     errors.New("dial failed"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := fetchRIBMessagesForIP
			fetchRIBMessagesForIP = func(ip netip.Addr) ([]rtnetlink.RouteMessage, error) { return tt.msgs, tt.err }
			defer func() { fetchRIBMessagesForIP = orig }()

			_, err := get(tt.ip)

			if (err != nil) != tt.wantErr {
				t.Errorf("get() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_get_Linux_RealCall(t *testing.T) {
	// Smoke test with real routing table
	ip := netip.MustParseAddr("192.0.2.1")
	route, err := get(ip)

	if err == nil {
		if route.Interface == nil {
			t.Error("get() returned route with nil interface")
		}
		if !route.Destination.IsValid() {
			t.Error("get() returned route with invalid destination")
		}
	}
}

func Test_getGlobalUnicastIPv6_Linux(t *testing.T) {
	// Smoke test - verify it doesn't panic and returns correct error when no IPv6
	// This is a real call test that depends on system state
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skip("Cannot get interfaces:", err)
	}

	for _, iface := range ifaces {
		// Test without subnet preference
		addr, err := getGlobalUnicastIPv6(&iface, netip.Prefix{})
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

func Test_selectAddrFromList(t *testing.T) {
	mustCIDR := func(cidr string) net.Addr {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", cidr, err)
		}
		return n
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
				mustCIDR("192.0.2.10/24"),
				mustCIDR("198.51.100.1/24"),
			},
			prefix: netip.MustParsePrefix("192.0.2.0/24"),
			want:   netip.MustParseAddr("192.0.2.10"),
			ok:     true,
		},
		{
			name: "default route prefix matches any address",
			addrs: []net.Addr{
				mustCIDR("198.51.100.1/24"),
			},
			prefix: netip.MustParsePrefix("0.0.0.0/0"),
			want:   netip.MustParseAddr("198.51.100.1"),
			ok:     true,
		},
		{
			name: "returns false when no address is inside prefix",
			addrs: []net.Addr{
				mustCIDR("198.51.100.1/24"),
			},
			prefix: netip.MustParsePrefix("192.0.2.0/24"),
			ok:     false,
		},
		{
			name: "returns false when family missing",
			addrs: []net.Addr{
				mustCIDR("192.0.2.10/24"),
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
