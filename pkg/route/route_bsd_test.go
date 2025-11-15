//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package route

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"golang.org/x/net/route"
)

func TestGetMostSpecificRoute_Darwin(t *testing.T) {
	ipv4 := netip.MustParseAddr("192.0.2.100")
	ipv6 := netip.MustParseAddr("2001:db8::100")

	tests := []struct {
		name    string
		ip      netip.Addr
		msgs    []route.Message
		wantErr bool
	}{
		{
			name: "IPv4 host route",
			ip:   ipv4,
			msgs: []route.Message{
				&route.RouteMessage{
					Index: 1,
					Flags: syscall.RTF_UP | syscall.RTF_HOST,
					Addrs: []route.Addr{
						&route.Inet4Addr{IP: [4]byte{192, 0, 2, 100}},     // dest
						&route.Inet4Addr{IP: [4]byte{192, 0, 2, 1}},       // gateway
						&route.Inet4Addr{IP: [4]byte{255, 255, 255, 255}}, // mask
						nil, nil,
						&route.Inet4Addr{IP: [4]byte{192, 0, 2, 10}}, // source
					},
				},
			},
			wantErr: false,
		},
		{
			name: "IPv4 subnet route",
			ip:   ipv4,
			msgs: []route.Message{
				&route.RouteMessage{
					Index: 1,
					Flags: syscall.RTF_UP,
					Addrs: []route.Addr{
						&route.Inet4Addr{IP: [4]byte{192, 0, 2, 0}},     // dest
						&route.Inet4Addr{IP: [4]byte{192, 0, 2, 1}},     // gateway
						&route.Inet4Addr{IP: [4]byte{255, 255, 255, 0}}, // mask
						nil, nil,
						&route.Inet4Addr{IP: [4]byte{192, 0, 2, 10}}, // source
					},
				},
			},
			wantErr: false,
		},
		{
			name: "IPv6 host route",
			ip:   ipv6,
			msgs: []route.Message{
				&route.RouteMessage{
					Index: 1,
					Flags: syscall.RTF_UP | syscall.RTF_HOST,
					Addrs: []route.Addr{
						&route.Inet6Addr{IP: [16]byte(ipv6.As16())},
						&route.Inet6Addr{IP: [16]byte(netip.MustParseAddr("2001:db8::1").As16())},
						&route.Inet6Addr{IP: [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
						nil, nil,
						&route.Inet6Addr{IP: [16]byte(netip.MustParseAddr("2001:db8::10").As16())},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "no matching route",
			ip:   ipv4,
			msgs: []route.Message{
				&route.RouteMessage{
					Index: 1,
					Flags: syscall.RTF_UP,
					Addrs: []route.Addr{
						&route.Inet4Addr{IP: [4]byte{10, 0, 0, 0}},
						&route.Inet4Addr{IP: [4]byte{10, 0, 0, 1}},
						&route.Inet4Addr{IP: [4]byte{255, 0, 0, 0}},
						nil, nil,
						&route.Inet4Addr{IP: [4]byte{10, 0, 0, 10}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "route without UP flag",
			ip:   ipv4,
			msgs: []route.Message{
				&route.RouteMessage{
					Index: 1,
					Flags: 0, // Not RTF_UP
					Addrs: []route.Addr{
						&route.Inet4Addr{IP: [4]byte{192, 0, 2, 0}},
						&route.Inet4Addr{IP: [4]byte{192, 0, 2, 1}},
						&route.Inet4Addr{IP: [4]byte{255, 255, 255, 0}},
						nil, nil,
						&route.Inet4Addr{IP: [4]byte{192, 0, 2, 10}},
					},
				},
			},
			wantErr: true,
		},
		{
			name:    "empty messages",
			ip:      ipv4,
			msgs:    []route.Message{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock interface lookup
			_, err := getMostSpecificRoute(tt.ip, tt.msgs)

			if (err != nil) != tt.wantErr {
				t.Errorf("getMostSpecificRoute() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_get_Darwin(t *testing.T) {
	tests := []struct {
		name    string
		ip      netip.Addr
		msgs    []route.Message
		err     error
		wantErr bool
	}{
		{
			name: "successful fetch",
			ip:   netip.MustParseAddr("192.0.2.1"),
			msgs: []route.Message{
				&route.RouteMessage{
					Index: 1,
					Flags: syscall.RTF_UP | syscall.RTF_HOST,
					Addrs: []route.Addr{
						&route.Inet4Addr{IP: [4]byte{192, 0, 2, 1}},
						&route.Inet4Addr{IP: [4]byte{192, 0, 2, 254}},
						&route.Inet4Addr{IP: [4]byte{255, 255, 255, 255}},
						nil, nil,
						&route.Inet4Addr{IP: [4]byte{192, 0, 2, 10}},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "fetch error",
			ip:      netip.MustParseAddr("192.0.2.1"),
			err:     errors.New("fetch failed"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := fetchRIBMessages
			fetchRIBMessages = func() ([]route.Message, error) { return tt.msgs, tt.err }
			defer func() { fetchRIBMessages = orig }()

			_, err := get(tt.ip)

			if (err != nil) != tt.wantErr {
				t.Errorf("get() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_get_Darwin_RealCall(t *testing.T) {
	// Smoke test with real routing table
	ip := netip.MustParseAddr("8.8.8.8")
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

func Test_getGlobalUnicastIPv6_Darwin(t *testing.T) {
	// Smoke test - verify it doesn't panic and returns correct error when no IPv6
	// This is a real call test that depends on system state
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skip("Cannot get interfaces:", err)
	}

	for _, iface := range ifaces {
		// Test without next hop (should return any global address)
		addr, err := getGlobalUnicastIPv6(&iface, netip.Addr{})
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
