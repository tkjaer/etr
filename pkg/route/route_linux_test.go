//go:build linux

package route

import (
	"errors"
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
					Family: unix.AF_INET,
					Attributes: rtnetlink.RouteAttributes{
						Dst:      []byte{}, // Invalid
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getMostSpecificRoute(tt.ip, tt.msgs)

			if (err != nil) != tt.wantErr {
				t.Errorf("getMostSpecificRoute() error = %v, wantErr %v", err, tt.wantErr)
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
