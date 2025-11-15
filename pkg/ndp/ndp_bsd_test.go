//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package ndp

import (
	"errors"
	"net"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func Test_isNeighbourMatch_Darwin(t *testing.T) {
	ipv6 := net.ParseIP("fe80::1")
	ipv4 := net.ParseIP("192.0.2.1")

	tests := []struct {
		name string
		msg  route.Message
		ip   net.IP
		want bool
	}{
		{
			name: "matching IPv6",
			msg: &route.RouteMessage{
				Flags: unix.RTF_LLINFO,
				Addrs: []route.Addr{
					&route.Inet6Addr{IP: [16]byte(ipv6.To16())},
					&route.LinkAddr{Addr: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
				},
			},
			ip:   ipv6,
			want: true,
		},
		{
			name: "non-matching IPv6",
			msg: &route.RouteMessage{
				Flags: unix.RTF_LLINFO,
				Addrs: []route.Addr{
					&route.Inet6Addr{IP: [16]byte(net.ParseIP("fe80::2").To16())},
					&route.LinkAddr{Addr: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
				},
			},
			ip:   ipv6,
			want: false,
		},
		{
			name: "matching IPv4",
			msg: &route.RouteMessage{
				Flags: unix.RTF_LLINFO,
				Addrs: []route.Addr{
					&route.Inet4Addr{IP: [4]byte{192, 0, 2, 1}},
					&route.LinkAddr{Addr: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
				},
			},
			ip:   ipv4,
			want: true,
		},
		{
			name: "no LLINFO flag",
			msg: &route.RouteMessage{
				Flags: 0,
				Addrs: []route.Addr{
					&route.Inet6Addr{IP: [16]byte(ipv6.To16())},
				},
			},
			ip:   ipv6,
			want: false,
		},
		{
			name: "not a route message",
			msg:  &route.InterfaceMessage{},
			ip:   ipv6,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNeighbourMatch(tt.msg, tt.ip); got != tt.want {
				t.Errorf("isNeighbourMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_checkNeighbourTable_Darwin(t *testing.T) {
	mac1 := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	ipv6 := net.ParseIP("fe80::1")

	tests := []struct {
		name    string
		ip      net.IP
		msgs    []route.Message
		err     error
		wantMAC net.HardwareAddr
		wantErr bool
	}{
		{
			name: "found",
			ip:   ipv6,
			msgs: []route.Message{
				&route.RouteMessage{
					Flags: unix.RTF_LLINFO,
					Addrs: []route.Addr{
						&route.Inet6Addr{IP: [16]byte(ipv6.To16())},
						&route.LinkAddr{Addr: []byte(mac1)},
					},
				},
			},
			wantMAC: mac1,
			wantErr: false,
		},
		{
			name: "not found",
			ip:   ipv6,
			msgs: []route.Message{
				&route.RouteMessage{
					Flags: unix.RTF_LLINFO,
					Addrs: []route.Addr{
						&route.Inet6Addr{IP: [16]byte(net.ParseIP("fe80::2").To16())},
						&route.LinkAddr{Addr: []byte(mac1)},
					},
				},
			},
			wantErr: true,
		},
		{
			name:    "empty table",
			ip:      ipv6,
			msgs:    []route.Message{},
			wantErr: true,
		},
		{
			name:    "table error",
			ip:      ipv6,
			err:     errors.New("fetch error"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := getNeighbourTable
			getNeighbourTable = func() ([]route.Message, error) { return tt.msgs, tt.err }
			defer func() { getNeighbourTable = orig }()

			mac, err := checkNeighbourTable(tt.ip, nil)

			if (err != nil) != tt.wantErr {
				t.Errorf("checkNeighbourTable() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && (mac == nil || mac.String() != tt.wantMAC.String()) {
				t.Errorf("checkNeighbourTable() = %v, want %v", mac, tt.wantMAC)
			}
		})
	}
}

func Test_checkNeighbourTable_Darwin_RealCall(t *testing.T) {
	mac, err := checkNeighbourTable(net.ParseIP("fe80::1"), nil)
	if err == nil && mac == nil {
		t.Error("checkNeighbourTable() returned nil MAC without error")
	}
}
