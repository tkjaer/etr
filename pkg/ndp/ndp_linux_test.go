//go:build linux
// +build linux

package ndp

import (
	"errors"
	"net"
	"testing"

	"github.com/jsimonetti/rtnetlink/rtnl"
)

func Test_isNeighbourMatch_Linux(t *testing.T) {
	tests := []struct {
		entryIP net.IP
		testIP  net.IP
		want    bool
	}{
		{net.ParseIP("fe80::1"), net.ParseIP("fe80::1"), true},
		{net.ParseIP("fe80::1"), net.ParseIP("fe80::2"), false},
		{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::1"), true},
	}

	for _, tt := range tests {
		n := &rtnl.Neigh{IP: tt.entryIP, HwAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}}
		if got := isNeighbourMatch(n, tt.testIP); got != tt.want {
			t.Errorf("isNeighbourMatch(%v, %v) = %v, want %v", tt.entryIP, tt.testIP, got, tt.want)
		}
	}
}

func Test_checkNeighbourTable_Linux(t *testing.T) {
	mac1 := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	mac2 := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}

	tests := []struct {
		name    string
		ip      net.IP
		neighs  []*rtnl.Neigh
		err     error
		wantMAC net.HardwareAddr
		wantErr bool
	}{
		{
			name: "found",
			ip:   net.ParseIP("fe80::1"),
			neighs: []*rtnl.Neigh{
				{IP: net.ParseIP("fe80::1"), HwAddr: mac1},
			},
			wantMAC: mac1,
			wantErr: false,
		},
		{
			name: "not found",
			ip:   net.ParseIP("fe80::1"),
			neighs: []*rtnl.Neigh{
				{IP: net.ParseIP("fe80::2"), HwAddr: mac1},
			},
			wantErr: true,
		},
		{
			name:    "empty table",
			ip:      net.ParseIP("fe80::1"),
			neighs:  []*rtnl.Neigh{},
			wantErr: true,
		},
		{
			name:    "dial error",
			ip:      net.ParseIP("fe80::1"),
			err:     errors.New("dial error"),
			wantErr: true,
		},
		{
			name: "multiple entries",
			ip:   net.ParseIP("2001:db8::5"),
			neighs: []*rtnl.Neigh{
				{IP: net.ParseIP("2001:db8::1"), HwAddr: mac1},
				{IP: net.ParseIP("2001:db8::5"), HwAddr: mac2},
			},
			wantMAC: mac2,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := getNeighbourTable
			getNeighbourTable = func(iface *net.Interface) ([]*rtnl.Neigh, error) { return tt.neighs, tt.err }
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

func Test_checkNeighbourTable_Linux_RealCall(t *testing.T) {
	mac, err := checkNeighbourTable(net.ParseIP("fe80::1"), nil)
	if err == nil && mac == nil {
		t.Error("checkNeighbourTable() returned nil MAC without error")
	}
}
