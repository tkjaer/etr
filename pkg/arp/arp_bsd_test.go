//go:build darwin || freebsd || netbsd || openbsd

package arp

import (
	"errors"
	"net"
	"testing"

	"github.com/juruen/goarp/arp"
)

func Test_isARPEntryMatch_Darwin(t *testing.T) {
	tests := []struct {
		entryIP net.IP
		testIP  net.IP
		want    bool
	}{
		{net.ParseIP("192.0.2.100"), net.ParseIP("192.0.2.100"), true},
		{net.ParseIP("192.0.2.100"), net.ParseIP("192.0.2.200"), false},
		{net.ParseIP("fe80::1"), net.ParseIP("fe80::1"), true},
		{net.ParseIP("fe80::1"), net.ParseIP("fe80::2"), false},
	}

	for _, tt := range tests {
		entry := arp.Entry{IPAddr: tt.entryIP, HwAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}}
		if got := isARPEntryMatch(entry, tt.testIP); got != tt.want {
			t.Errorf("isARPEntryMatch(%v, %v) = %v, want %v", tt.entryIP, tt.testIP, got, tt.want)
		}
	}
}

func Test_checkARPTable_Darwin(t *testing.T) {
	mac1 := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	mac2 := net.HardwareAddr{0x55, 0x55, 0x55, 0x55, 0x55, 0x55}

	tests := []struct {
		name    string
		ip      net.IP
		table   []arp.Entry
		err     error
		wantMAC net.HardwareAddr
		wantErr bool
	}{
		{"found", net.ParseIP("192.0.2.100").To4(), []arp.Entry{{IPAddr: net.ParseIP("192.0.2.100"), HwAddr: mac1}}, nil, mac1, false},
		{"not found", net.ParseIP("192.0.2.100").To4(), []arp.Entry{{IPAddr: net.ParseIP("192.0.2.200"), HwAddr: mac1}}, nil, nil, true},
		{"empty table", net.ParseIP("192.0.2.100").To4(), []arp.Entry{}, nil, nil, true},
		{"table error", net.ParseIP("192.0.2.100").To4(), nil, errors.New("table error"), nil, true},
		{"multiple entries", net.ParseIP("198.51.100.5").To4(), []arp.Entry{
			{IPAddr: net.ParseIP("198.51.100.1"), HwAddr: mac1},
			{IPAddr: net.ParseIP("198.51.100.5"), HwAddr: mac2},
		}, nil, mac2, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := getARPTable
			getARPTable = func() ([]arp.Entry, error) { return tt.table, tt.err }
			defer func() { getARPTable = orig }()

			mac, err := checkARPTable(tt.ip, nil)

			if (err != nil) != tt.wantErr {
				t.Errorf("checkARPTable() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && (mac == nil || mac.String() != tt.wantMAC.String()) {
				t.Errorf("checkARPTable() = %v, want %v", mac, tt.wantMAC)
			}
		})
	}
}

func Test_checkARPTable_Darwin_RealCall(t *testing.T) {
	mac, err := checkARPTable(net.ParseIP("192.0.2.1").To4(), nil)
	if err == nil && mac == nil {
		t.Error("checkARPTable() returned nil MAC without error")
	}
}
