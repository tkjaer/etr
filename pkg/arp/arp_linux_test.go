//go:build linux
// +build linux

package arp

import (
	"errors"
	"net"
	"testing"

	"github.com/jsimonetti/rtnetlink/rtnl"
)

func Test_isARPEntryMatch_Linux(t *testing.T) {
	tests := []struct {
		name      string
		entry     *rtnl.Neigh
		ip        net.IP
		wantMatch bool
	}{
		{
			name: "matching IPv4",
			entry: &rtnl.Neigh{
				IP:     net.ParseIP("192.0.2.100"),
				HwAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			},
			ip:        net.ParseIP("192.0.2.100"),
			wantMatch: true,
		},
		{
			name: "non-matching IPv4",
			entry: &rtnl.Neigh{
				IP:     net.ParseIP("192.0.2.100"),
				HwAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			},
			ip:        net.ParseIP("192.0.2.200"),
			wantMatch: false,
		},
		{
			name: "matching IPv6",
			entry: &rtnl.Neigh{
				IP:     net.ParseIP("fe80::1"),
				HwAddr: net.HardwareAddr{0xfe, 0xed, 0xbe, 0xef, 0xca, 0xfe},
			},
			ip:        net.ParseIP("fe80::1"),
			wantMatch: true,
		},
		{
			name: "non-matching IPv6",
			entry: &rtnl.Neigh{
				IP:     net.ParseIP("fe80::1"),
				HwAddr: net.HardwareAddr{0xfe, 0xed, 0xbe, 0xef, 0xca, 0xfe},
			},
			ip:        net.ParseIP("fe80::2"),
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isARPEntryMatch(tt.entry, tt.ip)
			if got != tt.wantMatch {
				t.Errorf("isARPEntryMatch() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func Test_checkARPTable_Linux(t *testing.T) {
	tests := []struct {
		name          string
		ip            net.IP
		iface         *net.Interface
		mockNeighbors []*rtnl.Neigh
		mockError     error
		wantMAC       net.HardwareAddr
		wantErr       bool
		errMessage    string
	}{
		{
			name:  "entry found in table",
			ip:    net.ParseIP("192.0.2.100").To4(),
			iface: nil,
			mockNeighbors: []*rtnl.Neigh{
				{
					IP:     net.ParseIP("192.0.2.100"),
					HwAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
				},
			},
			mockError:  nil,
			wantMAC:    net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			wantErr:    false,
			errMessage: "",
		},
		{
			name:  "entry not found in table",
			ip:    net.ParseIP("192.0.2.100").To4(),
			iface: nil,
			mockNeighbors: []*rtnl.Neigh{
				{
					IP:     net.ParseIP("192.0.2.200"),
					HwAddr: net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
				},
			},
			mockError:  nil,
			wantMAC:    nil,
			wantErr:    true,
			errMessage: "no ARP entry found",
		},
		{
			name:          "empty neighbor table",
			ip:            net.ParseIP("192.0.2.100").To4(),
			iface:         nil,
			mockNeighbors: []*rtnl.Neigh{},
			mockError:     nil,
			wantMAC:       nil,
			wantErr:       true,
			errMessage:    "no ARP entry found",
		},
		{
			name:          "error retrieving neighbors",
			ip:            net.ParseIP("192.0.2.100").To4(),
			iface:         nil,
			mockNeighbors: nil,
			mockError:     errors.New("failed to dial rtnetlink"),
			wantMAC:       nil,
			wantErr:       true,
			errMessage:    "failed to dial rtnetlink",
		},
		{
			name:  "multiple entries, match found",
			ip:    net.ParseIP("198.51.100.5").To4(),
			iface: nil,
			mockNeighbors: []*rtnl.Neigh{
				{
					IP:     net.ParseIP("198.51.100.1"),
					HwAddr: net.HardwareAddr{0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
				},
				{
					IP:     net.ParseIP("198.51.100.5"),
					HwAddr: net.HardwareAddr{0x55, 0x55, 0x55, 0x55, 0x55, 0x55},
				},
				{
					IP:     net.ParseIP("198.51.100.10"),
					HwAddr: net.HardwareAddr{0x10, 0x10, 0x10, 0x10, 0x10, 0x10},
				},
			},
			mockError:  nil,
			wantMAC:    net.HardwareAddr{0x55, 0x55, 0x55, 0x55, 0x55, 0x55},
			wantErr:    false,
			errMessage: "",
		},
		{
			name:  "IPv6 neighbor",
			ip:    net.ParseIP("fe80::1"),
			iface: nil,
			mockNeighbors: []*rtnl.Neigh{
				{
					IP:     net.ParseIP("fe80::1"),
					HwAddr: net.HardwareAddr{0xfe, 0xed, 0xbe, 0xef, 0xca, 0xfe},
				},
			},
			mockError:  nil,
			wantMAC:    net.HardwareAddr{0xfe, 0xed, 0xbe, 0xef, 0xca, 0xfe},
			wantErr:    false,
			errMessage: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock the getARPTable function
			originalGetARPTable := getARPTable
			getARPTable = func(iface *net.Interface) ([]*rtnl.Neigh, error) {
				return tt.mockNeighbors, tt.mockError
			}
			defer func() { getARPTable = originalGetARPTable }()

			// Call the function under test
			mac, err := checkARPTable(tt.ip, tt.iface) // Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("checkARPTable() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check error message if we expect an error
			if tt.wantErr && err != nil && tt.errMessage != "" {
				if err.Error() != tt.errMessage {
					t.Errorf("checkARPTable() error message = %q, want %q", err.Error(), tt.errMessage)
				}
			}

			// Check MAC address
			if !tt.wantErr {
				if mac == nil {
					t.Error("checkARPTable() returned nil MAC without error")
				} else if mac.String() != tt.wantMAC.String() {
					t.Errorf("checkARPTable() MAC = %v, want %v", mac, tt.wantMAC)
				}
			}
		})
	}
}

func Test_checkARPTable_Linux_RealCall(t *testing.T) {
	// This test makes a real call to the system neighbor table
	// It's a smoke test to ensure the real getNeighbours function works

	ip := net.ParseIP("192.0.2.1").To4()

	// This should not panic even with a real call
	mac, err := checkARPTable(ip, nil)

	// We don't know if the entry exists, so we just check it doesn't panic
	// and that if there's no error, we have a MAC
	if err == nil && mac == nil {
		t.Error("checkARPTable() returned nil MAC without error")
	}

	// If it succeeded, log the result for informational purposes
	if err == nil {
		t.Logf("Found neighbor entry: %s -> %s", ip, mac)
	} else {
		t.Logf("No neighbor entry found (expected): %v", err)
	}
}
