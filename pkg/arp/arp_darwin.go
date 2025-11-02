//go:build darwin

// This should work on freebsd, netbsd and openbsd as well (but not tested).

package arp

import (
	"errors"
	"net"

	"github.com/juruen/goarp/arp"
)

// getARPTable is a variable holding the function to retrieve ARP table entries.
// This allows for easy mocking in tests.
var getARPTable = func() ([]arp.Entry, error) {
	return arp.DumpArpTable()
}

// isARPEntryMatch checks if the given ARP entry matches the provided IP address.
func isARPEntryMatch(entry arp.Entry, ip net.IP) bool {
	return entry.IPAddr.Equal(ip)
}

func checkARPTable(ip net.IP, _ *net.Interface) (net.HardwareAddr, error) {
	// On Darwin, we can use the ARP package to check the ARP table
	// but it doesn't support checking for a specific interface.
	// Instead, we can use the system ARP table and filter by interface.
	entries, err := getARPTable()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if isARPEntryMatch(entry, ip) {
			return entry.HwAddr, nil
		}
	}
	return nil, errors.New("no ARP entry found")
}
