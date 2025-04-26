//go:build darwin
// +build darwin

// This should work on freebsd, netbsd and openbsd as well (but not tested).

package arp

import (
	"errors"
	"net"

	"github.com/juruen/goarp/arp"
)

func checkARPTable(ip net.IP, _ *net.Interface) (net.HardwareAddr, error) {
	// On Darwin, we can use the ARP package to check the ARP table
	// but it doesn't support checking for a specific interface.
	// Instead, we can use the system ARP table and filter by interface.
	entries, err := arp.DumpArpTable()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IPAddr.Equal(ip) {
			return entry.HwAddr, nil
		}
	}
	return nil, errors.New("no ARP entry found")
}
