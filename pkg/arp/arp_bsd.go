//go:build darwin || dragonfly || freebsd || netbsd || openbsd

// This should work on netbsd and openbsd as well (but not tested).

package arp

import (
	"errors"
	"log/slog"
	"net"

	"github.com/juruen/goarp/arp"
)

// getARPTable is a variable holding the function to retrieve ARP table entries.
// This allows for easy mocking in tests.
var getARPTable = func() ([]arp.Entry, error) {
	slog.Debug("Retrieving ARP table using goarp package")
	return arp.DumpArpTable()
}

// isARPEntryMatch checks if the given ARP entry matches the provided IP address.
func isARPEntryMatch(entry arp.Entry, ip net.IP) bool {
	slog.Debug("Comparing ARP entry IP with target IP", "entry_ip", entry.IPAddr.String(), "target_ip", ip.String())
	return entry.IPAddr.Equal(ip)
}

func checkARPTable(ip net.IP, _ *net.Interface) (net.HardwareAddr, error) {
	// On Darwin, we can use the ARP package to check the ARP table
	// but it doesn't support checking for a specific interface.
	// Instead, we can use the system ARP table and filter by interface.
	slog.Debug("Checking ARP table for IP", "target_ip", ip.String())
	entries, err := getARPTable()
	if err != nil {
		slog.Debug("Error retrieving ARP table", "error", err)
		return nil, err
	}
	slog.Debug("Retrieved ARP table entries", "entries", entries)
	for _, entry := range entries {
		slog.Debug("Checking ARP entry", "entry", entry)
		if isARPEntryMatch(entry, ip) {
			slog.Debug("Found matching ARP entry", "entry", entry)
			return entry.HwAddr, nil
		}
	}
	slog.Debug("No matching ARP entry found", "target_ip", ip.String())
	return nil, errors.New("no ARP entry found")
}
