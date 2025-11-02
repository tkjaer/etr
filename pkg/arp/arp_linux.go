//go:build linux

package arp

import (
	"errors"
	"net"

	"github.com/jsimonetti/rtnetlink/rtnl"
)

// getARPTable is a variable holding the function to retrieve ARP table entries.
// This allows for easy mocking in tests.
var getARPTable = func(iface *net.Interface) ([]*rtnl.Neigh, error) {
	c, err := rtnl.Dial(nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Neighbours(iface, 0)
	if err != nil {
		return nil, err
	}

	return r, nil
}

// isARPEntryMatch checks if the given ARP entry matches the provided IP address.
func isARPEntryMatch(n *rtnl.Neigh, ip net.IP) bool {
	return n.IP.Equal(ip)
}

// Check if IP is in the kernel ARP table for the provided interface
func checkARPTable(ip net.IP, iface *net.Interface) (net.HardwareAddr, error) {
	r, err := getARPTable(iface)
	if err != nil {
		return nil, err
	}

	for _, n := range r {
		if isARPEntryMatch(n, ip) {
			return n.HwAddr, nil
		}
	}
	return nil, errors.New("no ARP entry found")
}
