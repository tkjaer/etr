//go:build linux
// +build linux

package arp

import (
	"errors"
	"net"

	"github.com/jsimonetti/rtnetlink/rtnl"
)

// Check if IP is in the kernel ARP table for the provided interface
func checkARPTable(ip net.IP, iface *net.Interface) (net.HardwareAddr, error) {
	c, err := rtnl.Dial(nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	r, err := c.Neighbours(iface, 0)
	if err != nil {
		return nil, err
	}

	for _, n := range r {
		if n.IP.Equal(ip) {
			return n.HwAddr, nil
		}
	}
	return nil, errors.New("no ARP entry found")
}
