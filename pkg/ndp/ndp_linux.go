//go:build linux

package ndp

import (
	"errors"
	"net"

	"github.com/jsimonetti/rtnetlink/rtnl"
)

// getNeighbourTable fetches neighbors. Variable for mocking in tests.
var getNeighbourTable = func(iface *net.Interface) ([]*rtnl.Neigh, error) {
	c, err := rtnl.Dial(nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Neighbours(iface, 0)
}

// isNeighbourMatch checks if a neighbor entry matches the target IP
func isNeighbourMatch(n *rtnl.Neigh, ip net.IP) bool {
	return n.IP.Equal(ip)
}

// CheckNeighbourTable checks if IP is in the kernel Neighbour table for the provided interface
func checkNeighbourTable(ip net.IP, iface *net.Interface) (net.HardwareAddr, error) {
	neighbors, err := getNeighbourTable(iface)
	if err != nil {
		return nil, err
	}

	for _, n := range neighbors {
		if isNeighbourMatch(n, ip) {
			return n.HwAddr, nil
		}
	}
	return nil, errors.New("no Neighbour entry found")
}
