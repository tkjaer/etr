//go:build darwin

// This should work on freebsd, netbsd and openbsd as well (but not tested).

package ndp

import (
	"errors"
	"net"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// getNeighbourTable fetches the routing table. Variable for mocking in tests.
var getNeighbourTable = func() ([]route.Message, error) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, unix.NET_RT_FLAGS, unix.RTF_LLINFO)
	if err != nil {
		return nil, err
	}
	return route.ParseRIB(route.RIBTypeRoute, rib)
}

// isNeighbourMatch checks if a route message matches the target IP
func isNeighbourMatch(msg route.Message, ip net.IP) bool {
	routeMsg, ok := msg.(*route.RouteMessage)
	if !ok || routeMsg.Flags&unix.RTF_LLINFO == 0 {
		return false
	}

	addrs := routeMsg.Addrs
	if len(addrs) <= unix.RTAX_GATEWAY || addrs[unix.RTAX_DST] == nil {
		return false
	}

	var dstIP net.IP
	switch addr := addrs[unix.RTAX_DST].(type) {
	case *route.Inet4Addr:
		dstIP = net.IPv4(addr.IP[0], addr.IP[1], addr.IP[2], addr.IP[3])
	case *route.Inet6Addr:
		dstIP = net.IP(addr.IP[:])
	default:
		return false
	}

	return dstIP.Equal(ip)
}

// CheckNeighbourTable checks if IP is in the kernel Neighbour table for the provided interface
// On macOS, we use the routing socket to query the neighbor cache
func checkNeighbourTable(ip net.IP, iface *net.Interface) (net.HardwareAddr, error) {
	msgs, err := getNeighbourTable()
	if err != nil {
		return nil, err
	}

	// Look through the messages for our IP
	for _, msg := range msgs {
		if !isNeighbourMatch(msg, ip) {
			continue
		}

		routeMsg := msg.(*route.RouteMessage)

		// Check interface if specified
		if iface != nil && routeMsg.Index != iface.Index {
			continue
		}

		// Extract MAC address from gateway (link-layer address)
		gwAddr := routeMsg.Addrs[unix.RTAX_GATEWAY]
		if linkAddr, ok := gwAddr.(*route.LinkAddr); ok {
			if len(linkAddr.Addr) > 0 {
				return net.HardwareAddr(linkAddr.Addr), nil
			}
		}
	}

	return nil, errors.New("no neighbour entry found")
}
