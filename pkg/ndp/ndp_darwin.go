//go:build darwin
// +build darwin

// This should work on freebsd, netbsd and openbsd as well (but not tested).

package ndp

import (
	"errors"
	"net"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// CheckNeighbourTable checks if IP is in the kernel Neighbour table for the provided interface
// On macOS, we use the routing socket to query the neighbor cache
func checkNeighbourTable(ip net.IP, iface *net.Interface) (net.HardwareAddr, error) {
	// Open routing socket
	rib, err := route.FetchRIB(unix.AF_UNSPEC, unix.NET_RT_FLAGS, unix.RTF_LLINFO)
	if err != nil {
		return nil, err
	}

	// Parse routing messages
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}

	// Look through the messages for our IP
	for _, msg := range msgs {
		routeMsg, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}

		// Check if this route has link-layer info (neighbor cache entry)
		if routeMsg.Flags&unix.RTF_LLINFO == 0 {
			continue
		}

		// Extract addresses from the message
		addrs := routeMsg.Addrs

		// addrs[unix.RTAX_DST] is the destination IP
		// addrs[unix.RTAX_GATEWAY] is the link-layer address (MAC)

		if len(addrs) <= unix.RTAX_GATEWAY {
			continue
		}

		dstAddr := addrs[unix.RTAX_DST]
		gwAddr := addrs[unix.RTAX_GATEWAY]

		if dstAddr == nil || gwAddr == nil {
			continue
		}

		// Check if the destination matches our target IP
		var dstIP net.IP
		switch addr := dstAddr.(type) {
		case *route.Inet4Addr:
			dstIP = net.IPv4(addr.IP[0], addr.IP[1], addr.IP[2], addr.IP[3])
		case *route.Inet6Addr:
			dstIP = net.IP(addr.IP[:])
		default:
			continue
		}

		if !dstIP.Equal(ip) {
			continue
		}

		// Check interface if specified
		if iface != nil && routeMsg.Index != iface.Index {
			continue
		}

		// Extract MAC address from gateway (link-layer address)
		if linkAddr, ok := gwAddr.(*route.LinkAddr); ok {
			if len(linkAddr.Addr) > 0 {
				return net.HardwareAddr(linkAddr.Addr), nil
			}
		}
	}

	return nil, errors.New("no neighbour entry found")
}
