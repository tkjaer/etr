//go:build linux

package route

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/sys/unix"
)

// fetchRIBMessagesForIP fetches the RIB messages for the given IP address.
// Variable for mocking in tests.
var fetchRIBMessagesForIP = func(ip netip.Addr) ([]rtnetlink.RouteMessage, error) {
	c, err := rtnetlink.Dial(nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	af := unix.AF_INET
	if ip.Is6() {
		af = unix.AF_INET6
	}

	attr := rtnetlink.RouteAttributes{
		Dst: ip.AsSlice(),
	}

	tx := &rtnetlink.RouteMessage{
		Family:     uint8(af),
		Table:      unix.RT_TABLE_MAIN,
		Attributes: attr,
	}

	rx, err := c.Route.Get(tx)
	if err != nil {
		return nil, err
	}
	return rx, nil
}

// getMostSpecificRoute returns the most specific route for the given IP address.
func getMostSpecificRoute(ip netip.Addr, msgs []rtnetlink.RouteMessage) (Route, error) {
	// RTM_GETROUTE on Linux by default returns the most specific route
	if len(msgs) > 1 {
		// This shouldn't happen
		return Route{}, fmt.Errorf("multiple routes found for %s", ip)
	}
	m := msgs[0]
	dst, ok := netip.AddrFromSlice(m.Attributes.Dst)
	if !ok {
		return Route{}, fmt.Errorf("failed to parse destination address: %v", m.Attributes.Dst)
	}
	gw := netip.Addr{}
	if _, ok := netip.AddrFromSlice(m.Attributes.Gateway); ok {
		gw, _ = netip.AddrFromSlice(m.Attributes.Gateway)
	}
	src, ok := netip.AddrFromSlice(m.Attributes.Src)
	if !ok {
		return Route{}, fmt.Errorf("failed to parse source address: %v", m.Attributes.Src)
	}
	intf, err := net.InterfaceByIndex(int(m.Attributes.OutIface))
	if err != nil {
		return Route{}, fmt.Errorf("failed to get interface by index %d: %v", m.Attributes.OutIface, err)
	}
	// Skip down interfaces
	if intf.Flags&unix.IFF_UP == 0 {
		return Route{}, fmt.Errorf("interface %s is down", intf.Name)
	}
	if dst == ip {
		return Route{
			Destination: dst,
			Gateway:     gw,
			Source:      src,
			Interface:   intf,
		}, nil
	}
	return Route{}, fmt.Errorf("no matching route found for %s", ip)
}

// get retrieves the most specific route for a given IP address.
// It fetches the routing information base (RIB) messages and finds most specific route.
// It returns the route as a Route struct or an error if no matching route is found.
// The function handles both IPv4 and IPv6 addresses.
func get(ip netip.Addr) (Route, error) {
	msgs, err := fetchRIBMessagesForIP(ip)
	if err != nil {
		return Route{}, err
	}
	route, err := getMostSpecificRoute(ip, msgs)
	if err != nil {
		return Route{}, fmt.Errorf("failed to get most specific route: %w", err)
	}
	return route, nil
}
