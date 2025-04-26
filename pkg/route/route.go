package route

import (
	"net"
	"net/netip"
)

// Route represents a network route with its destination, gateway, source address, and the associated network interface.
type Route struct {
	Destination netip.Addr
	Gateway     netip.Addr
	Source      netip.Addr
	Interface   *net.Interface
}

// Get retrieves the most specific route for a given IP address and returns it as a Route struct.
// The function handles both IPv4 and IPv6 addresses.
func Get(ip netip.Addr) (Route, error) {
	// Use platform-specific implementation to fetch the route
	return get(ip)
}
