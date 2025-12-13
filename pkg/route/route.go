//go:build linux || darwin || freebsd || netbsd || openbsd

package route

import (
	"fmt"
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

func selectInterfaceAddr(iface *net.Interface, wantIPv6 bool, prefix netip.Prefix) (netip.Addr, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	addr, ok := selectAddrFromList(addrs, wantIPv6, prefix)
	if ok {
		return addr, nil
	}
	family := "IPv4"
	if wantIPv6 {
		family = "IPv6"
	}
	return netip.Addr{}, fmt.Errorf("no %s address on interface %s within %s", family, iface.Name, prefix)
}

func selectAddrFromList(addrs []net.Addr, wantIPv6 bool, prefix netip.Prefix) (netip.Addr, bool) {
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		var (
			candidate netip.Addr
			valid     bool
		)
		if wantIPv6 {
			if ipNet.IP.To4() != nil {
				continue
			}
			ipv6 := ipNet.IP.To16()
			if ipv6 == nil {
				continue
			}
			candidate, valid = netip.AddrFromSlice(ipv6)
		} else {
			ipv4 := ipNet.IP.To4()
			if ipv4 == nil {
				continue
			}
			candidate, valid = netip.AddrFromSlice(ipv4)
		}
		if !valid {
			continue
		}
		if prefix.Contains(candidate) {
			return candidate, true
		}
	}
	return netip.Addr{}, false
}
