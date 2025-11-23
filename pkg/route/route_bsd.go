//go:build darwin || freebsd || netbsd || openbsd

package route

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

// fetchRIBMessages retrieves the routing information base (RIB) messages from the kernel.
// Variable for mocking in tests.
var fetchRIBMessages = func() ([]route.Message, error) {
	r, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	m, err := route.ParseRIB(route.RIBTypeRoute, r)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// getGlobalUnicastIPv6 returns a global unicast IPv6 address from the given interface.
// If nextHop is provided and is not link-local, it prefers an address within
// the same subnet as the next hop.
func getGlobalUnicastIPv6(iface *net.Interface, nextHop netip.Addr) (netip.Addr,
	error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}

	var fallback netip.Addr

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		// Skip if not IPv6
		if !ip.Is6() {
			continue
		}
		// Skip link-local addresses
		if ip.IsLinkLocalUnicast() {
			continue
		}
		// Skip IPv4-mapped IPv6 addresses
		if ip.Is4In6() {
			continue
		}
		// Check if it's a global unicast address
		if ip.IsGlobalUnicast() {
			// If we have a non-link-local next hop, prefer addresses in the same subnet
			if nextHop.IsValid() && !nextHop.IsLinkLocalUnicast() {
				// Get the prefix for this address
				ones, _ := ipNet.Mask.Size()
				prefix := netip.PrefixFrom(ip, ones)
				// Check if the next hop is in this subnet
				if prefix.Contains(nextHop) {
					return ip, nil
				}
			}
			// Keep first global address as fallback
			if !fallback.IsValid() {
				fallback = ip
			}
		}
	}

	if fallback.IsValid() {
		return fallback, nil
	}

	return netip.Addr{}, fmt.Errorf("interface has no global unicast IPv6 address")
}

// getMostSpecificRoute finds the most specific route for a given IP address from the routing messages.
func getMostSpecificRoute(ip netip.Addr, msgs []route.Message) (Route, error) {
	mostSpecific := Route{}
	mostSpecificMaskLength := int(0)
	routeFound := false

	for _, msg := range msgs {
		rm := msg.(*route.RouteMessage)

		destination := rm.Addrs[0]
		gateway := rm.Addrs[1]
		mask := rm.Addrs[2]
		source := rm.Addrs[5]

		if mask == nil {
			// Skip routes without a mask
			continue
		}

		if rm.Flags&syscall.RTF_UP == 0 {
			// Skip down routes
			continue
		}

		switch destination.(type) {
		case *route.Inet4Addr:
			a := netip.AddrFrom4(destination.(*route.Inet4Addr).IP)
			// Support routes without a gateway (i.e., directly connected)
			g := netip.Addr{}
			if _, ok := gateway.(*route.Inet4Addr); ok {
				g = netip.AddrFrom4(gateway.(*route.Inet4Addr).IP)
			}
			s := netip.AddrFrom4(source.(*route.Inet4Addr).IP)

			// Check if the destination is a host route and matches the IP
			if ip.Is4() && rm.Flags&syscall.RTF_HOST != 0 && a == ip {
				intf, err := net.InterfaceByIndex(rm.Index)
				if err != nil {
					return Route{}, err
				}
				return Route{
					Destination: ip,
					Gateway:     g,
					Source:      s,
					Interface:   intf,
				}, nil
			}

			// Check if the destination subnet contains the IP
			if ip.Is4() {
				bitLen, _ := net.IPv4Mask(mask.(*route.Inet4Addr).IP[0], mask.(*route.Inet4Addr).IP[1], mask.(*route.Inet4Addr).IP[2], mask.(*route.Inet4Addr).IP[3]).Size()
				subnet := netip.PrefixFrom(a, bitLen)
				if subnet.Contains(ip) {
					intf, err := net.InterfaceByIndex(rm.Index)
					if err != nil {
						return Route{}, err
					}
					if bitLen > mostSpecificMaskLength || (bitLen == mostSpecificMaskLength && !routeFound) {
						mostSpecific = Route{
							Destination: ip,
							Gateway:     g,
							Source:      s,
							Interface:   intf,
						}
						routeFound = true
						mostSpecificMaskLength = bitLen
					}
				}
			}

		case *route.Inet6Addr:
			a := netip.AddrFrom16(destination.(*route.Inet6Addr).IP)
			// Support routes without a gateway (i.e., directly connected)
			g := netip.Addr{}
			if _, ok := gateway.(*route.Inet6Addr); ok {
				g = netip.AddrFrom16(gateway.(*route.Inet6Addr).IP)
			}
			s := netip.AddrFrom16(source.(*route.Inet6Addr).IP)

			// Check if the destination is a host route and matches the IP
			if ip.Is6() && rm.Flags&syscall.RTF_HOST != 0 && a == ip {
				intf, err := net.InterfaceByIndex(rm.Index)
				if err != nil {
					return Route{}, err
				}
				// If source is link-local, try to find a global unicast address
				// Pass the gateway to prefer addresses in the same subnet
				if s.IsLinkLocalUnicast() {
					globalSrc, err := getGlobalUnicastIPv6(intf, g)
					if err != nil {
						return Route{}, fmt.Errorf("no global unicast IPv6 source address found on interface %s for destination %s: %w", intf.Name, ip, err)
					}
					s = globalSrc
				}
				return Route{
					Destination: ip,
					Gateway:     g,
					Source:      s,
					Interface:   intf,
				}, nil
			}

			// Check if the destination subnet contains the IP
			if ip.Is6() {
				bitLen, _ := net.IPMask(mask.(*route.Inet6Addr).IP[:]).Size()
				subnet := netip.PrefixFrom(a, bitLen)
				if subnet.Contains(ip) {
					intf, err := net.InterfaceByIndex(rm.Index)
					if err != nil {
						return Route{}, err
					}
					if bitLen > mostSpecificMaskLength || (bitLen == mostSpecificMaskLength && !routeFound) {
						// If source is link-local, try to find a global unicast address
						// Pass the gateway to prefer addresses in the same subnet
						if s.IsLinkLocalUnicast() {
							globalSrc, err := getGlobalUnicastIPv6(intf, g)
							if err != nil {
								return Route{}, fmt.Errorf("no global unicast IPv6 source address found on interface %s for destination %s: %w", intf.Name, ip, err)
							}
							s = globalSrc
						}
						mostSpecific = Route{
							Destination: ip,
							Gateway:     g,
							Source:      s,
							Interface:   intf,
						}
						routeFound = true
						mostSpecificMaskLength = bitLen
					}
				}
			}
		}
	}

	// If no route was found, return an error
	if mostSpecific != (Route{}) {
		return mostSpecific, nil
	} else {
		return Route{}, fmt.Errorf("no matching route found")
	}
}

// get retrieves the most specific route for a given IP address.
// It fetches the routing information base (RIB) messages and finds the route with the longest prefix match.
// It returns the route as a Route struct or an error if no matching route is found.
// The function handles both IPv4 and IPv6 addresses.
func get(ip netip.Addr) (Route, error) {
	msgs, err := fetchRIBMessages()
	if err != nil {
		return Route{}, err
	}
	route, err := getMostSpecificRoute(ip, msgs)
	if err != nil {
		return Route{}, err
	}
	return route, nil
}
