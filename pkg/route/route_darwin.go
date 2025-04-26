//go:build darwin

package route

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
)

// fetchRIBMessages retrieves the routing information base (RIB) messages from the kernel.
func fetchRIBMessages() ([]route.Message, error) {
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

// getMostSpecificRoute finds the most specific route for a given IP address from the routing messages.
func getMostSpecificRoute(ip netip.Addr, msgs []route.Message) (Route, error) {
	mostSpecific := Route{}
	mostSpecificMaskLength := int(0)

	for _, msg := range msgs {
		rm := msg.(*route.RouteMessage)

		destination := rm.Addrs[0]
		gateway := rm.Addrs[1]
		mask := rm.Addrs[2]
		source := rm.Addrs[5]

		if rm.Flags&syscall.RTF_UP == 0 {
			// Skip down routes
			continue
		}

		if _, ok := gateway.(*route.LinkAddr); ok {
			// Gateway is a link address, skipping we've not implemented this yet
			continue
		}

		switch destination.(type) {
		case *route.Inet4Addr:
			a := netip.AddrFrom4(destination.(*route.Inet4Addr).IP)
			g := netip.AddrFrom4(gateway.(*route.Inet4Addr).IP)
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

			// Check if the destination is a subnet and contains the IP
			if ip.Is4() && mask != nil {
				bitLen, _ := net.IPv4Mask(mask.(*route.Inet4Addr).IP[0], mask.(*route.Inet4Addr).IP[1], mask.(*route.Inet4Addr).IP[2], mask.(*route.Inet4Addr).IP[3]).Size()
				subnet := netip.PrefixFrom(a, bitLen)
				if subnet.Contains(ip) {
					intf, err := net.InterfaceByIndex(rm.Index)
					if err != nil {
						return Route{}, err
					}
					if bitLen >= mostSpecificMaskLength {
						mostSpecific = Route{
							Destination: ip,
							Gateway:     g,
							Source:      s,
							Interface:   intf,
						}
						mostSpecificMaskLength = bitLen
					}
				}
			}

		case *route.Inet6Addr:
			a := netip.AddrFrom16(destination.(*route.Inet6Addr).IP)
			g := netip.AddrFrom16(gateway.(*route.Inet6Addr).IP)
			s := netip.AddrFrom16(source.(*route.Inet6Addr).IP)

			// Check if the destination is a host route and matches the IP
			if ip.Is6() && rm.Flags&syscall.RTF_HOST != 0 && a == ip {
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

			// Check if the destination is a subnet and contains the IP
			if ip.Is6() && mask != nil {
				bitLen, _ := net.IPMask(mask.(*route.Inet6Addr).IP[:]).Size()
				subnet := netip.PrefixFrom(a, bitLen)
				if subnet.Contains(ip) {
					intf, err := net.InterfaceByIndex(rm.Index)
					if err != nil {
						return Route{}, err
					}
					if bitLen >= mostSpecificMaskLength {
						mostSpecific = Route{
							Destination: ip,
							Gateway:     g,
							Source:      s,
							Interface:   intf,
						}
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
