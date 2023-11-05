package main

import (
	"errors"
	"net"
	"net/netip"
)

// parse destination and return a valid IP address that meets the address family criteria
func lookupDst(destination string, forceIPv4, forceIPv6 bool) (netip.Addr, error) {
	// check if destination is an IP address
	parsedIP, err := netip.ParseAddr(destination)

	// resolve IP if destination is a hostname
	if err != nil {
		lookup, err := net.LookupHost(destination)
		if err != nil {
			return parsedIP, errors.New("could not resolve destination")
		}

		// find the first valid IP that meets our criteria
		for _, record := range lookup {
			ip, err := netip.ParseAddr(record)
			if err != nil {
				continue
			}
			switch {
			case forceIPv4 && ip.Is4():
				parsedIP = ip
			case forceIPv6 && ip.Is6():
				parsedIP = ip
			case !forceIPv4 && !forceIPv6:
				parsedIP = ip
			}
			if parsedIP.IsValid() {
				break
			}
		}
	}

	// evaluate if we've found a valid IP address
	switch {
	case !parsedIP.IsValid():
		return parsedIP, errors.New("could not resolve destination")
	case forceIPv4 && parsedIP.Is6():
		return parsedIP, errors.New("IPv4 is forced and destination is not IPv4")
	case forceIPv6 && parsedIP.Is4():
		return parsedIP, errors.New("IPv6 is forced and destination is not IPv6")
	}

	return parsedIP, nil
}

// func lookupSrc(sourceIP netip.Addr, sourceInterface string) (netip.Addr, net.Interface, net.HardwareAddr, error) {
// }
