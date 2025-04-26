package main

import (
	"errors"
	"net"
	"net/netip"
)

type RouteInformation struct {
	destIP  netip.Addr
	destMAC net.HardwareAddr
	srcIP   netip.Addr
	srcMAC  net.HardwareAddr
	iface   *net.Interface
}

// GetDestinationIP resolves the destination IP address if necessary, validates it and returns it
func GetDestinationIP() (netip.Addr, error) {
	// Check if destination is an IP address
	destIP, err := netip.ParseAddr(Args.destination)

	// If not, resolve it
	if err != nil {
		lookup, err := net.LookupHost(Args.destination)
		if err != nil {
			return destIP, errors.New("could not resolve destination")
		}

		// find the first valid IP that meets our criteria
		for _, record := range lookup {
			ip, err := netip.ParseAddr(record)
			if err != nil {
				continue
			}
			switch {
			case Args.forceIPv4 && ip.Is4():
				destIP = ip
			case Args.forceIPv6 && ip.Is6():
				destIP = ip
			case !Args.forceIPv4 && !Args.forceIPv6:
				destIP = ip
			}
			if destIP.IsValid() {
				break
			}
		}
	}

	if destIP.IsValid() {
		return destIP, nil
	}

	return destIP, errors.New("could not resolve destination")
}
