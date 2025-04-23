package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"

	"github.com/jsimonetti/rtnetlink/rtnl"

	"github.com/jackpal/gateway"
)

type RouteInformation struct {
	destIP  netip.Addr
	destMAC net.HardwareAddr
	srcIP   netip.Addr
	srcMAC  net.HardwareAddr
	iface   *net.Interface
}

// GetInterfaceIP returns the interface IP address, given that the gateway IP is in the same subnet.
func GetInterfaceIP(ifc *net.Interface, gatewayIP net.IP) (net.IP, error) {
	log.Debugf("Looking for IP address for interface %v in the same subnet as %s", ifc.Name, gatewayIP)
	conn, err := rtnl.Dial(nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	addrs, err := conn.Addrs(ifc, 0)
	if err != nil {
		return nil, err
	}

	// Check if we have an IP in the same subnet as the gateway
	for _, addr := range addrs {
		if addr.Contains(gatewayIP) {
			return addr.IP, nil
		}
	}
	// If not, check if we have an IP of the same address family
	for _, addr := range addrs {
		if addr.IP.To4() != nil && gatewayIP.To4() != nil {
			return addr.IP, nil
		}
		if addr.IP.To16() != nil && gatewayIP.To16() != nil {
			return addr.IP, nil
		}
	}

	return nil, errors.New("IP not found")
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

// GetRouteInformation returns the route information for the destination IP
func GetRouteInformation() (*RouteInformation, error) {
	destIP, err := GetDestinationIP()
	if err != nil {
		return nil, err
	}
	log.Debugf("Destination IP: %s", destIP)

	// Get the route for the destination IP including source interface
	route, err := GetRouteForIP(net.IP(destIP.AsSlice()))
	if err != nil {
		return nil, err
	}
	log.Debugf("Route for %s: \n\tinterface: %v\n\tnext-hop: %v\n\tsource MAC: %v", destIP, route.Interface.Name, route.Gateway, route.Interface.HardwareAddr)

	// Get the source IP address for the route
	_srcIP, err := GetInterfaceIP(route.Interface, route.Gateway)
	if err != nil {
		return nil, err
	}
	log.Debugf("Source IP for %s: %v", route.Interface.Name, _srcIP)

	// Convert the IP to a netip.Addr
	srcIP, ok := netip.AddrFromSlice(_srcIP)
	if !ok {
		return nil, errors.New("could not parse source IP")
	}

	// Get the destination MAC address for the route
	destMAC, err := GetMACForIP(route.Gateway, route.Interface)
	log.Debugf("Destination MAC for %s: %v", route.Interface.Name, destMAC)
	if err != nil {
		return nil, err
	}

	return &RouteInformation{
		destIP:  destIP,
		destMAC: destMAC,
		srcIP:   srcIP,
		srcMAC:  route.Interface.HardwareAddr,
		iface:   route.Interface,
	}, nil
}

// GetRouteForIP returns the route for the given IP address
func GetRouteForIPLinux(ip net.IP) (*rtnl.Route, error) {
	conn, err := rtnl.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("can't establish netlink connection: %s", err)
	}
	defer conn.Close()

	r, err := conn.RouteGet(ip)

	return r, err
}

func GetRouteForIPMac(ip net.IP) (*rtnl.Route, error) {
	// Just return the default route for now
	gateway, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("can't discover gateway: %s", err)
	}
	log.Debugf("Gateway: %s", gateway)
	iface, err := net.InterfaceByName(Args.sourceInterface)
	if err != nil {
		return nil, fmt.Errorf("can't find interface %s: %s", Args.sourceInterface, err)
	}
	r := &rtnl.Route{
		Gateway:   gateway,
		Interface: iface,
	}
	r.Gateway = net.IPv4(0, 0, 0, 0)
	r.Destination = &net.IPNet{}
	return r, nil
}

func GetRouteForIP(ip net.IP) (*rtnl.Route, error) {
	// If we are running on Linux, use the netlink route
	if runtime.GOOS == "linux" {
		return GetRouteForIPLinux(ip)
	}
	// If we are running on MacOS, use the MacOS route
	if runtime.GOOS == "darwin" {
		return GetRouteForIPMac(ip)
	}

	return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
}
