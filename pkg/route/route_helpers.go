//go:build linux || darwin || freebsd || netbsd || openbsd

package route

import (
	"fmt"
	"net"
	"net/netip"
)

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

func getGlobalUnicastIPv6(iface *net.Interface, preferPrefix netip.Prefix, preferNextHop netip.Addr) (netip.Addr, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}

	var fallback netip.Addr
	preferNextHopValid := preferNextHop.IsValid() && !preferNextHop.IsLinkLocalUnicast()

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		if !ip.Is6() || ip.IsLinkLocalUnicast() || ip.Is4In6() {
			continue
		}
		if !ip.IsGlobalUnicast() {
			continue
		}
		if preferPrefix.IsValid() && preferPrefix.Contains(ip) {
			return ip, nil
		}
		if preferNextHopValid {
			ones, _ := ipNet.Mask.Size()
			candidatePrefix := netip.PrefixFrom(ip, ones)
			if candidatePrefix.Contains(preferNextHop) {
				return ip, nil
			}
		}
		if !fallback.IsValid() {
			fallback = ip
		}
	}

	if fallback.IsValid() {
		return fallback, nil
	}

	return netip.Addr{}, fmt.Errorf("interface %s has no global unicast IPv6 address", iface.Name)
}
