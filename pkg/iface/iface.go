//go:build linux || darwin || freebsd

package iface

import (
	"net"
	"strings"
)

// IsEthernetInterface determines if an interface requires Ethernet (Layer 2) framing.
// Returns false for tunnel/VPN interfaces that use raw IP packets.
func IsEthernetInterface(iface *net.Interface) bool {
	if iface == nil {
		return false
	}

	// Check if the interface has a hardware address
	// Tunnel interfaces typically don't have MAC addresses
	if len(iface.HardwareAddr) == 0 {
		return false
	}

	// Check for common tunnel/VPN interface name prefixes
	name := iface.Name
	tunnelPrefixes := []string{
		"utun",  // macOS VPN interfaces (IPsec, WireGuard, etc.)
		"tun",   // Generic tunnel interface
		"tap",   // TAP interfaces (though these usually have MAC)
		"ppp",   // PPP interfaces
		"ipsec", // IPsec interfaces
		"wg",    // WireGuard interfaces on Linux
		"vpn",   // Generic VPN interfaces
	}

	for _, prefix := range tunnelPrefixes {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}

	// All checks passed, assume it's an Ethernet interface
	return true
}
