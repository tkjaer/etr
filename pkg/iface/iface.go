//go:build linux || darwin || freebsd || netbsd || openbsd

package iface

import (
	"net"
)

// IsEthernetInterface determines if an interface requires Ethernet (Layer 2) framing.
// Returns false for tunnel/VPN interfaces that use raw IP packets.
//
// This function uses multiple heuristics:
// 1. Point-to-point interfaces (IFF_POINTOPOINT flag) don't use Ethernet framing
// 2. Interfaces without hardware addresses are typically not Ethernet
func IsEthernetInterface(iface *net.Interface) bool {
	if iface == nil {
		return false
	}

	// Point-to-point interfaces (VPNs, PPP, etc.) don't use Ethernet framing
	// This is the most reliable check across all platforms
	if iface.Flags&net.FlagPointToPoint != 0 {
		return false
	}

	// Loopback interfaces don't use Ethernet framing
	if iface.Flags&net.FlagLoopback != 0 {
		return false
	}

	// Check if the interface has a hardware address
	// Most tunnel interfaces don't have MAC addresses
	if len(iface.HardwareAddr) == 0 {
		return false
	}

	return true
}
