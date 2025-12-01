//go:build linux || darwin || freebsd || netbsd || openbsd

package iface

import (
	"net"
	"testing"
)

func TestIsEthernetInterface(t *testing.T) {
	tests := []struct {
		name     string
		iface    *net.Interface
		expected bool
	}{
		{
			name:     "nil interface",
			iface:    nil,
			expected: false,
		},
		{
			name: "interface without hardware address",
			iface: &net.Interface{
				Name:         "any0",
				HardwareAddr: nil,
				Flags:        net.FlagUp | net.FlagRunning,
			},
			expected: false,
		},
		{
			name: "point-to-point interface (VPN/tunnel)",
			iface: &net.Interface{
				Name:         "utun0",
				HardwareAddr: nil,
				Flags:        net.FlagUp | net.FlagRunning | net.FlagPointToPoint,
			},
			expected: false,
		},
		{
			name: "point-to-point interface with MAC (should still be non-Ethernet)",
			iface: &net.Interface{
				Name:         "ppp0",
				HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				Flags:        net.FlagUp | net.FlagRunning | net.FlagPointToPoint,
			},
			expected: false,
		},
		{
			name: "loopback interface",
			iface: &net.Interface{
				Name:         "lo0",
				HardwareAddr: nil,
				Flags:        net.FlagUp | net.FlagLoopback,
			},
			expected: false,
		},
		{
			name: "ethernet interface with MAC",
			iface: &net.Interface{
				Name:         "en0",
				HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				Flags:        net.FlagUp | net.FlagRunning | net.FlagBroadcast | net.FlagMulticast,
			},
			expected: true,
		},
		{
			name: "wifi interface with MAC",
			iface: &net.Interface{
				Name:         "wlan0",
				HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				Flags:        net.FlagUp | net.FlagRunning | net.FlagBroadcast,
			},
			expected: true,
		},
		{
			name: "eth interface with MAC",
			iface: &net.Interface{
				Name:         "eth0",
				HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				Flags:        net.FlagUp | net.FlagBroadcast,
			},
			expected: true,
		},
		{
			name: "bridge interface with MAC",
			iface: &net.Interface{
				Name:         "br0",
				HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				Flags:        net.FlagUp | net.FlagRunning | net.FlagBroadcast,
			},
			expected: true,
		},
		{
			name: "WireGuard interface (point-to-point, no MAC)",
			iface: &net.Interface{
				Name:         "wg0",
				HardwareAddr: nil,
				Flags:        net.FlagUp | net.FlagRunning | net.FlagPointToPoint,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsEthernetInterface(tt.iface)
			if result != tt.expected {
				t.Errorf("IsEthernetInterface() = %v, want %v for interface %+v",
					result, tt.expected, tt.iface)
			}
		})
	}
}
