//go:build linux || darwin || freebsd

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
				Name:         "tun0",
				HardwareAddr: nil,
			},
			expected: false,
		},
		{
			name: "utun interface (macOS VPN)",
			iface: &net.Interface{
				Name:         "utun0",
				HardwareAddr: nil,
			},
			expected: false,
		},
		{
			name: "utun interface with MAC (should still be non-Ethernet)",
			iface: &net.Interface{
				Name:         "utun1",
				HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			},
			expected: false,
		},
		{
			name: "tun interface",
			iface: &net.Interface{
				Name:         "tun0",
				HardwareAddr: nil,
			},
			expected: false,
		},
		{
			name: "ppp interface",
			iface: &net.Interface{
				Name:         "ppp0",
				HardwareAddr: nil,
			},
			expected: false,
		},
		{
			name: "wg interface (WireGuard)",
			iface: &net.Interface{
				Name:         "wg0",
				HardwareAddr: nil,
			},
			expected: false,
		},
		{
			name: "ethernet interface with MAC",
			iface: &net.Interface{
				Name:         "en0",
				HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			},
			expected: true,
		},
		{
			name: "wifi interface with MAC",
			iface: &net.Interface{
				Name:         "wlan0",
				HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			},
			expected: true,
		},
		{
			name: "eth interface with MAC",
			iface: &net.Interface{
				Name:         "eth0",
				HardwareAddr: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsEthernetInterface(tt.iface)
			if result != tt.expected {
				t.Errorf("IsEthernetInterface() = %v, want %v for interface %v",
					result, tt.expected, tt.iface)
			}
		})
	}
}
