package main

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// decodeRecvProbe decodes a received probe packet and returns the TTL, probe number,
// timestamp, source IP address, and flag indicating the type of response.
// It handles both ICMP and non-ICMP protocols, including TCP and UDP.
func (pm *ProbeManager) decodeRecvProbe(packet gopacket.Packet) (ttl uint8, probeNum uint, timestamp time.Time, ip net.IP, port uint, flag string) {
	// Decode any ICMP layers first to ensure we're catching TTL exceeded and
	// not just parsing the inner layer.
	if icmp4Layer := packet.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
		ttl, probeNum, port, _ = pm.decodeICMPv4Layer(icmp4Layer.(*layers.ICMPv4))
		flag = "TTL"
	} else if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		ttl, probeNum, port, _ = pm.decodeICMPv6Layer(icmp6Layer.(*layers.ICMPv6))
		flag = "TTL"
	} else {
		switch pm.probeConfig.protocolConfig.transport {
		case layers.IPProtocolTCP:
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				ttl, probeNum, port, flag = decodeTCPLayer(tcpLayer.(*layers.TCP))
			}
		case layers.IPProtocolUDP:
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				ttl, probeNum, port = decodeUDPLayer(udpLayer.(*layers.UDP))
			}
		}
	}
	ip = packet.NetworkLayer().NetworkFlow().Src().Raw()
	timestamp = packet.Metadata().Timestamp
	return
}
