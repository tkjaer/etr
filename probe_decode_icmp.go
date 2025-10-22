package main

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// decodeICMPv4Layer decodes an ICMPv4 layer and returns the TTL, probe number, and flag.
func (pm *ProbeManager) decodeICMPv4Layer(icmp4Layer *layers.ICMPv4) (ttl uint8, probeNum uint, port uint, flag string) {
	if icmp4Layer.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded && icmp4Layer.TypeCode.Code() == layers.ICMPv4CodeTTLExceeded {
		if packet := gopacket.NewPacket(icmp4Layer.Payload, protoToLayerType(pm.probeConfig.protocolConfig.inet), gopacket.Default); packet != nil {

			inetLayer := packet.Layer(protoToLayerType(pm.probeConfig.protocolConfig.inet))
			if inetLayer == nil {
				return
			}

			// Verify source and destination IP addresses
			switch pm.probeConfig.protocolConfig.inet {
			case layers.IPProtocolIPv4:
				if src := inetLayer.(*layers.IPv4).SrcIP; !src.Equal(net.IP(pm.probeConfig.route.Source.AsSlice())) {
					return
				} else if dst := inetLayer.(*layers.IPv4).DstIP; !dst.Equal(net.IP(pm.probeConfig.route.Destination.AsSlice())) {
					return
				}
			case layers.IPProtocolIPv6:
				if src := inetLayer.(*layers.IPv6).SrcIP; !src.Equal(net.IP(pm.probeConfig.route.Source.AsSlice())) {
					return
				} else if dst := inetLayer.(*layers.IPv6).DstIP; !dst.Equal(net.IP(pm.probeConfig.route.Destination.AsSlice())) {
					return
				}
			}

			// Verify source and destination ports.
			//
			// If we have an ErrorLayer, we're probably looking at a truncated TCP header, so we'll try
			// to decode this before potentially checking a TCP layer that gopacket failed to decode.
			if errorLayer := packet.Layer(gopacket.LayerTypeDecodeFailure); errorLayer != nil {
				if srcPort := binary.BigEndian.Uint16(inetLayer.LayerPayload()[:2]); !pm.sourcePortWithinRange(srcPort) {
					return
				} else if dstPort := binary.BigEndian.Uint16(inetLayer.LayerPayload()[2:4]); dstPort != pm.probeConfig.dstPort {
					return
				} else {
					ttl, probeNum = decodeTTLAndProbe(binary.BigEndian.Uint32(inetLayer.LayerPayload()[4:8]))
					port = uint(srcPort)
					return
				}
			}
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				if srcPort := tcpLayer.(*layers.TCP).SrcPort; !pm.sourcePortWithinRange(uint16(srcPort)) {
					return
				} else if dstPort := tcpLayer.(*layers.TCP).DstPort; dstPort != layers.TCPPort(pm.probeConfig.dstPort) {
					return
				}
				ttl, probeNum, port, flag = decodeTCPLayer(tcpLayer.(*layers.TCP))
				return
			}
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				if srcPort := udpLayer.(*layers.UDP).SrcPort; !pm.sourcePortWithinRange(uint16(srcPort)) {
					return
				} else if dstPort := udpLayer.(*layers.UDP).DstPort; dstPort != layers.UDPPort(pm.probeConfig.dstPort) {
					return
				}
				ttl, probeNum, port = decodeUDPLayer(udpLayer.(*layers.UDP))
				return
			}
		}
	}
	return
}

func (pm *ProbeManager) sourcePortWithinRange(srcPort uint16) bool {
	return srcPort >= uint16(pm.probeConfig.srcPort) && srcPort < uint16(pm.probeConfig.srcPort+pm.parallelProbes)
}

func protoToLayerType(proto layers.IPProtocol) gopacket.LayerType {
	switch proto {
	case layers.IPProtocolIPv4:
		return layers.LayerTypeIPv4
	case layers.IPProtocolIPv6:
		return layers.LayerTypeIPv6
	case layers.IPProtocolTCP:
		return layers.LayerTypeTCP
	case layers.IPProtocolUDP:
		return layers.LayerTypeUDP
	default:
		return layers.LayerTypeTCP
	}
}
