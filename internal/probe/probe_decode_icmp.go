package probe

import (
	"encoding/binary"
	"log/slog"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// decodeICMPv4Layer decodes an ICMPv4 layer and returns the TTL, probe number, and flag.
func (pm *ProbeManager) decodeICMPv4Layer(icmp4Layer *layers.ICMPv4) (ttl uint8, probeNum uint, port uint, flag string) {
	// Handle both TTL exceeded (intermediate hops) and destination unreachable (final hop)
	isTimeExceeded := icmp4Layer.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded && icmp4Layer.TypeCode.Code() == layers.ICMPv4CodeTTLExceeded
	isDestUnreachable := icmp4Layer.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable && icmp4Layer.TypeCode.Code() == layers.ICMPv4CodePort

	if isTimeExceeded || isDestUnreachable {
		if isTimeExceeded {
			flag = "TTL"
		} else if isDestUnreachable {
			flag = "D"
		}
		if packet := gopacket.NewPacket(icmp4Layer.Payload, protoToLayerType(pm.probeConfig.protocolConfig.inet), gopacket.Default); packet != nil {
			slog.Debug("Packet received", slog.Any("packet", packet))

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
				ttl, probeNum, port, _ = decodeTCPLayer(tcpLayer.(*layers.TCP))
				// Keep the ICMP-level flag (TTL or D) rather than TCP flags
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

// decodeICMPv6Layer decodes an ICMPv6 layer and returns the TTL, probe number, port, and flag.
func (pm *ProbeManager) decodeICMPv6Layer(icmp6Layer *layers.ICMPv6) (ttl uint8, probeNum uint, port uint, flag string) {
	// Handle both time exceeded (intermediate hops) and destination unreachable (final hop)
	isTimeExceeded := icmp6Layer.TypeCode.Type() == layers.ICMPv6TypeTimeExceeded && icmp6Layer.TypeCode.Code() == layers.ICMPv6CodeHopLimitExceeded
	isDestUnreachable := icmp6Layer.TypeCode.Type() == layers.ICMPv6TypeDestinationUnreachable && icmp6Layer.TypeCode.Code() == 4 // Port unreachable

	if isTimeExceeded || isDestUnreachable {
		if isTimeExceeded {
			flag = "TTL"
		} else if isDestUnreachable {
			flag = "D"
		}
		innerPayload := icmp6Layer.Payload
		expectedLayer := protoToLayerType(pm.probeConfig.protocolConfig.inet)

		if pm.probeConfig.protocolConfig.inet == layers.IPProtocolIPv6 {
			offset, ok := locateInnerIPv6Header(innerPayload)
			if !ok {
				return
			}
			innerPayload = innerPayload[offset:]
		}

		if len(innerPayload) == 0 {
			return
		}

		if packet := gopacket.NewPacket(innerPayload, expectedLayer, gopacket.Default); packet != nil {
			inetLayer := packet.Layer(expectedLayer)
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
				payload := inetLayer.LayerPayload()
				if len(payload) < 8 {
					return
				}
				if srcPort := binary.BigEndian.Uint16(payload[:2]); !pm.sourcePortWithinRange(srcPort) {
					return
				} else if dstPort := binary.BigEndian.Uint16(payload[2:4]); dstPort != pm.probeConfig.dstPort {
					return
				} else {
					ttl, probeNum = decodeTTLAndProbe(binary.BigEndian.Uint32(payload[4:8]))
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
				ttl, probeNum, port, _ = decodeTCPLayer(tcpLayer.(*layers.TCP))
				// Keep the ICMP-level flag (TTL or D) rather than TCP flags
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

// locateInnerIPv6Header scans the provided payload to locate the start of an
// inner IPv6 header. It checks for the presence of an IPv6 header by examining
// the version field in the first nibble of each potential header location.
//
// The function returns the offset of the inner IPv6 header within the payload
// and a boolean indicating whether an IPv6 header was found.
func locateInnerIPv6Header(payload []byte) (int, bool) {
	if len(payload) < 40 {
		return 0, false
	}

	if payload[0]>>4 == 6 {
		return 0, true
	}

	if len(payload) >= 44 && payload[4]>>4 == 6 {
		return 4, true
	}

	for offset := 1; offset+40 <= len(payload); offset++ {
		if payload[offset]>>4 == 6 {
			return offset, true
		}
	}

	return 0, false
}

// sourcePortWithinRange checks if the given source port falls within the range
// allocated for this probe manager's probes.
func (pm *ProbeManager) sourcePortWithinRange(srcPort uint16) bool {
	return srcPort >= uint16(pm.probeConfig.srcPort) && srcPort < uint16(pm.probeConfig.srcPort+pm.parallelProbes)
}

// protoToLayerType maps an IPProtocol to the corresponding gopacket LayerType.
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
