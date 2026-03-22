package probe

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// decodeICMPv4Layer decodes an ICMPv4 layer and returns the TTL, probe number, and flag.
func (pm *ProbeManager) decodeICMPv4Layer(icmp4Layer *layers.ICMPv4) (ttl uint8, probeNum uint, port uint, flag string) {
	// Handle both TTL exceeded (intermediate hops) and destination unreachable (final hop)
	isTimeExceeded := icmp4Layer.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded && icmp4Layer.TypeCode.Code() == layers.ICMPv4CodeTTLExceeded
	isDestUnreachable := icmp4Layer.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable && icmp4Layer.TypeCode.Code() == layers.ICMPv4CodePort

	if !isTimeExceeded && !isDestUnreachable {
		return
	}
	if isTimeExceeded {
		flag = "TTL"
	} else {
		flag = "D"
	}

	expected := protoToLayerType(pm.probeConfig.protocolConfig.inet)
	packet := gopacket.NewPacket(icmp4Layer.Payload, expected, gopacket.Default)
	if packet == nil {
		return
	}
	inetLayer := packet.Layer(expected)
	if inetLayer == nil || !pm.innerIPsMatch(inetLayer) {
		return
	}
	payload := inetLayer.LayerPayload()

	// If we have an ErrorLayer, we're probably looking at a truncated IPv4/TCP
	// header, so decode the raw bytes before relying on decoded layers.
	if packet.Layer(gopacket.LayerTypeDecodeFailure) != nil {
		if len(payload) < 8 {
			return
		}
		srcPort := binary.BigEndian.Uint16(payload[:2])
		dstPort := binary.BigEndian.Uint16(payload[2:4])
		if !pm.sourcePortWithinRange(srcPort) || dstPort != pm.probeConfig.dstPort {
			return
		}
		ttl, probeNum = decodeTTLAndProbe(binary.BigEndian.Uint32(payload[4:8]))
		port = uint(srcPort)
		return
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if !pm.sourcePortWithinRange(uint16(tcp.SrcPort)) || tcp.DstPort != layers.TCPPort(pm.probeConfig.dstPort) {
			return
		}
		ttl, probeNum, port, _ = decodeTCPLayer(tcp)
		return
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		if !pm.sourcePortWithinRange(uint16(udp.SrcPort)) || udp.DstPort != layers.UDPPort(pm.probeConfig.dstPort) {
			return
		}
		ttl, probeNum, port = decodeUDPLayer(udp)
	}

	return
}

// decodeICMPv6Layer decodes an ICMPv6 layer and returns the TTL, probe number, port, and flag.
func (pm *ProbeManager) decodeICMPv6Layer(icmp6Layer *layers.ICMPv6) (ttl uint8, probeNum uint, port uint, flag string) {
	// Handle both time exceeded (intermediate hops) and destination unreachable (final hop)
	isTimeExceeded := icmp6Layer.TypeCode.Type() == layers.ICMPv6TypeTimeExceeded && icmp6Layer.TypeCode.Code() == layers.ICMPv6CodeHopLimitExceeded
	isDestUnreachable := icmp6Layer.TypeCode.Type() == layers.ICMPv6TypeDestinationUnreachable && icmp6Layer.TypeCode.Code() == 4 // Port unreachable

	if !isTimeExceeded && !isDestUnreachable {
		return
	}
	if isTimeExceeded {
		flag = "TTL"
	} else {
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

	packet := gopacket.NewPacket(innerPayload, expectedLayer, gopacket.Default)
	if packet == nil {
		return
	}
	inetLayer := packet.Layer(expectedLayer)
	if inetLayer == nil || !pm.innerIPsMatch(inetLayer) {
		return
	}
	payload := inetLayer.LayerPayload()

	// If we have an ErrorLayer, we're probably looking at a truncated IPv6/TCP
	// header, so decode the raw bytes before relying on decoded layers.
	if packet.Layer(gopacket.LayerTypeDecodeFailure) != nil {
		if len(payload) < 8 {
			return
		}
		srcPort := binary.BigEndian.Uint16(payload[:2])
		dstPort := binary.BigEndian.Uint16(payload[2:4])
		if !pm.sourcePortWithinRange(srcPort) || dstPort != pm.probeConfig.dstPort {
			return
		}
		ttl, probeNum = decodeTTLAndProbe(binary.BigEndian.Uint32(payload[4:8]))
		port = uint(srcPort)
		return
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if !pm.sourcePortWithinRange(uint16(tcp.SrcPort)) || tcp.DstPort != layers.TCPPort(pm.probeConfig.dstPort) {
			return
		}
		ttl, probeNum, port, _ = decodeTCPLayer(tcp)
		return
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		if !pm.sourcePortWithinRange(uint16(udp.SrcPort)) || udp.DstPort != layers.UDPPort(pm.probeConfig.dstPort) {
			return
		}
		ttl, probeNum, port = decodeUDPLayer(udp)
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

// sourcePortWithinRange checks if the given source port belongs to one of
// this probe manager's probes.
func (pm *ProbeManager) sourcePortWithinRange(srcPort uint16) bool {
	if srcPort < pm.probeConfig.srcPort {
		return false
	}
	offset := srcPort - pm.probeConfig.srcPort
	if !pm.discovery.enabled {
		return offset < pm.parallelProbes
	}
	// In discovery mode, accept any port that maps to a known probe.
	pm.probeTracker.mutex.Lock()
	_, exists := pm.probeTracker.probes[offset]
	pm.probeTracker.mutex.Unlock()
	return exists
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

func (pm *ProbeManager) innerIPsMatch(layer gopacket.Layer) bool {
	switch ipLayer := layer.(type) {
	case *layers.IPv4:
		return ipLayer.SrcIP.Equal(net.IP(pm.probeConfig.route.Source.AsSlice())) &&
			ipLayer.DstIP.Equal(net.IP(pm.probeConfig.route.Destination.AsSlice()))
	case *layers.IPv6:
		return ipLayer.SrcIP.Equal(net.IP(pm.probeConfig.route.Source.AsSlice())) &&
			ipLayer.DstIP.Equal(net.IP(pm.probeConfig.route.Destination.AsSlice()))
	default:
		return false
	}
}
