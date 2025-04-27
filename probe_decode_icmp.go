package main

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (p *probe) decodeICMPv4Layer(icmp4Layer *layers.ICMPv4) (ttl uint8, probeNum uint, flag string) {
	if icmp4Layer.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded && icmp4Layer.TypeCode.Code() == layers.ICMPv4CodeTTLExceeded {
		if packet := gopacket.NewPacket(icmp4Layer.Payload, protoToLayerType(p.inet), gopacket.Default); packet != nil {

			inetLayer := packet.Layer(protoToLayerType(p.inet))
			if inetLayer == nil {
				return
			}

			// Verify source and destination IP addresses
			switch p.inet {
			case layers.IPProtocolIPv4:
				if src := inetLayer.(*layers.IPv4).SrcIP; !src.Equal(net.IP(p.route.Source.AsSlice())) {
					return
				} else if dst := inetLayer.(*layers.IPv4).DstIP; !dst.Equal(net.IP(p.route.Destination.AsSlice())) {
					return
				}
			case layers.IPProtocolIPv6:
				if src := inetLayer.(*layers.IPv6).SrcIP; !src.Equal(net.IP(p.route.Source.AsSlice())) {
					return
				} else if dst := inetLayer.(*layers.IPv6).DstIP; !dst.Equal(net.IP(p.route.Destination.AsSlice())) {
					return
				}
			}

			// Verify source and destination ports.
			//
			// If we have an ErrorLayer, we're probably looking at a truncated TCP header, so we'll try
			// to decode this before potentially checking a TCP layer gopacket failed to decode.
			if errorLayer := packet.Layer(gopacket.LayerTypeDecodeFailure); errorLayer != nil {
				if srcPort := binary.BigEndian.Uint16(inetLayer.LayerPayload()[:2]); srcPort != p.srcPort {
					return
				} else if dstPort := binary.BigEndian.Uint16(inetLayer.LayerPayload()[2:4]); dstPort != p.dstPort {
					return
				} else {
					ttl, probeNum = decodeTTLAndProbe(binary.BigEndian.Uint32(inetLayer.LayerPayload()[4:8]))
					return
				}
			}
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				if srcPort := tcpLayer.(*layers.TCP).SrcPort; srcPort != layers.TCPPort(p.srcPort) {
					return
				} else if dstPort := tcpLayer.(*layers.TCP).DstPort; dstPort != layers.TCPPort(p.dstPort) {
					return
				}
				ttl, probeNum, flag = decodeTCPLayer(tcpLayer.(*layers.TCP))
				return
			}
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				if srcPort := udpLayer.(*layers.UDP).SrcPort; srcPort != layers.UDPPort(p.srcPort) {
					return
				} else if dstPort := udpLayer.(*layers.UDP).DstPort; dstPort != layers.UDPPort(p.dstPort) {
					return
				}
				ttl, probeNum = decodeUDPLayer(udpLayer.(*layers.UDP))
				return
			}
		}
	}
	return
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
