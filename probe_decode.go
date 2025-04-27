package main

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (p *probe) decodeRecvProbe(packet gopacket.Packet) (ttl uint8, probeNum uint, timestamp time.Time, ip net.IP, flag string) {
	// Decode any ICMP layers first to ensure we're catching TTL exceeded and
	// not just parsing the inner layer.
	if icmp4Layer := packet.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
		ttl, probeNum, _ = p.decodeICMPv4Layer(icmp4Layer.(*layers.ICMPv4))
		flag = "TTL"
	} else if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		// TODO: implement decodeICMPv6Layer()
		fmt.Println("ICMPv6 decode not implemented yet")
	} else {
		switch p.proto {
		case layers.IPProtocolTCP:
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				ttl, probeNum, flag = decodeTCPLayer(tcpLayer.(*layers.TCP))
			}
		case layers.IPProtocolUDP:
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				ttl, probeNum = decodeUDPLayer(udpLayer.(*layers.UDP))
			}
		}
	}
	ip = packet.NetworkLayer().NetworkFlow().Src().Raw()
	timestamp = packet.Metadata().Timestamp
	return
}
