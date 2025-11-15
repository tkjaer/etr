//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package arp

import (
	"log/slog"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// CreateARPRequest creates an ARP request packet as bytes.
// This function is pure and easily testable.
func CreateARPRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP),
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	if err := gopacket.SerializeLayers(buffer, opts, &eth, &arp); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// IsARPReplyFor checks if the given packet is an ARP reply for the target IP.
// This function is pure and easily testable.
func IsARPReplyFor(packet gopacket.Packet, targetIP net.IP) (net.HardwareAddr, bool) {
	slog.Debug("Checking ARP packet for target IP", "target_ip", targetIP.String())
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		slog.Debug("No ARP layer found in packet")
		return nil, false
	}

	arp := arpLayer.(*layers.ARP)
	if arp.Operation != layers.ARPReply {
		slog.Debug("ARP packet is not a reply", "operation", arp.Operation)
		return nil, false
	}

	if !net.IP(arp.SourceProtAddress).Equal(targetIP) {
		slog.Debug("ARP packet source IP does not match target IP", "source_ip", net.IP(arp.SourceProtAddress).String(), "target_ip", targetIP.String())
		return nil, false
	}

	return net.HardwareAddr(arp.SourceHwAddress), true
}
