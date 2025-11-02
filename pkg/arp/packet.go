//go:build linux || darwin

package arp

import (
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
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return nil, false
	}

	arp := arpLayer.(*layers.ARP)
	if arp.Operation != layers.ARPReply {
		return nil, false
	}

	if !net.IP(arp.SourceProtAddress).Equal(targetIP) {
		return nil, false
	}

	return net.HardwareAddr(arp.SourceHwAddress), true
}
