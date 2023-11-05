package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/google/gopacket/layers"
)

type probe struct {
	ipProtocol      layers.IPProtocol
	etherType       layers.EthernetType
	dstIP           netip.Addr
	srcIP           netip.Addr
	dstPort         uint16
	srcPort         uint16
	srcIface        net.Interface
	srcMAC          net.HardwareAddr
	dstMAC          net.HardwareAddr
	interProbeDelay uint
	numProbes       uint
	maxTTL          uint8
}

func (p *probe) init() {
	err := getArgs()
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	dstIP, err := lookupDst(Args.destination, Args.forceIPv4, Args.forceIPv6)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	p.dstIP = dstIP

	// set etherType based on IP version of dstIP
	switch {
	case p.dstIP.Is4():
		p.etherType = layers.EthernetTypeIPv4
	case p.dstIP.Is6():
		p.etherType = layers.EthernetTypeIPv6
	}

	switch {
	case Args.TCP:
		p.ipProtocol = layers.IPProtocolTCP
	case Args.UDP:
		p.ipProtocol = layers.IPProtocolUDP
	default:
		p.ipProtocol = layers.IPProtocolTCP
	}

	// lookup source IP, interface, and source + dest MAC with lookupSrc():
	// temporary values:
	srcIP, _ := netip.AddrFromSlice([]byte{192, 0, 2, 1})
	p.srcIP = srcIP
	p.srcIface = net.Interface{Index: 1, Name: "en0"}
	p.srcMAC = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	p.dstMAC = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}

	p.dstPort = uint16(Args.destinationPort)
	p.srcPort = uint16(Args.sourcePort)
	p.numProbes = Args.numProbes
	p.interProbeDelay = Args.interProbeDelay
	p.maxTTL = uint8(Args.maxTTL)

}

func (p *probe) start() {
	fmt.Println("Starting probe")
}
