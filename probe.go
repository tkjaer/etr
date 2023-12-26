package main

import (
	"net"
	"net/netip"
	"os"

	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
)

type probe struct {
	proto           layers.IPProtocol
	inet            layers.IPProtocol
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

var log = logrus.New()

func (p *probe) init() {

	log.Out = os.Stdout
	log.SetLevel(logrus.DebugLevel)

	err := getArgs()
	if err != nil {
		log.Fatal(err)
	}

	dstIP, err := lookupDst(Args.destination, Args.forceIPv4, Args.forceIPv6)
	if err != nil {
		log.Fatal(err)
	}
	p.dstIP = dstIP

	// set EtherType and INET Protocol based on IP version of dstIP
	switch {
	case p.dstIP.Is4():
		p.etherType = layers.EthernetTypeIPv4
		p.inet = layers.IPProtocolIPv4
	case p.dstIP.Is6():
		p.etherType = layers.EthernetTypeIPv6
		p.inet = layers.IPProtocolIPv6
	}

	// set probe protocol
	switch {
	case Args.TCP:
		p.proto = layers.IPProtocolTCP
	case Args.UDP:
		p.proto = layers.IPProtocolUDP
	default:
		p.proto = layers.IPProtocolTCP
	}

	// lookup source IP, interface, and source + dest MAC with lookupSrc():
	// temporary values:
	srcIP, _ := netip.AddrFromSlice([]byte{192, 0, 2, 1})
	p.srcIP = srcIP
	p.srcIface = net.Interface{Index: 1, Name: "en0"}

	// temporary flag based MAC assignment
	// TODO: remove this once the lookup function is implemented
	p.srcMAC, err = net.ParseMAC(Args.sourceMAC)
	if err != nil {
		log.Fatal(err)
	}
	p.dstMAC, err = net.ParseMAC(Args.destinationMAC)
	if err != nil {
		log.Fatal(err)
	}

	p.dstPort = uint16(Args.destinationPort)
	p.srcPort = uint16(Args.sourcePort)

	p.numProbes = Args.numProbes
	p.interProbeDelay = Args.interProbeDelay
	p.maxTTL = uint8(Args.maxTTL)
}

func (p *probe) start() {
	log.Info("Starting probe")
}
