package main

import (
	"os"

	"github.com/google/gopacket/layers"
	"github.com/tkjaer/etr/pkg/arp"
	"github.com/tkjaer/etr/pkg/route"
	"golang.org/x/term"
)

func (p *probe) init() error {

	if args.json {
		p.outputType = "json"
	} else {
		if term.IsTerminal(int(os.Stdout.Fd())) {
			p.outputType = "terminal"
		} else {
			p.outputType = "ascii"
		}
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

	ip, err := p.GetDestinationIP()
	if err != nil {
		return err
	}
	log.Debug("Destination IP: ", p.route.Destination)

	p.route, err = route.Get(ip)
	if err != nil {
		return err
	}
	log.Debugf("Route: %+v\n", p.route)

	p.dstMAC, err = arp.Get(p.route.Gateway.AsSlice(), p.route.Interface, p.route.Source.AsSlice())
	if err != nil {
		return err
	}

	// set EtherType and INET Protocol based on dstIP version
	switch {
	case p.route.Destination.Is4():
		p.etherType = layers.EthernetTypeIPv4
		p.inet = layers.IPProtocolIPv4
	case p.route.Destination.Is6():
		p.etherType = layers.EthernetTypeIPv6
		p.inet = layers.IPProtocolIPv6
	}

	p.dstPort = uint16(Args.destinationPort)
	p.srcPort = uint16(Args.sourcePort)
	p.numProbes = Args.numProbes
	p.interProbeDelay = Args.interProbeDelay
	p.interTTLDelay = Args.interTTLDelay
	p.maxTTL = uint8(Args.maxTTL)
	p.timeout = Args.timeout

	return nil
}
