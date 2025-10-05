package main

import (
	"fmt"

	"github.com/google/gopacket/layers"
)

// Create and set probe BPF filter string to capture returning probes.
func (pm *ProbeManager) setBPFFilter() error {
	var proto string
	switch pm.probeConfig.protocolConfig.transport {
	case layers.IPProtocolTCP:
		proto = "tcp"
	case layers.IPProtocolUDP:
		proto = "udp"
	}
	var ttl_exceeded string
	switch pm.probeConfig.protocolConfig.inet {
	case layers.IPProtocolIPv4:
		ttl_exceeded = "icmp and icmp[0] == 11 and icmp[1] == 0"
	case layers.IPProtocolIPv6:
		ttl_exceeded = "icmp6 and icmp6[0] == 3 and icmp6[1] == 0"
	}
	srcPortRange := fmt.Sprintf(
		"portrange %d-%d",
		pm.probeConfig.srcPort,
		pm.probeConfig.srcPort+pm.parallelProbes-1)

	// FIXME: We need to figure out how to handle UDP probes.
	// UDP is tricky as we don't know if/how the destination will respond.
	// It might send ICMP port unreachable, UDP packets from the destination
	// port or nothing at all.

	// Match packets that are actual responses from the destination
	// Note: We match on src/dst IP and ports reversed, since we are capturing
	// the returning packets.
	destinationAnswers := fmt.Sprintf(
		"%v and src host %v and dst host %v and src port %v and dst %v",
		proto,
		pm.probeConfig.route.Destination,
		pm.probeConfig.route.Source,
		pm.probeConfig.dstPort,
		srcPortRange)

	// Match packets that are TTL exceeded messages from intermediate routers
	ttlExceededAnswers := fmt.Sprintf("dst host %v and %v", pm.probeConfig.route.Source, ttl_exceeded)

	filter := fmt.Sprintf("(%v) or (%v)", destinationAnswers, ttlExceededAnswers)

	return pm.handle.SetBPFFilter(filter)
}
