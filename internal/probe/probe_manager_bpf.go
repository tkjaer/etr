package probe

import (
	"fmt"
	"runtime"

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
	var dest_unreachable string
	switch pm.probeConfig.protocolConfig.inet {
	case layers.IPProtocolIPv4:
		// ICMP type 11 (TTL exceeded), code 0 (time to live exceeded in transit)
		ttl_exceeded = "icmp and icmp[0] == 11 and icmp[1] == 0"
		// ICMP type 3 (dest unreachable), code 3 (port unreachable)
		dest_unreachable = "icmp and icmp[0] == 3 and icmp[1] == 3"
	case layers.IPProtocolIPv6:
		ttl_exceeded = "icmp6 and icmp6[0] == 3 and icmp6[1] == 0"
		dest_unreachable = "icmp6 and icmp6[0] == 1 and icmp6[1] == 4"
	}
	portRange := ""
	// libpcap on OpenBSD does not support "portrange" syntax
	if runtime.GOOS == "openbsd" {
		portRange = "("
		for i := range pm.parallelProbes {
			if i > 0 {
				portRange += " or "
			}
			portRange += fmt.Sprintf("dst port %d", pm.probeConfig.srcPort+i)
		}
		portRange += ")"

	} else {
		portRange = fmt.Sprintf(
			"dst portrange %d-%d",
			pm.probeConfig.srcPort,
			pm.probeConfig.srcPort+pm.parallelProbes-1)
	}

	// Note:
	// UDP is tricky as we don't know if/how the destination will respond.
	// It might send ICMP port unreachable, UDP packets from the destination
	// port or nothing at all. Port unreachable is the best bet for a reliable
	// answer, but even that might not always be sent.

	// Match packets that are actual responses from the destination
	// Note: We match on src/dst IP and ports reversed, since we are capturing
	// the returning packets.
	destinationAnswers := fmt.Sprintf(
		"%v and src host %v and dst host %v and src port %v and %v",
		proto,
		pm.probeConfig.route.Destination,
		pm.probeConfig.route.Source,
		pm.probeConfig.dstPort,
		portRange)

	// Match packets that are TTL exceeded messages from intermediate routers
	ttlExceededAnswers := fmt.Sprintf("dst host %v and %v", pm.probeConfig.route.Source, ttl_exceeded)
	destUnreachableAnswers := fmt.Sprintf("dst host %v and %v", pm.probeConfig.route.Source, dest_unreachable)

	filter := fmt.Sprintf("(%v) or (%v) or (%v)", destinationAnswers, ttlExceededAnswers, destUnreachableAnswers)

	return pm.handle.SetBPFFilter(filter)
}
