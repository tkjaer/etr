package probe

import (
	"fmt"
	"runtime"

	"github.com/google/gopacket/layers"
	"github.com/tkjaer/etr/internal/config"
	"github.com/tkjaer/etr/pkg/route"
)

// BuildBPFFilter builds the tcpdump-compatible BPF filter for the given args.
func BuildBPFFilter(a config.Args) (string, error) {
	d, err := getDestinationIP(a)
	if err != nil {
		return "", err
	}

	r, err := route.Get(d)
	if err != nil {
		return "", err
	}

	protocolConfig := ProtocolConfig{}
	if r.Destination.Is4() {
		protocolConfig.etherType = layers.EthernetTypeIPv4
		protocolConfig.inet = layers.IPProtocolIPv4
	} else if r.Destination.Is6() {
		protocolConfig.etherType = layers.EthernetTypeIPv6
		protocolConfig.inet = layers.IPProtocolIPv6
	} else {
		return "", fmt.Errorf("unsupported destination address")
	}

	if a.TCP {
		protocolConfig.transport = layers.IPProtocolTCP
	} else if a.UDP {
		protocolConfig.transport = layers.IPProtocolUDP
	} else {
		protocolConfig.transport = layers.IPProtocolTCP
	}

	probeConfig := ProbeConfig{
		protocolConfig: protocolConfig,
		route:          r,
		dstPort:        uint16(a.DestinationPort),
		srcPort:        uint16(a.SourcePort),
	}

	var proto string
	switch probeConfig.protocolConfig.transport {
	case layers.IPProtocolTCP:
		proto = "tcp"
	case layers.IPProtocolUDP:
		proto = "udp"
	default:
		return "", fmt.Errorf("unsupported transport protocol")
	}
	var ttlExceeded string
	var destUnreachable string
	switch probeConfig.protocolConfig.inet {
	case layers.IPProtocolIPv4:
		// ICMP type 11 (TTL exceeded), code 0 (time to live exceeded in transit)
		ttlExceeded = "icmp and icmp[0] == 11 and icmp[1] == 0"
		// ICMP type 3 (dest unreachable), code 3 (port unreachable)
		destUnreachable = "icmp and icmp[0] == 3 and icmp[1] == 3"
	case layers.IPProtocolIPv6:
		ttlExceeded = "icmp6 and icmp6[0] == 3 and icmp6[1] == 0"
		destUnreachable = "icmp6 and icmp6[0] == 1 and icmp6[1] == 4"
	default:
		return "", fmt.Errorf("unsupported network protocol")
	}
	pp := uint16(a.ParallelProbes)
	if pp == 0 {
		pp = 1
	}

	// In discovery mode, each new flow gets its own sequential source port.
	// Widen the BPF port range to cover the initial probes plus the flow budget.
	portCount := uint32(pp)
	if a.Discover {
		budget := uint32(a.DiscoverFlows)
		if budget == 0 {
			// Unlimited: cover all ports from srcPort to 65535
			portCount = 65536 - uint32(probeConfig.srcPort)
		} else {
			portCount = uint32(pp) + budget
			if uint32(probeConfig.srcPort)+portCount-1 > 65535 {
				portCount = 65536 - uint32(probeConfig.srcPort)
			}
		}
	}

	portRange := ""
	// libpcap on OpenBSD does not support "portrange" syntax
	if runtime.GOOS == "openbsd" {
		portRange = "("
		for i := range portCount {
			if i > 0 {
				portRange += " or "
			}
			portRange += fmt.Sprintf("port %d", uint32(probeConfig.srcPort)+uint32(i))
		}
		portRange += ")"
	} else {
		portRange = fmt.Sprintf(
			"portrange %d-%d",
			probeConfig.srcPort,
			uint32(probeConfig.srcPort)+portCount-1)
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
		"%v and src host %v and dst host %v and src port %v and dst %v",
		proto,
		probeConfig.route.Destination,
		probeConfig.route.Source,
		probeConfig.dstPort,
		portRange)

	// Match packets that are the probes we are sending out
	etrPackets := fmt.Sprintf(
		"%v and src host %v and dst host %v and src %v and dst port %v",
		proto,
		probeConfig.route.Source,
		probeConfig.route.Destination,
		portRange,
		probeConfig.dstPort)

	// Match packets that are TTL exceeded messages from intermediate routers
	ttlExceededAnswers := fmt.Sprintf("dst host %v and %v", probeConfig.route.Source, ttlExceeded)
	destUnreachableAnswers := fmt.Sprintf("dst host %v and %v", probeConfig.route.Source, destUnreachable)

	// If --print-bpf is set, include the outgoing probe packets in the filter,
	// allow capturing them with tcpdump for testing/debugging.
	if a.PrintBPFFilter {
		return fmt.Sprintf("(%v) or (%v) or (%v) or (%v)", destinationAnswers, ttlExceededAnswers, destUnreachableAnswers, etrPackets), nil
	}
	return fmt.Sprintf("(%v) or (%v) or (%v)", destinationAnswers, ttlExceededAnswers, destUnreachableAnswers), nil
}
