package probe

import (
	"context"
	"fmt"
	"runtime"

	"github.com/google/gopacket/layers"
	"github.com/tkjaer/etr/pkg/route"
)

// BuildBPFFilter returns a tcpdump-compatible BPF filter matching the probes
// described by cfg and their responses.
func BuildBPFFilter(cfg Config) (string, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return "", err
	}
	tgt, err := resolveTarget(context.Background(), cfg)
	if err != nil {
		return "", err
	}
	return buildBPFFilter(cfg, tgt, true)
}

// resolveTarget resolves the destination and route, and derives the
// network and transport protocols for the probes.
func resolveTarget(ctx context.Context, cfg Config) (target, error) {
	d, err := getDestinationIP(ctx, cfg.Destination, cfg.Family)
	if err != nil {
		return target{}, err
	}

	r, err := route.Get(d)
	if err != nil {
		return target{}, err
	}

	tgt := target{route: r}
	switch {
	case r.Destination.Is4():
		tgt.etherType = layers.EthernetTypeIPv4
		tgt.inet = layers.IPProtocolIPv4
	case r.Destination.Is6():
		tgt.etherType = layers.EthernetTypeIPv6
		tgt.inet = layers.IPProtocolIPv6
	default:
		return target{}, fmt.Errorf("unsupported destination address")
	}

	switch cfg.Protocol {
	case ProtocolTCP:
		tgt.transport = layers.IPProtocolTCP
	case ProtocolUDP:
		tgt.transport = layers.IPProtocolUDP
	default:
		return target{}, fmt.Errorf("unsupported protocol: %v", cfg.Protocol)
	}
	return tgt, nil
}

// buildBPFFilter builds the capture filter. includeProbes also matches the
// outgoing probe packets, which is useful when capturing with tcpdump.
func buildBPFFilter(probeConfig Config, tgt target, includeProbes bool) (string, error) {
	var proto string
	switch tgt.transport {
	case layers.IPProtocolTCP:
		proto = "tcp"
	case layers.IPProtocolUDP:
		proto = "udp"
	default:
		return "", fmt.Errorf("unsupported transport protocol")
	}
	var ttlExceeded string
	var destUnreachable string
	switch tgt.inet {
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
	pp := probeConfig.ParallelProbes

	// In discovery mode, each new flow gets its own sequential source port.
	// Widen the BPF port range to cover the initial probes plus the flow budget.
	portCount := uint32(pp)
	if probeConfig.Discovery != nil {
		budget := uint32(probeConfig.Discovery.MaxFlows)
		if budget == 0 {
			// Unlimited: cover all ports from srcPort to 65535
			portCount = 65536 - uint32(probeConfig.SrcPort)
		} else {
			portCount = uint32(pp) + budget
			if uint32(probeConfig.SrcPort)+portCount-1 > 65535 {
				portCount = 65536 - uint32(probeConfig.SrcPort)
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
			portRange += fmt.Sprintf("port %d", uint32(probeConfig.SrcPort)+uint32(i))
		}
		portRange += ")"
	} else {
		portRange = fmt.Sprintf(
			"portrange %d-%d",
			probeConfig.SrcPort,
			uint32(probeConfig.SrcPort)+portCount-1)
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
		tgt.route.Destination,
		tgt.route.Source,
		probeConfig.DstPort,
		portRange)

	// Match packets that are the probes we are sending out
	etrPackets := fmt.Sprintf(
		"%v and src host %v and dst host %v and src %v and dst port %v",
		proto,
		tgt.route.Source,
		tgt.route.Destination,
		portRange,
		probeConfig.DstPort)

	// Match packets that are TTL exceeded messages from intermediate routers
	ttlExceededAnswers := fmt.Sprintf("dst host %v and %v", tgt.route.Source, ttlExceeded)
	destUnreachableAnswers := fmt.Sprintf("dst host %v and %v", tgt.route.Source, destUnreachable)

	if includeProbes {
		return fmt.Sprintf("(%v) or (%v) or (%v) or (%v)", destinationAnswers, ttlExceededAnswers, destUnreachableAnswers, etrPackets), nil
	}
	return fmt.Sprintf("(%v) or (%v) or (%v)", destinationAnswers, ttlExceededAnswers, destUnreachableAnswers), nil
}
