package main

import (
	"time"

	"github.com/tkjaer/etr/internal/config"
	"github.com/tkjaer/etr/internal/probe"
)

// configFromArgs converts parsed command-line arguments into a probe.Config.
func configFromArgs(a config.Args) probe.Config {
	cfg := probe.Config{
		Destination:     a.Destination,
		Protocol:        probe.ProtocolTCP,
		SrcPort:         uint16(a.SourcePort),
		DstPort:         uint16(a.DestinationPort),
		ParallelProbes:  uint16(a.ParallelProbes),
		Count:           a.NumProbes,
		MaxTTL:          uint8(a.MaxTTL),
		InterTTLDelay:   a.InterTTLDelay,
		InterProbeDelay: a.InterProbeDelay,
		Timeout:         a.Timeout,
		ResolvePTR:      !a.NoResolve,
		LookupASN:       a.LookupASN,
		HashAlgorithm:   probe.HashAlgorithm(a.HashAlgorithm),
	}
	if a.UDP {
		cfg.Protocol = probe.ProtocolUDP
	}
	switch {
	case a.ForceIPv4:
		cfg.Family = probe.FamilyIPv4
	case a.ForceIPv6:
		cfg.Family = probe.FamilyIPv6
	}
	// On the command line, -i 0 means no delay rather than the default.
	if cfg.InterTTLDelay == 0 {
		cfg.InterTTLDelay = -time.Nanosecond
	}
	if a.Discover {
		cfg.Discovery = &probe.DiscoveryConfig{
			Hops:             a.DiscoverHops,
			MaxFlows:         a.DiscoverFlows,
			NoNewPathsRounds: a.DiscoverNoNewPathsRounds,
			StableRounds:     a.DiscoverPerProbeStableRounds,
		}
	}
	return cfg
}
