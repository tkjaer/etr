package etr

// Sink is the interface that receives probe results.
type Sink interface {
	UpdateHop(probeID uint16, ttl uint8, hop HopStats)
	DeleteHops(probeID uint16, ttls []uint8)
	CompleteProbe(probeID uint16, stats ProbeStats)
	CompleteProbeRun(run *ProbeRun)
	UpdateDiscoveryStats(stats DiscoveryStats)
}

// Starter is implemented by sinks that need to start once setup has succeeded
type Starter interface {
	Start()
}
