package probe

import "github.com/tkjaer/etr/internal/shared"

// Sink is the interface that receives probe results.
type Sink interface {
	UpdateHop(probeID uint16, ttl uint8, hop shared.HopStats)
	DeleteHops(probeID uint16, ttls []uint8)
	CompleteProbe(probeID uint16, stats shared.ProbeStats)
	CompleteProbeRun(run *shared.ProbeRun)
	UpdateDiscoveryStats(stats shared.DiscoveryStats)
}
