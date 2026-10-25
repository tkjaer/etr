package output

import (
	"log/slog"

	"github.com/tkjaer/etr/internal/probe"
)

// Output interface for different output types
type Output interface {
	UpdateHop(probeID uint16, ttl uint8, hopStats probe.HopStats)
	DeleteHops(probeID uint16, ttls []uint8)
	CompleteProbe(probeID uint16, stats probe.ProbeStats)
	CompleteProbeRun(run *probe.ProbeRun)
	UpdateDiscoveryStats(stats probe.DiscoveryStats)
	Close() error
}

// OutputManager manages multiple outputs
type OutputManager struct {
	outputs []Output
}

func (om *OutputManager) Register(o Output) {
	om.outputs = append(om.outputs, o)
}

func (om *OutputManager) UpdateHop(probeID uint16, ttl uint8, hopStats probe.HopStats) {
	for _, o := range om.outputs {
		o.UpdateHop(probeID, ttl, hopStats)
	}
}

func (om *OutputManager) DeleteHops(probeID uint16, ttls []uint8) {
	for _, o := range om.outputs {
		o.DeleteHops(probeID, ttls)
	}
}

func (om *OutputManager) CompleteProbe(probeID uint16, stats probe.ProbeStats) {
	for _, o := range om.outputs {
		o.CompleteProbe(probeID, stats)
	}
}

func (om *OutputManager) CompleteProbeRun(run *probe.ProbeRun) {
	for _, o := range om.outputs {
		o.CompleteProbeRun(run)
	}
}

func (om *OutputManager) UpdateDiscoveryStats(stats probe.DiscoveryStats) {
	for _, o := range om.outputs {
		o.UpdateDiscoveryStats(stats)
	}
}

func (om *OutputManager) Close() {
	for _, o := range om.outputs {
		if err := o.Close(); err != nil {
			slog.Error("Failed to close output", "error", err)
		}
	}
}
