package output

import "github.com/tkjaer/etr/internal/shared"

// Output interface for different output types
type Output interface {
	UpdateHop(probeID uint16, ttl uint8, hopStats shared.HopStats)
	DeleteHops(probeID uint16, ttls []uint8)
	CompleteProbe(probeID uint16, stats shared.ProbeStats)
	CompleteProbeRun(run *shared.ProbeRun)
	Close() error
}

// OutputManager manages multiple outputs
type OutputManager struct {
	outputs []Output
}

func (om *OutputManager) Register(o Output) {
	om.outputs = append(om.outputs, o)
}

func (om *OutputManager) UpdateHop(probeID uint16, ttl uint8, hopStats shared.HopStats) {
	for _, o := range om.outputs {
		o.UpdateHop(probeID, ttl, hopStats)
	}
}

func (om *OutputManager) DeleteHops(probeID uint16, ttls []uint8) {
	for _, o := range om.outputs {
		o.DeleteHops(probeID, ttls)
	}
}

func (om *OutputManager) CompleteProbe(probeID uint16, stats shared.ProbeStats) {
	for _, o := range om.outputs {
		o.CompleteProbe(probeID, stats)
	}
}

func (om *OutputManager) CompleteProbeRun(run *shared.ProbeRun) {
	for _, o := range om.outputs {
		o.CompleteProbeRun(run)
	}
}

func (om *OutputManager) Close() {
	for _, o := range om.outputs {
		o.Close()
	}
}
