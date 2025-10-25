package main

type OutputInfo struct {
	destination    string
	protocol       string
	srcPort        uint16
	dstPort        uint16
	parallelProbes uint16
	hashAlgorithm  string
}

// Output interface for different output types
type Output interface {
	UpdateHop(probeID uint16, ttl uint8, hopStats HopStats)
	CompleteProbe(probeID uint16, stats ProbeStats)
	CompleteProbeRun(run *ProbeRun)
	Close() error
}

// OutputManager manages multiple outputs
type OutputManager struct {
	outputs []Output
}

func (om *OutputManager) Register(o Output) {
	om.outputs = append(om.outputs, o)
}

func (om *OutputManager) UpdateHop(probeID uint16, ttl uint8, hopStats HopStats) {
	for _, o := range om.outputs {
		o.UpdateHop(probeID, ttl, hopStats)
	}
}

func (om *OutputManager) CompleteProbe(probeID uint16, stats ProbeStats) {
	for _, o := range om.outputs {
		o.CompleteProbe(probeID, stats)
	}
}

func (om *OutputManager) CompleteProbeRun(run *ProbeRun) {
	for _, o := range om.outputs {
		o.CompleteProbeRun(run)
	}
}

func (om *OutputManager) Close() {
	for _, o := range om.outputs {
		o.Close()
	}
}
