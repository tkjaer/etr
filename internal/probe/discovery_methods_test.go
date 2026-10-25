package probe

import (
	"sync"
	"testing"
)

func newDiscoveryTestManager(budget uint) *ProbeManager {
	pm := &ProbeManager{
		stop:         make(chan struct{}),
		probeConfig:  Config{SrcPort: 50000, ParallelProbes: 1},
		probeTracker: ProbeTracker{probes: make(map[uint16]*Probe)},
		discovery: discoveryState{
			enabled:       true,
			flowBudget:    budget,
			flowsUsed:     1,
			nextProbeID:   1,
			perProbeState: map[uint16]*probeDiscoveryState{0: {}},
			activeProbes:  map[uint16]struct{}{0: {}},
		},
	}
	// Probes exit straight away, so the test doesn't send packets.
	close(pm.stop)
	return pm
}

func TestRetireAndReplaceStartsReplacementFirst(t *testing.T) {
	pm := newDiscoveryTestManager(0)
	if err := pm.addProbe(0); err != nil {
		t.Fatal(err)
	}
	old := pm.getProbe(0)

	var newRegistered bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-old.discoveryStop
		// When the old probe is told to stop, its replacement must already
		// be registered.
		newRegistered = pm.getProbe(1) != nil
	}()

	pm.retireAndReplaceProbeNoLock(0)
	wg.Wait()
	pm.wg.Wait()

	if !newRegistered {
		t.Error("old probe was stopped before its replacement was registered")
	}
	if _, ok := pm.discovery.activeProbes[0]; ok {
		t.Error("retired probe is still active")
	}
	if _, ok := pm.discovery.activeProbes[1]; !ok {
		t.Error("replacement probe is not active")
	}
	if pm.discovery.flowsUsed != 2 || pm.discovery.nextProbeID != 2 {
		t.Errorf("flowsUsed=%d nextProbeID=%d, want 2 and 2", pm.discovery.flowsUsed, pm.discovery.nextProbeID)
	}
}

func TestRetireAndReplaceRespectsFlowBudget(t *testing.T) {
	pm := newDiscoveryTestManager(1)
	if err := pm.addProbe(0); err != nil {
		t.Fatal(err)
	}
	old := pm.getProbe(0)

	pm.retireAndReplaceProbeNoLock(0)
	pm.wg.Wait()

	select {
	case <-old.discoveryStop:
	default:
		t.Error("old probe was not stopped")
	}
	if pm.getProbe(1) != nil {
		t.Error("replacement started although the flow budget is used up")
	}
}
