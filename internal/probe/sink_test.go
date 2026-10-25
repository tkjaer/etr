package probe

import (
	"slices"
	"testing"

	"github.com/tkjaer/etr/internal/shared"
)

type recordingSink struct {
	hops      []uint8
	deleted   []uint8
	runs      []*shared.ProbeRun
	completed []uint16
	discovery []shared.DiscoveryStats
}

func (s *recordingSink) UpdateHop(probeID uint16, ttl uint8, hop shared.HopStats) {
	s.hops = append(s.hops, ttl)
}

func (s *recordingSink) DeleteHops(probeID uint16, ttls []uint8) {
	s.deleted = append(s.deleted, ttls...)
}

func (s *recordingSink) CompleteProbe(probeID uint16, stats shared.ProbeStats) {
	s.completed = append(s.completed, probeID)
}

func (s *recordingSink) CompleteProbeRun(run *shared.ProbeRun) {
	s.runs = append(s.runs, run)
}

func (s *recordingSink) UpdateDiscoveryStats(stats shared.DiscoveryStats) {
	s.discovery = append(s.discovery, stats)
}

func newOutputTestManager(msgs ...outputMsg) *ProbeManager {
	pm := &ProbeManager{
		outputChan: make(chan outputMsg, len(msgs)),
		stats: ProbeManagerStats{
			Probes: map[uint16]*shared.ProbeStats{
				1: {ProbeID: 1, Hops: map[uint8]*shared.HopStats{3: {Sent: 1}}},
			},
		},
	}
	for _, m := range msgs {
		pm.outputChan <- m
	}
	close(pm.outputChan)
	return pm
}

func TestOutputRoutineForwardsToSink(t *testing.T) {
	run := &shared.ProbeRun{ProbeID: 1}
	pm := newOutputTestManager(
		outputMsg{msgType: "hop", probeNum: 1, ttl: 3},
		outputMsg{msgType: "hop", probeNum: 2, ttl: 3}, // unknown probe, skipped
		outputMsg{msgType: "delete_hops", probeNum: 1, deleteTTLs: []uint8{4, 5}},
		outputMsg{msgType: "probe_run", run: run},
		outputMsg{msgType: "discovery_update", discoveryStats: &shared.DiscoveryStats{FlowsUsed: 2}},
		outputMsg{msgType: "complete", probeNum: 1},
	)

	var s recordingSink
	pm.outputRoutine(&s)

	if !slices.Equal(s.hops, []uint8{3}) {
		t.Errorf("hops = %v, want [3]", s.hops)
	}
	if !slices.Equal(s.deleted, []uint8{4, 5}) {
		t.Errorf("deleted = %v, want [4 5]", s.deleted)
	}
	if len(s.runs) != 1 || s.runs[0] != run {
		t.Errorf("runs = %v, want [%p]", s.runs, run)
	}
	if len(s.discovery) != 1 || s.discovery[0].FlowsUsed != 2 {
		t.Errorf("discovery = %+v, want one update with FlowsUsed 2", s.discovery)
	}
	if !slices.Equal(s.completed, []uint16{1}) {
		t.Errorf("completed = %v, want [1]", s.completed)
	}
}

func TestOutputRoutineNilSinkDiscards(t *testing.T) {
	pm := newOutputTestManager(
		outputMsg{msgType: "hop", probeNum: 1, ttl: 3},
		outputMsg{msgType: "complete", probeNum: 1},
	)

	// Must drain the channel without panicking.
	pm.outputRoutine(nil)
}
