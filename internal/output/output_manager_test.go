package output

import (
	"testing"

	"github.com/tkjaer/etr/internal/shared"
)

// mockOutput is a mock implementation of Output for testing
type mockOutput struct {
	updateHopCalls        []updateHopCall
	deleteHopsCalls       []deleteHopsCall
	completeProbeCalls    []completeProbeCall
	completeProbeRunCalls []completeProbeRunCall
	closeCalls            int
}

type updateHopCall struct {
	probeID  uint16
	ttl      uint8
	hopStats shared.HopStats
}

type deleteHopsCall struct {
	probeID uint16
	ttls    []uint8
}

type completeProbeCall struct {
	probeID uint16
	stats   shared.ProbeStats
}

type completeProbeRunCall struct {
	run *shared.ProbeRun
}

func (m *mockOutput) UpdateHop(probeID uint16, ttl uint8, hopStats shared.HopStats) {
	m.updateHopCalls = append(m.updateHopCalls, updateHopCall{probeID, ttl, hopStats})
}

func (m *mockOutput) DeleteHops(probeID uint16, ttls []uint8) {
	m.deleteHopsCalls = append(m.deleteHopsCalls, deleteHopsCall{probeID, ttls})
}

func (m *mockOutput) CompleteProbe(probeID uint16, stats shared.ProbeStats) {
	m.completeProbeCalls = append(m.completeProbeCalls, completeProbeCall{probeID, stats})
}

func (m *mockOutput) CompleteProbeRun(run *shared.ProbeRun) {
	m.completeProbeRunCalls = append(m.completeProbeRunCalls, completeProbeRunCall{run})
}

func (m *mockOutput) Close() error {
	m.closeCalls++
	return nil
}

func TestOutputManager_Register(t *testing.T) {
	om := &OutputManager{}
	mock1 := &mockOutput{}
	mock2 := &mockOutput{}

	om.Register(mock1)
	if len(om.outputs) != 1 {
		t.Errorf("Register() outputs count = %d, want 1", len(om.outputs))
	}

	om.Register(mock2)
	if len(om.outputs) != 2 {
		t.Errorf("Register() outputs count = %d, want 2", len(om.outputs))
	}
}

func TestOutputManager_UpdateHop(t *testing.T) {
	om := &OutputManager{}
	mock1 := &mockOutput{}
	mock2 := &mockOutput{}
	om.Register(mock1)
	om.Register(mock2)

	hopStats := shared.HopStats{CurrentIP: "192.0.2.1"}
	om.UpdateHop(1, 5, hopStats)

	if len(mock1.updateHopCalls) != 1 {
		t.Errorf("mock1 UpdateHop calls = %d, want 1", len(mock1.updateHopCalls))
	}
	if len(mock2.updateHopCalls) != 1 {
		t.Errorf("mock2 UpdateHop calls = %d, want 1", len(mock2.updateHopCalls))
	}

	if mock1.updateHopCalls[0].probeID != 1 {
		t.Errorf("probeID = %d, want 1", mock1.updateHopCalls[0].probeID)
	}
	if mock1.updateHopCalls[0].ttl != 5 {
		t.Errorf("ttl = %d, want 5", mock1.updateHopCalls[0].ttl)
	}
	if mock1.updateHopCalls[0].hopStats.CurrentIP != "192.0.2.1" {
		t.Errorf("hopStats.CurrentIP = %s, want 192.0.2.1", mock1.updateHopCalls[0].hopStats.CurrentIP)
	}
}

func TestOutputManager_DeleteHops(t *testing.T) {
	om := &OutputManager{}
	mock := &mockOutput{}
	om.Register(mock)

	ttls := []uint8{1, 2, 3}
	om.DeleteHops(10, ttls)

	if len(mock.deleteHopsCalls) != 1 {
		t.Fatalf("DeleteHops calls = %d, want 1", len(mock.deleteHopsCalls))
	}
	if mock.deleteHopsCalls[0].probeID != 10 {
		t.Errorf("probeID = %d, want 10", mock.deleteHopsCalls[0].probeID)
	}
	if len(mock.deleteHopsCalls[0].ttls) != 3 {
		t.Errorf("ttls length = %d, want 3", len(mock.deleteHopsCalls[0].ttls))
	}
}

func TestOutputManager_CompleteProbe(t *testing.T) {
	om := &OutputManager{}
	mock := &mockOutput{}
	om.Register(mock)

	stats := shared.ProbeStats{ProbeID: 42}
	om.CompleteProbe(42, stats)

	if len(mock.completeProbeCalls) != 1 {
		t.Fatalf("CompleteProbe calls = %d, want 1", len(mock.completeProbeCalls))
	}
	if mock.completeProbeCalls[0].probeID != 42 {
		t.Errorf("probeID = %d, want 42", mock.completeProbeCalls[0].probeID)
	}
}

func TestOutputManager_CompleteProbeRun(t *testing.T) {
	om := &OutputManager{}
	mock := &mockOutput{}
	om.Register(mock)

	run := &shared.ProbeRun{DestinationIP: "203.0.113.1"}
	om.CompleteProbeRun(run)

	if len(mock.completeProbeRunCalls) != 1 {
		t.Fatalf("CompleteProbeRun calls = %d, want 1", len(mock.completeProbeRunCalls))
	}
	if mock.completeProbeRunCalls[0].run.DestinationIP != "203.0.113.1" {
		t.Errorf("destinationIP = %s, want 203.0.113.1", mock.completeProbeRunCalls[0].run.DestinationIP)
	}
}

func TestOutputManager_Close(t *testing.T) {
	om := &OutputManager{}
	mock1 := &mockOutput{}
	mock2 := &mockOutput{}
	om.Register(mock1)
	om.Register(mock2)

	om.Close()

	if mock1.closeCalls != 1 {
		t.Errorf("mock1 Close calls = %d, want 1", mock1.closeCalls)
	}
	if mock2.closeCalls != 1 {
		t.Errorf("mock2 Close calls = %d, want 1", mock2.closeCalls)
	}
}

func TestOutputManager_MultipleOutputs(t *testing.T) {
	om := &OutputManager{}
	mock1 := &mockOutput{}
	mock2 := &mockOutput{}
	mock3 := &mockOutput{}
	om.Register(mock1)
	om.Register(mock2)
	om.Register(mock3)

	// Test that all outputs receive all calls
	om.UpdateHop(1, 1, shared.HopStats{})
	om.DeleteHops(1, []uint8{1})
	om.CompleteProbe(1, shared.ProbeStats{})
	om.CompleteProbeRun(&shared.ProbeRun{})
	om.Close()

	for i, mock := range []*mockOutput{mock1, mock2, mock3} {
		if len(mock.updateHopCalls) != 1 {
			t.Errorf("mock%d UpdateHop calls = %d, want 1", i+1, len(mock.updateHopCalls))
		}
		if len(mock.deleteHopsCalls) != 1 {
			t.Errorf("mock%d DeleteHops calls = %d, want 1", i+1, len(mock.deleteHopsCalls))
		}
		if len(mock.completeProbeCalls) != 1 {
			t.Errorf("mock%d CompleteProbe calls = %d, want 1", i+1, len(mock.completeProbeCalls))
		}
		if len(mock.completeProbeRunCalls) != 1 {
			t.Errorf("mock%d CompleteProbeRun calls = %d, want 1", i+1, len(mock.completeProbeRunCalls))
		}
		if mock.closeCalls != 1 {
			t.Errorf("mock%d Close calls = %d, want 1", i+1, mock.closeCalls)
		}
	}
}
