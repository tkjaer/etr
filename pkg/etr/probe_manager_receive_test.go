package etr

import (
	"testing"
	"time"
)

func newDeliveryTestProbe(statsBuf, respBuf int) *probe {
	return &probe{
		statsChan:    make(chan probeEvent, statsBuf),
		responseChan: make(chan responseEvent, respBuf),
	}
}

// runDelivery calls deliverResponse and fails the test if it blocks.
func runDelivery(t *testing.T, p *probe, stop <-chan struct{}) bool {
	t.Helper()
	done := make(chan bool, 1)
	go func() {
		done <- deliverResponse(p, stop, probeEvent{ProbeID: 1}, responseEvent{TTL: 3})
	}()
	select {
	case ok := <-done:
		return ok
	case <-time.After(time.Second):
		t.Fatal("deliverResponse blocked")
		return false
	}
}

func TestDeliverResponse(t *testing.T) {
	p := newDeliveryTestProbe(1, 1)

	if !runDelivery(t, p, make(chan struct{})) {
		t.Fatal("deliverResponse = false, want true")
	}
	if ev := <-p.statsChan; ev.ProbeID != 1 {
		t.Errorf("stats event = %+v, want probe 1", ev)
	}
	if ev := <-p.responseChan; ev.TTL != 3 {
		t.Errorf("response event = %+v, want TTL 3", ev)
	}
}

func TestDeliverResponseDropsWhenProbeNotReading(t *testing.T) {
	// A retired probe's response buffer is full and nobody reads it.
	p := newDeliveryTestProbe(1, 1)
	p.responseChan <- responseEvent{}

	if !runDelivery(t, p, make(chan struct{})) {
		t.Fatal("deliverResponse = false, want true")
	}
	if len(p.statsChan) != 1 {
		t.Error("stats event was not delivered")
	}
}

func TestDeliverResponseGivesUpAfterStop(t *testing.T) {
	// After stop, the stats processor is gone and its buffer may be full.
	p := newDeliveryTestProbe(1, 1)
	p.statsChan <- probeEvent{}
	stop := make(chan struct{})
	close(stop)

	if runDelivery(t, p, stop) {
		t.Error("deliverResponse = true after stop, want false")
	}
}
