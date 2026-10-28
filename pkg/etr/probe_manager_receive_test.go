package etr

import (
	"bytes"
	"log/slog"
	"strings"
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

func TestLogReceived(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	logReceived(2, &probeEventDataReceived{
		ProbeNum:  5,
		TTL:       6,
		IP:        "192.0.2.1",
		Flag:      "TTL",
		Timestamp: time.Date(2026, 10, 28, 8, 45, 49, 394049000, time.UTC),
	})

	got := buf.String()
	for _, want := range []string{
		`level=DEBUG`,
		`msg="Received response"`,
		`probe_id=2`,
		`probe_num=5`,
		`ttl=6`,
		`ip=192.0.2.1`,
		`reply=time_exceeded`,
		`recv_time=2026-10-28T08:45:49.394049Z`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("log output missing %q:\n%s", want, got)
		}
	}
}
