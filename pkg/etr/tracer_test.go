package etr

import (
	"context"
	"errors"
	"testing"
)

type startRecorder struct {
	recordingSink
	started bool
}

func (s *startRecorder) Start() { s.started = true }

func TestNewRejectsInvalidConfig(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New(Config{}) succeeded, want an error for the missing destination")
	}
}

func TestRunWhileRunning(t *testing.T) {
	tr, err := New(Config{Destination: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	tr.running.Store(true)

	if _, err := tr.Run(context.Background(), nil); !errors.Is(err, ErrRunning) {
		t.Errorf("Run() error = %v, want ErrRunning", err)
	}
}

func TestRunCancelledDuringSetup(t *testing.T) {
	tr, err := New(Config{Destination: "etr-test.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Run twice: the first run must not leave the tracer marked as running
	for range 2 {
		var s startRecorder
		if _, err := tr.Run(ctx, &s); !errors.Is(err, context.Canceled) {
			t.Errorf("Run() error = %v, want context.Canceled", err)
		}
		if s.started {
			t.Error("Start was called although setup failed")
		}
	}
}
