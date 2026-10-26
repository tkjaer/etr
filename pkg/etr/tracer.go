package etr

import (
	"context"
	"errors"
	"sync/atomic"
)

// ErrRunning is returned by Run while another run is in progress
var ErrRunning = errors.New("run already in progress")

// Tracer runs traceroutes for a Config, one run at a time
type Tracer struct {
	cfg     Config
	running atomic.Bool
}

// New validates cfg and returns a Tracer for it
func New(cfg Config) (*Tracer, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Tracer{cfg: cfg}, nil
}

// Run sets up a new run and sends results to sink until the probes finish or
// ctx is cancelled. A nil sink discards results, and Run doesn't close it. If
// sink implements Starter, Start is called once setup has succeeded.
func (t *Tracer) Run(ctx context.Context, sink Sink) (*Result, error) {
	if !t.running.CompareAndSwap(false, true) {
		return nil, ErrRunning
	}
	defer t.running.Store(false)

	pm, err := newProbeManager(ctx, t.cfg)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		pm.handle.Close()
		return nil, err
	}
	if s, ok := sink.(Starter); ok {
		s.Start()
	}
	return pm.run(ctx, sink)
}
