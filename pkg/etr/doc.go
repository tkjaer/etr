// Package etr runs ECMP-aware traceroutes, probing several flows in parallel
// to find the paths between this host and a destination.
//
// It sends and captures packets with libpcap through cgo, so building needs
// libpcap and running needs raw packet access (usually root).
//
// Create a Tracer with New and call Run with a Sink to receive results. Run
// may be called again once a run has finished, but returns ErrRunning while
// one is in progress. The sink is called from a single goroutine and should
// return quickly, as a slow sink holds up probing.
//
// The package logs through the default slog logger.
package etr
