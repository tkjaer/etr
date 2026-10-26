package etr_test

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	"github.com/tkjaer/etr/pkg/etr"
)

// printSink prints each completed probe run
type printSink struct{}

func (printSink) UpdateHop(uint16, uint8, etr.HopStats)   {}
func (printSink) DeleteHops(uint16, []uint8)              {}
func (printSink) CompleteProbe(uint16, etr.ProbeStats)    {}
func (printSink) UpdateDiscoveryStats(etr.DiscoveryStats) {}
func (printSink) CompleteProbeRun(run *etr.ProbeRun) {
	fmt.Printf("probe %d: path %s, %d hops\n", run.ProbeID, run.PathHash, len(run.Hops))
}

// Example needs raw packet access, so it has no Output line and never runs
func Example() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT)
	defer stop()

	tracer, err := etr.New(etr.Config{Destination: "example.com", Count: 3})
	if err != nil {
		log.Fatal(err)
	}
	if _, err := tracer.Run(ctx, printSink{}); err != nil {
		log.Fatal(err)
	}
}
