package main

import "time"

type probeStats struct {
	sourcePort         uint16
	pathHash           string
	destinationReached bool
	destinationLoss    uint8
	destinationLatency time.Duration
	probeNum           uint
}

type probeSummaryStats struct {
}
