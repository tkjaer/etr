package main

import (
	"fmt"
	"sync"
)

// TUIOutput updates the terminal in real time
type TUIOutput struct {
	mu sync.Mutex
}

func (t *TUIOutput) UpdateHop(probeID uint16, ttl uint8, hopStats HopStats) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := hopStats.IPs[hopStats.CurrentIP]
	if s == nil {
		log.Debugf("No stats for IP %s on probe %d TTL %d", hopStats.CurrentIP, probeID, ttl)
		return
	}
	// FIXME: Handle multiple IPs per TTL
	fmt.Printf("Probe %d TTL %d: IP=%s RTT(avg)=%.2fms HopLost=%d HopPCTLoss=%.2f IPLost=%d IPPCTLoss=%.2f\n",
		probeID, ttl, hopStats.CurrentIP, float64(s.Avg)/1000, hopStats.Lost, hopStats.LossPct, s.Lost, s.LossPct)
}

func (t *TUIOutput) CompleteProbe(probeID uint16, stats ProbeStats) {
	// No-op for TUI, as it updates per-hop
}

func (t *TUIOutput) Close() error { return nil }
