package main

import (
	"log/slog"
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
		slog.Debug("No stats for IP", "ip", hopStats.CurrentIP, "probe_id", probeID, "ttl", ttl)
		return
	}
	// FIXME: Handle multiple IPs per TTL

	//  Host                                              Loss%   Snt   Last   Avg  Best  Wrst StDev
	fmt.Printf("%2d. %-48s %6.1f%% %5d %6.1f %6.1f %6.1f %6.1f %6.1f\n",
		ttl, hopStats.CurrentIP, hopStats.LossPct,
		s.Responses+s.Lost,
		float64(s.Last)/1000,
		float64(s.Avg)/1000,
		float64(s.Min)/1000,
		float64(s.Max)/1000,
		float64(s.StdDev)/1000,
	)
}

func (t *TUIOutput) CompleteProbe(probeID uint16, stats ProbeStats) {
	// No-op for TUI, as it updates per-hop
}

func (t *TUIOutput) Close() error { return nil }
