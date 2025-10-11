package main

import (
	"context"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

// Top-level stats structure for all probes
type ProbeStats struct {
	Probes   map[uint16]*Probe
	Mutex    sync.RWMutex
	TTLCache *ttlcache.Cache[TTLCacheKey, TTLCacheValue]
}

// Key for the TTL cache
type TTLCacheKey struct {
	ProbeID uint16
	TTL     uint8
}

// Value stored in the TTL cache
type TTLCacheValue struct {
	SentTime time.Time
}

// Holds stats for a single probe instance
type Probe struct {
	ProbeID  uint16
	Hops     map[uint8]*HopStats // TTL -> hop stats
	Sent     uint
	Received uint
}

// Holds stats for a single hop (TTL)
type HopStats struct {
	IPs       map[string]*HopIPStats // IP string -> stats
	CurrentIP string                 // Most recent IP seen at this hop
}

// Holds stats for a single IP at a given hop
type HopIPStats struct {
	Min, Max   int64   // RTT in microseconds
	Avg        int64   // RTT in microseconds
	Stdev      float64 // RTT standard deviation in microseconds
	Loss       uint    // Number of timeouts/losses
	Responses  uint    // Number of responses
	Sum        int64   // Sum of RTTs for calculating average
	SumSquares int64   // Sum of squares for stddev calculation
}

func (pm *ProbeManager) statsProcessor() {
	stats := ProbeStats{
		Probes:   make(map[uint16]*Probe),
		Mutex:    sync.RWMutex{},
		TTLCache: ttlcache.New[TTLCacheKey, TTLCacheValue](ttlcache.WithTTL[TTLCacheKey, TTLCacheValue](pm.probeConfig.timeout)),
	}
	stats.TTLCache.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, item *ttlcache.Item[TTLCacheKey, TTLCacheValue]) {
		if reason == ttlcache.EvictionReasonExpired {
			pm.statsChan <- ProbeEvent{
				ProbeID:   item.Key().ProbeID,
				EventType: "timeout",
				Data: &ProbeEventDataTimeout{
					SentTime: item.Value().SentTime,
					TTL:      item.Key().TTL,
				},
			}
		}
	})
	go stats.TTLCache.Start()
	defer stats.TTLCache.Stop()

	for event := range pm.statsChan {
		// Update internal stats (maps, counters, etc.)
		// Decide if/when to output to TUI/JSON
		switch event.EventType {
		case "sent":
			if data, ok := event.Data.(*ProbeEventDataSent); ok {
				pm.updateSentStats(&stats, event.ProbeID, data)
			}
		case "received":
			if data, ok := event.Data.(*ProbeEventDataReceived); ok {
				pm.updateReceivedStats(&stats, event.ProbeID, data)
			}
		case "timeout":
			// if data, ok := event.Data.(*ProbeEventDataTimeout); ok {
			// }
			// Update loss, output to TUI
			pm.outputChan <- outputMsg{ /* ... */ }
		}
		// When a probe run completes, output summary to JSON
	}
}

func (pm *ProbeManager) updateSentStats(stats *ProbeStats, probeID uint16, data *ProbeEventDataSent) {
	stats.Mutex.Lock()
	defer stats.Mutex.Unlock()

	// Get or create ProbeStats entry
	probeStats, exists := stats.Probes[probeID]
	if !exists {
		probeStats = &Probe{
			ProbeID: probeID,
			Sent:    0,
			// FIXME: Do we actually want a received counter here?
			Received: 0,
			Hops:     make(map[uint8]*HopStats),
		}
		stats.Probes[probeID] = probeStats
	}

	stats.TTLCache.Set(TTLCacheKey{ProbeID: probeID, TTL: data.TTL}, TTLCacheValue{SentTime: data.Timestamp}, pm.probeConfig.timeout)
	probeStats.Sent++
}

func (pm *ProbeManager) updateReceivedStats(stats *TracerouteStats, probeID uint16, data *ProbeEventDataReceived) {
	stats.Mutex.Lock()
	defer stats.Mutex.Unlock()

	// Get or create ProbeStats
	probeStats, exists := stats.Probes[probeID]
	if !exists {
		probeStats = &ProbeStats{
			ProbeID: probeID,
			Hops:    make(map[uint8]*HopStats),
		}
		stats.Probes[probeID] = probeStats
	}

	// Get or create HopStats
	hopStats, exists := probeStats.Hops[data.TTL]
	if !exists {
		hopStats = &HopStats{
			TTL: data.TTL,
			IPs: make(map[string]*HopIPStats),
		}
		probeStats.Hops[data.TTL] = hopStats
	}
	hopStats.CurrentIP = data.IP

	// Get or create HopIPStats
	ipStats, exists := hopStats.IPs[data.IP]
	if !exists {
		ipStats = &HopIPStats{
			IP: data.IP,
		}
		hopStats.IPs[data.IP] = ipStats
	}

	// Update RTT stats (assuming we have sentTime stored somewhere)
	rtt := data.Timestamp.Sub( /* sentTime */ ).Microseconds()
	ipStats.Responses++
	ipStats.SumSquares += rtt * rtt
	ipStats.Avg = ((ipStats.Avg * int64(ipStats.Responses-1)) + rtt) / int64(ipStats.Responses)
	if ipStats.Min == 0 || rtt < ipStats.Min {
		ipStats.Min = rtt
	}
	if rtt > ipStats.Max {
		ipStats.Max = rtt
	}
	if ipStats.Responses > 1 {
		meanSquare := float64(ipStats.SumSquares) / float64(ipStats.Responses)
		ipStats.Stdev = sqrt(meanSquare - float64(ipStats.Avg*ipStats.Avg))
	}

	probeStats.Received++
}
