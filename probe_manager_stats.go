package main

import (
	"context"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

// Top-level stats structure for all probes
type ProbeManagerStats struct {
	Probes   map[uint16]*ProbeStats
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
type ProbeStats struct {
	ProbeID uint16
	Hops    map[uint8]*HopStats // TTL -> hop stats
}

// Holds stats for a single hop (TTL)
type HopStats struct {
	IPs       map[string]*HopIPStats // IP string -> stats
	CurrentIP string                 // Most recent IP seen at this hop
	Received  uint                   // Number of probes received at this TTL
	Lost      uint                   // Number of probes lost at this TTL
	LossPct   float64                // Percentage loss at this TTL
}

// Holds stats for a single IP at a given hop
type HopIPStats struct {
	Min, Max   int64   // RTT in microseconds
	Avg        int64   // RTT in microseconds
	Last       int64   // Last RTT in microseconds
	StdDev     float64 // RTT standard deviation in microseconds
	Lost       uint    // Number of timeouts/losses
	LossPct    float64 // Percentage loss
	Responses  uint    // Number of responses
	Sum        int64   // Sum of RTTs for calculating average
	SumSquares int64   // Sum of squares for stddev calculation
	PTR        string  // PTR record for this IP
}

func (pm *ProbeManager) statsProcessor() {
	pm.stats = ProbeManagerStats{
		Probes:   make(map[uint16]*ProbeStats),
		Mutex:    sync.RWMutex{},
		TTLCache: ttlcache.New(ttlcache.WithTTL[TTLCacheKey, TTLCacheValue](pm.probeConfig.timeout)),
	}
	pm.stats.TTLCache.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, item *ttlcache.Item[TTLCacheKey, TTLCacheValue]) {
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
	go pm.stats.TTLCache.Start()
	defer pm.stats.TTLCache.Stop()

	for {
		select {
		case event, ok := <-pm.statsChan:
			if !ok {
				// Channel closed, exit
				log.Debug("statsChan closed, exiting statsProcessor")
				return
			}
			// Update internal stats (maps, counters, etc.)
			// Decide if/when to output to TUI/JSON
			switch event.EventType {
			case "sent":
				if data, ok := event.Data.(*ProbeEventDataSent); ok {
					pm.updateSentStats(event.ProbeID, data)
				}
			case "received":
				if data, ok := event.Data.(*ProbeEventDataReceived); ok {
					pm.updateReceivedStats(event.ProbeID, data)
					pm.notifyOutput(event.ProbeID, data.TTL)
				}
			case "timeout":
				if data, ok := event.Data.(*ProbeEventDataTimeout); ok {
					pm.updateTimeoutStats(event.ProbeID, data)
					pm.notifyOutput(event.ProbeID, data.TTL)
				}
			default:
				// Unknown event type
				log.Debugf("Unknown ProbeEvent type: %s", event.EventType)
			}
		case <-pm.stop:
			// Stop signal received, drain any remaining events and exit
			log.Debug("Stop signal received in statsProcessor, draining remaining events...")
			for {
				select {
				case event, ok := <-pm.statsChan:
					if !ok {
						return
					}
					// Process remaining events
					switch event.EventType {
					case "sent":
						if data, ok := event.Data.(*ProbeEventDataSent); ok {
							pm.updateSentStats(event.ProbeID, data)
						}
					case "received":
						if data, ok := event.Data.(*ProbeEventDataReceived); ok {
							pm.updateReceivedStats(event.ProbeID, data)
							pm.notifyOutput(event.ProbeID, data.TTL)
						}
					case "timeout":
						if data, ok := event.Data.(*ProbeEventDataTimeout); ok {
							pm.updateTimeoutStats(event.ProbeID, data)
							pm.notifyOutput(event.ProbeID, data.TTL)
						}
					}
				default:
					// No more events, exit
					log.Debug("No more events to drain, exiting statsProcessor")
					return
				}
			}
		}
	}
}

func (pm *ProbeManager) notifyOutput(probeID uint16, ttl uint8) {
	// Check if this is the last remaining hop for this probe
	pm.stats.Mutex.RLock()
	defer pm.stats.Mutex.RUnlock()
	_, exists := pm.stats.Probes[probeID]
	if !exists {
		pm.outputChan <- outputMsg{
			probeNum: uint(probeID),
			ttl:      ttl,
			msgType:  "complete",
		}
		return
	} else {
		pm.outputChan <- outputMsg{
			probeNum: uint(probeID),
			ttl:      ttl,
			msgType:  "hop",
		}
	}
}

func (pm *ProbeManager) updateSentStats(probeID uint16, data *ProbeEventDataSent) {
	pm.stats.Mutex.Lock()
	defer pm.stats.Mutex.Unlock()

	// Get or create ProbeStats entry
	probeStats, exists := pm.stats.Probes[probeID]
	if !exists {
		probeStats = &ProbeStats{
			ProbeID: probeID,
			Hops:    make(map[uint8]*HopStats),
		}
		pm.stats.Probes[probeID] = probeStats
	}

	pm.stats.TTLCache.Set(TTLCacheKey{ProbeID: probeID, TTL: data.TTL}, TTLCacheValue{SentTime: data.Timestamp}, pm.probeConfig.timeout)

	// Get or create HopStats entry
	hopStats, exists := probeStats.Hops[data.TTL]
	if !exists {
		hopStats = &HopStats{
			IPs: make(map[string]*HopIPStats),
		}
		probeStats.Hops[data.TTL] = hopStats
	}
}

func (pm *ProbeManager) updateReceivedStats(probeID uint16, data *ProbeEventDataReceived) {
	pm.stats.Mutex.Lock()
	defer pm.stats.Mutex.Unlock()

	// Check if we have stats for this probeID
	probeStats, exists := pm.stats.Probes[probeID]
	if !exists {
		// This should not happen; received a probe for unknown probeID
		log.Debugf("Received probe for unknown probeID %d", probeID)
		return
	}

	// Check if we have HopStats for this TTL
	hopStats, exists := probeStats.Hops[data.TTL]
	if !exists {
		log.Debugf("Received probe for unknown TTL %d on probeID %d", data.TTL, probeID)
		return
	}

	hopStats.Received++
	hopStats.LossPct = calculateLossPct(hopStats.Lost, hopStats.Received)

	// Get or create HopIPStats
	ipStats, exists := hopStats.IPs[data.IP]
	if !exists {
		// If hopStats only contains a single blank entry, we'll attribute it to this IP
		// and remove the blank entry
		if len(hopStats.IPs) == 1 {
			if blankStats, ok := hopStats.IPs[""]; ok {
				ipStats = blankStats
				delete(hopStats.IPs, "")
			}
		} else {
			ipStats = &HopIPStats{}
		}
		hopStats.IPs[data.IP] = ipStats
		// Request PTR lookup for new IP
		go pm.ptrManager.RequestPTR(data.IP)
	}

	// Update PTR if available
	if ptr, found := pm.ptrManager.GetPTR(data.IP); found && ptr != "" {
		ipStats.PTR = ptr
	}

	// Update current IP for this hop
	hopStats.CurrentIP = data.IP

	// Check and remove from TTL cache
	cacheKey := TTLCacheKey{ProbeID: probeID, TTL: data.TTL}
	sentTime := time.Time{}
	if cacheEntry, present := pm.stats.TTLCache.GetAndDelete(cacheKey); present {
		sentTime = cacheEntry.Value().SentTime
	} else {
		log.Debugf("Received probe for TTL %d on probeID %d that has already expired", data.TTL, probeID)
		return
	}

	// Update and calculate stats

	rtt := data.Timestamp.Sub(sentTime).Microseconds()

	ipStats.Last = rtt

	if ipStats.Min == 0 || rtt < ipStats.Min {
		ipStats.Min = rtt
	}

	if rtt > ipStats.Max {
		ipStats.Max = rtt
	}

	ipStats.Responses++

	ipStats.Sum += rtt
	ipStats.SumSquares += rtt * rtt
	ipStats.Avg = ipStats.Sum / int64(ipStats.Responses)
	ipStats.StdDev = calculateStdDev(ipStats.Sum, ipStats.SumSquares, ipStats.Responses)
}

func (pm *ProbeManager) updateTimeoutStats(probeID uint16, data *ProbeEventDataTimeout) {
	pm.stats.Mutex.Lock()
	defer pm.stats.Mutex.Unlock()

	probeStats, exists := pm.stats.Probes[probeID]
	if !exists {
		log.Debugf("Timeout for unknown probeID %d", probeID)
		return
	}

	hopStats, exists := probeStats.Hops[data.TTL]
	if !exists {
		log.Debugf("Timeout for unknown TTL %d on probeID %d", data.TTL, probeID)
		return
	}

	hopStats.Lost++
	hopStats.LossPct = calculateLossPct(hopStats.Lost, hopStats.Received)

	if ipStats, exists := hopStats.IPs[hopStats.CurrentIP]; !exists {
		hopStats.IPs[hopStats.CurrentIP] = &HopIPStats{
			Lost:    1,
			LossPct: 100.0,
		}
	} else {
		ipStats.Lost++
		ipStats.LossPct = calculateLossPct(ipStats.Lost, ipStats.Responses)
	}
}

func (pm *ProbeManager) getProbeHopStats(probeID uint16, ttl uint8) (HopStats, bool) {
	stats := HopStats{}
	exists := false
	pm.stats.Mutex.RLock()
	defer pm.stats.Mutex.RUnlock()
	if probe, ok := pm.stats.Probes[probeID]; ok {
		if hop, ok := probe.Hops[ttl]; ok {
			stats = *hop
			exists = true
		}
	}
	return stats, exists
}

func (pm *ProbeManager) getProbeStats(probeID uint16) (ProbeStats, bool) {
	stats := ProbeStats{}
	exists := false
	pm.stats.Mutex.RLock()
	defer pm.stats.Mutex.RUnlock()
	if probe, ok := pm.stats.Probes[probeID]; ok {
		stats = *probe
		exists = true
	}
	return stats, exists
}
