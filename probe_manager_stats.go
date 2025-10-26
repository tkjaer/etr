package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/jellydator/ttlcache/v3"
)

// ProbeRun represents a single TTL iteration for one probe
type ProbeRun struct {
	ProbeID         uint16    `json:"probe_id"`
	ProbeNum        uint      `json:"probe_num"`        // Which iteration (0, 1, 2, ...)
	PathHash        string    `json:"path_hash"`        // Hash of the path taken
	SourceIP        string    `json:"source_ip"`        // Source IP address
	SourcePort      uint16    `json:"source_port"`      // Source port
	DestinationIP   string    `json:"destination_ip"`   // Destination IP address
	DestinationPort uint16    `json:"destination_port"` // Destination port
	DestinationPTR  string    `json:"destination_ptr"`  // PTR record for destination
	Protocol        string    `json:"protocol"`         // Protocol (TCP/UDP)
	ReachedDest     bool      `json:"reached_dest"`     // Whether destination was reached
	Hops            []*HopRun `json:"hops"`             // Hops sorted by TTL
	Timestamp       time.Time `json:"timestamp"`
}

// HopRun represents the result for a single TTL in one probe run
type HopRun struct {
	TTL      uint8     `json:"ttl"`
	IP       string    `json:"ip"`        // IP that responded (empty if timeout)
	RTT      int64     `json:"rtt"`       // RTT in microseconds (0 if timeout)
	Timeout  bool      `json:"timeout"`   // Whether this hop timed out
	PTR      string    `json:"ptr"`       // PTR record for this IP
	RecvTime time.Time `json:"recv_time"` // When response was received
}

// ProbeRunBuilder is used internally to build a ProbeRun incrementally
type ProbeRunBuilder struct {
	ProbeID   uint16
	ProbeNum  uint
	Hops      map[uint8]*HopRun // TTL -> hop result (internal map for building)
	Timestamp time.Time
}

// Top-level stats structure for all probes
type ProbeManagerStats struct {
	Probes      map[uint16]*ProbeStats
	CurrentRuns map[uint16]*ProbeRunBuilder // Current probe run being built for each probe ID
	Mutex       sync.RWMutex
	TTLCache    *ttlcache.Cache[TTLCacheKey, TTLCacheValue]
}

// Key for the TTL cache
type TTLCacheKey struct {
	ProbeID  uint16
	ProbeNum uint // Which iteration
	TTL      uint8
}

// Value stored in the TTL cache
type TTLCacheValue struct {
	SentTime time.Time
}

// Holds stats for a single probe instance
type ProbeStats struct {
	ProbeID uint16              `json:"probe_id"`
	Hops    map[uint8]*HopStats `json:"hops"` // TTL -> hop stats
}

// Holds stats for a single hop (TTL)
type HopStats struct {
	IPs       map[string]*HopIPStats `json:"ips"`        // IP string -> stats
	CurrentIP string                 `json:"current_ip"` // Most recent IP seen at this hop
	Received  uint                   `json:"received"`   // Number of probes received at this TTL
	Lost      uint                   `json:"lost"`       // Number of probes lost at this TTL
	LossPct   float64                `json:"loss_pct"`   // Percentage loss at this TTL
}

// Holds stats for a single IP at a given hop
type HopIPStats struct {
	Min        int64   `json:"min"`         // RTT in microseconds
	Max        int64   `json:"max"`         // RTT in microseconds
	Avg        int64   `json:"avg"`         // RTT in microseconds
	Last       int64   `json:"last"`        // Last RTT in microseconds
	StdDev     float64 `json:"stddev"`      // RTT standard deviation in microseconds
	Lost       uint    `json:"lost"`        // Number of timeouts/losses
	LossPct    float64 `json:"loss_pct"`    // Percentage loss
	Responses  uint    `json:"responses"`   // Number of responses
	Sum        int64   `json:"sum"`         // Sum of RTTs for calculating average
	SumSquares int64   `json:"sum_squares"` // Sum of squares for stddev calculation
	PTR        string  `json:"ptr"`         // PTR record for this IP
}

func (pm *ProbeManager) statsProcessor() {
	pm.stats = ProbeManagerStats{
		Probes:      make(map[uint16]*ProbeStats),
		CurrentRuns: make(map[uint16]*ProbeRunBuilder),
		Mutex:       sync.RWMutex{},
		TTLCache:    ttlcache.New(ttlcache.WithTTL[TTLCacheKey, TTLCacheValue](pm.probeConfig.timeout)),
	}
	pm.stats.TTLCache.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, item *ttlcache.Item[TTLCacheKey, TTLCacheValue]) {
		if reason == ttlcache.EvictionReasonExpired {
			pm.statsChan <- ProbeEvent{
				ProbeID:   item.Key().ProbeID,
				EventType: "timeout",
				Data: &ProbeEventDataTimeout{
					ProbeNum: item.Key().ProbeNum,
					SentTime: item.Value().SentTime,
					TTL:      item.Key().TTL,
				},
			}
		}
	})
	go pm.stats.TTLCache.Start()

	// Request PTR lookup for destination IP early
	go pm.ptrManager.RequestPTR(pm.probeConfig.route.Destination.String())
	defer pm.stats.TTLCache.Stop()

	for {
		select {
		case event, ok := <-pm.statsChan:
			if !ok {
				// Channel closed, exit
				slog.Debug("Stats channel closed, exiting stats processor")
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
			case "iteration_complete":
				if data, ok := event.Data.(*ProbeEventDataIterationComplete); ok {
					// Output the completed probe run
					pm.outputProbeRun(event.ProbeID, data)
				}
			case "complete":
				// Probe is complete, notify output with special marker
				pm.outputChan <- outputMsg{
					probeNum: uint(event.ProbeID),
					msgType:  "complete",
				}
			default:
				// Unknown event type
				slog.Debug("Unknown probe event type", "type", event.EventType)
			}
		case <-pm.stop:
			// Stop signal received, drain any remaining events and exit
			slog.Debug("Stop signal received in stats processor, draining remaining events")
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
					case "complete":
						// Probe is complete, notify output
						pm.outputChan <- outputMsg{
							probeNum: uint(event.ProbeID),
							msgType:  "complete",
						}
					}
				default:
					// No more events, exit
					slog.Debug("No more events to drain, exiting stats processor")
					return
				}
			}
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

	pm.stats.TTLCache.Set(TTLCacheKey{ProbeID: probeID, ProbeNum: data.ProbeNum, TTL: data.TTL}, TTLCacheValue{SentTime: data.Timestamp}, pm.probeConfig.timeout)

	// Also build/update current ProbeRun for JSON output
	run, exists := pm.stats.CurrentRuns[probeID]
	if !exists || run.ProbeNum != data.ProbeNum {
		// New run
		run = &ProbeRunBuilder{
			ProbeID:   probeID,
			ProbeNum:  data.ProbeNum,
			Hops:      make(map[uint8]*HopRun),
			Timestamp: data.Timestamp,
		}
		pm.stats.CurrentRuns[probeID] = run
	}

	// Initialize hop as pending (will be updated on receive or timeout)
	if _, ok := run.Hops[data.TTL]; !ok {
		run.Hops[data.TTL] = &HopRun{
			TTL:     data.TTL,
			Timeout: true, // Assume timeout until we get a response
		}
	}

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
		slog.Debug("Received probe for unknown probe ID", "probe_id", probeID)
		return
	}

	// Check if we have HopStats for this TTL
	hopStats, exists := probeStats.Hops[data.TTL]
	if !exists {
		slog.Debug("Received probe for unknown TTL", "ttl", data.TTL, "probe_id", probeID)
		return
	}

	hopStats.Received++
	hopStats.LossPct = calculateLossPct(hopStats.Lost, hopStats.Received)

	// Get or create HopIPStats
	ipStats, exists := hopStats.IPs[data.IP]
	if !exists {
		// If hopStats only contains a single blank entry (meaning we've had
		// packet loss on this hop until now), we'll attribute it to this IP and
		// remove the blank entry
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
	cacheKey := TTLCacheKey{ProbeID: probeID, ProbeNum: data.ProbeNum, TTL: data.TTL}
	sentTime := time.Time{}
	if cacheEntry, present := pm.stats.TTLCache.GetAndDelete(cacheKey); present {
		sentTime = cacheEntry.Value().SentTime
	} else {
		slog.Debug("Received probe for TTL that has already expired", "ttl", data.TTL, "probe_id", probeID)
		return
	}

	// Update and calculate stats

	rtt := data.Timestamp.Sub(sentTime).Microseconds()

	// Get the latest PTR from the manager
	ptrValue := ipStats.PTR
	if ptr, found := pm.ptrManager.GetPTR(data.IP); found && ptr != "" {
		ptrValue = ptr
		// Update ipStats.PTR as well for consistency
		ipStats.PTR = ptr
	}

	// Update ProbeRun for this iteration
	if run, ok := pm.stats.CurrentRuns[probeID]; ok && run.ProbeNum == data.ProbeNum {
		run.Hops[data.TTL] = &HopRun{
			TTL:      data.TTL,
			IP:       data.IP,
			RTT:      rtt,
			Timeout:  false,
			PTR:      ptrValue,
			RecvTime: data.Timestamp,
		}
	}

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
	// If we've received a non-TTL response and stats exists for > this TTL, we'll
	// delete the statistics for higher TTLs as they are no longer relevant
	if data.Flag != "TTL" && len(probeStats.Hops) > int(data.TTL) {
		for ttl := data.TTL + 1; ; ttl++ {
			if _, ok := probeStats.Hops[ttl]; ok {
				delete(probeStats.Hops, ttl)
			} else {
				break
			}
		}
	}
}

func (pm *ProbeManager) updateTimeoutStats(probeID uint16, data *ProbeEventDataTimeout) {
	pm.stats.Mutex.Lock()
	defer pm.stats.Mutex.Unlock()

	probeStats, exists := pm.stats.Probes[probeID]
	if !exists {
		slog.Debug("Timeout for unknown probe ID", "probe_id", probeID)
		return
	}

	hopStats, exists := probeStats.Hops[data.TTL]
	if !exists {
		slog.Debug("Timeout for unknown TTL", "ttl", data.TTL, "probe_id", probeID)
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

// Notifies the output system of a hop update for TUI
func (pm *ProbeManager) notifyOutput(probeID uint16, ttl uint8) {
	pm.outputChan <- outputMsg{
		probeNum: uint(probeID),
		ttl:      ttl,
		msgType:  "hop",
	}
}

// Outputs the completed ProbeRun for a given probeID and iteration
func (pm *ProbeManager) outputProbeRun(probeID uint16, data *ProbeEventDataIterationComplete) {
	// Convert current ProbeStats to ProbeRun format for this iteration
	pm.stats.Mutex.RLock()
	probeStats, exists := pm.stats.Probes[probeID]
	pm.stats.Mutex.RUnlock()

	if !exists {
		return
	}

	// Build temporary map of hops
	hopsMap := make(map[uint8]*HopRun)

	pm.stats.Mutex.RLock()
	for ttl, hopStats := range probeStats.Hops {
		if hopStats.CurrentIP != "" {
			// Find the IP stats for this hop
			ipStats, ok := hopStats.IPs[hopStats.CurrentIP]
			if ok {
				// Get the latest PTR from the manager
				ptrValue := ipStats.PTR
				if ptr, found := pm.ptrManager.GetPTR(hopStats.CurrentIP); found && ptr != "" {
					ptrValue = ptr
				}
				hopsMap[ttl] = &HopRun{
					TTL:      ttl,
					IP:       hopStats.CurrentIP,
					RTT:      ipStats.Last,
					Timeout:  false,
					PTR:      ptrValue,
					RecvTime: data.Timestamp, // Approximate
				}
			}
		} else if hopStats.Lost > 0 {
			// This hop timed out
			hopsMap[ttl] = &HopRun{
				TTL:     ttl,
				IP:      "",
				RTT:     0,
				Timeout: true,
				PTR:     "",
			}
		}
	}
	pm.stats.Mutex.RUnlock()

	// Convert map to sorted slice
	hopsSlice := make([]*HopRun, 0, len(hopsMap))
	for ttl := uint8(1); ttl != 0; ttl++ {
		if hop, ok := hopsMap[ttl]; ok {
			hopsSlice = append(hopsSlice, hop)
		}
	}

	// Calculate path hash using the configured algorithm
	pathHash := calculatePathHashFromHops(hopsSlice, pm.outputConfig.hashAlgorithm)

	// Determine protocol name
	protocol := "TCP"
	if pm.probeConfig.protocolConfig.transport == layers.IPProtocolUDP {
		protocol = "UDP"
	}

	// Check if destination was reached (last hop matches destination)
	reachedDest := false
	if len(hopsSlice) > 0 {
		lastHop := hopsSlice[len(hopsSlice)-1]
		if lastHop.IP == pm.probeConfig.route.Destination.String() {
			reachedDest = true
		}
	}

	// Get destination PTR
	destIP := pm.probeConfig.route.Destination.String()
	destPTR := ""
	if ptr, found := pm.ptrManager.GetPTR(destIP); found && ptr != "" {
		destPTR = ptr
	}

	// Build ProbeRun with all metadata
	run := &ProbeRun{
		ProbeID:         probeID,
		ProbeNum:        data.ProbeNum,
		PathHash:        pathHash,
		SourceIP:        pm.probeConfig.route.Source.String(),
		SourcePort:      pm.probeConfig.srcPort + probeID, // Each probe uses a different source port
		DestinationIP:   destIP,
		DestinationPort: pm.probeConfig.dstPort,
		DestinationPTR:  destPTR,
		Protocol:        protocol,
		ReachedDest:     reachedDest,
		Hops:            hopsSlice,
		Timestamp:       data.Timestamp,
	}

	// Send to output
	pm.outputChan <- outputMsg{
		probeNum: data.ProbeNum,
		msgType:  "probe_run",
		run:      run,
	}
}
