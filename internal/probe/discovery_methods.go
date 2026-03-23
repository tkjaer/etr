package probe

import (
	"log/slog"

	"github.com/tkjaer/etr/internal/shared"
)

// TrackDiscoveryPath records a completed probe run during discovery.
// It updates per-probe stability and, when a path is confirmed, retires
// the probe and spawns a replacement with a new source port.
func (pm *ProbeManager) TrackDiscoveryPath(probeID uint16, probeNum uint, pathHash string, hops []*shared.HopRun) {
	pm.discoveryMu.Lock()
	defer pm.discoveryMu.Unlock()

	if !pm.discovery.enabled {
		return
	}

	// Per-probe stability tracking — a path hash is only recorded as
	// "discovered" once it has been observed for perProbeStableRounds
	// consecutive rounds, filtering out transient jitter from non-responding hops.
	probeState, exists := pm.discovery.perProbeState[probeID]
	if !exists {
		probeState = &probeDiscoveryState{
			lastPathHash:      pathHash,
			stableRoundsCount: 1,
		}
		pm.discovery.perProbeState[probeID] = probeState
	} else if pathHash == probeState.lastPathHash {
		probeState.stableRoundsCount++
		// If every hop responded, the hash is maximally complete —
		// confirm after just 2 stable rounds instead of the full count.
		allResponded := true
		for _, h := range hops {
			if h.Timeout {
				allResponded = false
				break
			}
		}
		requiredRounds := pm.discovery.perProbeStableRounds
		if allResponded && requiredRounds > 2 {
			requiredRounds = 2
		}
		if probeState.stableRoundsCount >= requiredRounds {
			// Path confirmed stable — record it and check convergence
			srcPort := pm.probeConfig.srcPort + probeID
			newPath := false
			if pathHash != "" {
				if _, seen := pm.discovery.allDiscoveredPaths[pathHash]; !seen {
					newPath = true
					hopIPs := make([]string, len(hops))
					for i, h := range hops {
						if h.Timeout {
							hopIPs[i] = "*"
						} else {
							hopIPs[i] = h.IP
						}
					}
					pm.discovery.allDiscoveredPaths[pathHash] = discoveredPathInfo{
						sourcePort: srcPort,
						hops:       hopIPs,
					}
				}
			}

			pm.discovery.confirmedProbes++
			if newPath {
				pm.discovery.noNewPathsCount = 0
			} else {
				pm.discovery.noNewPathsCount++
			}

			if pm.shouldStopDiscoveryNoLock() {
				pm.stopOnce.Do(func() { close(pm.stop) })
				return
			}

			// Retire this probe and spawn a replacement
			pm.retireAndReplaceProbeNoLock(probeID)
		}
	} else {
		probeState.stableRoundsCount = 1
		probeState.lastPathHash = pathHash
	}
}

// retireAndReplaceProbeNoLock stops a confirmed probe and starts a new one.
// Caller must hold discoveryMu write lock.
func (pm *ProbeManager) retireAndReplaceProbeNoLock(probeID uint16) {
	// Clean up old probe's discovery state
	delete(pm.discovery.perProbeState, probeID)
	delete(pm.discovery.activeProbes, probeID)

	// Close the probe's discovery channel to stop its Run loop
	pm.probeTracker.mutex.Lock()
	if p, exists := pm.probeTracker.probes[probeID]; exists && p.discoveryStop != nil {
		close(p.discoveryStop)
	}
	pm.probeTracker.mutex.Unlock()

	// Check budget before spawning replacement
	if pm.discovery.flowBudget > 0 && pm.discovery.flowsUsed >= pm.discovery.flowBudget {
		return
	}
	nextID := pm.discovery.nextProbeID
	if uint32(pm.probeConfig.srcPort)+uint32(nextID) > 65535 {
		return
	}

	pm.discovery.flowsUsed++
	pm.discovery.nextProbeID = nextID + 1
	pm.discovery.perProbeState[nextID] = &probeDiscoveryState{}
	pm.discovery.activeProbes[nextID] = struct{}{}

	slog.Debug("Discovery: spawning new probe", "new_probe_id", nextID,
		"src_port", pm.probeConfig.srcPort+nextID)

	// Spawn outside the lock to avoid holding discoveryMu during goroutine start
	go pm.spawnDiscoveryProbe(nextID)
}

// shouldStopDiscoveryNoLock checks convergence conditions.
// Caller must hold discoveryMu write lock.
func (pm *ProbeManager) shouldStopDiscoveryNoLock() bool {
	if pm.discovery.noNewPathsCount >= pm.discovery.noNewPathsLimit {
		return true
	}
	if pm.discovery.flowBudget > 0 && pm.discovery.flowsUsed >= pm.discovery.flowBudget {
		if pm.discovery.noNewPathsCount > 0 {
			return true
		}
	}
	return false
}

// DiscoveredPath describes one unique path found during discovery.
type DiscoveredPath struct {
	PathHash   string   `json:"path_hash"`
	SourcePort uint16   `json:"source_port"`
	Hops       []string `json:"hops"`
}

// DiscoverySummary holds end-of-run discovery statistics.
type DiscoverySummary struct {
	Enabled         bool             `json:"-"`
	DistinctPaths   uint             `json:"distinct_paths"`
	FlowsUsed       uint             `json:"flows_used"`
	FlowBudget      uint             `json:"flow_budget"`
	ProbesConfirmed uint             `json:"probes_confirmed"`
	Paths           []DiscoveredPath `json:"paths"`
}

// GetDiscoverySummary returns end-of-run discovery statistics.
func (pm *ProbeManager) GetDiscoverySummary() DiscoverySummary {
	pm.discoveryMu.RLock()
	defer pm.discoveryMu.RUnlock()

	paths := make([]DiscoveredPath, 0, len(pm.discovery.allDiscoveredPaths))
	for hash, info := range pm.discovery.allDiscoveredPaths {
		paths = append(paths, DiscoveredPath{PathHash: hash, SourcePort: info.sourcePort, Hops: info.hops})
	}

	return DiscoverySummary{
		Enabled:         pm.discovery.enabled,
		DistinctPaths:   uint(len(pm.discovery.allDiscoveredPaths)),
		FlowsUsed:       pm.discovery.flowsUsed,
		FlowBudget:      pm.discovery.flowBudget,
		ProbesConfirmed: pm.discovery.confirmedProbes,
		Paths:           paths,
	}
}

// discoveryStatsSnapshot returns a TUI-friendly snapshot of current discovery state.
// Caller must NOT hold discoveryMu.
func (pm *ProbeManager) discoveryStatsSnapshot() shared.DiscoveryStats {
	pm.discoveryMu.RLock()
	defer pm.discoveryMu.RUnlock()
	return shared.DiscoveryStats{
		FlowsUsed:        pm.discovery.flowsUsed,
		FlowBudget:       pm.discovery.flowBudget,
		ProbesConfirmed:  pm.discovery.confirmedProbes,
		NoNewPathsCount:  pm.discovery.noNewPathsCount,
		NoNewPathsTarget: pm.discovery.noNewPathsLimit,
	}
}
