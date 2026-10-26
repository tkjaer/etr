package probe

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tkjaer/etr/pkg/arp"
	"github.com/tkjaer/etr/pkg/asn"
	"github.com/tkjaer/etr/pkg/ndp"
	"github.com/tkjaer/etr/pkg/ptr"
)

type ProbeTracker struct {
	probes map[uint16]*Probe
	mutex  sync.Mutex
}

// Event structure for probe statistics
type ProbeEvent struct {
	ProbeID   uint16
	EventType string // "sent", "received", "timeout", etc.
	Data      any
}

type ProbeEventDataSent struct {
	ProbeNum  uint
	TTL       uint8
	Timestamp time.Time
}

type ProbeEventDataReceived struct {
	ProbeNum  uint
	TTL       uint8
	Timestamp time.Time
	IP        string
	Flag      string
}

type ProbeEventDataTimeout struct {
	ProbeNum uint
	SentTime time.Time
	TTL      uint8
}

type ProbeEventDataIterationComplete struct {
	ProbeNum  uint      // Which iteration just completed
	Timestamp time.Time // When it completed
}

type outputMsg struct {
	msgType        string          // "hop", "probe_run", "complete", "delete_hops", "discovery_update"
	run            *ProbeRun       // For probe_run messages
	deleteTTLs     []uint8         // For delete_hops messages
	probeNum       uint            // Probe number for hop/delete_hops/complete messages
	ttl            uint8           // TTL for hop messages
	discoveryStats *DiscoveryStats // For discovery_update messages
}

// discoveryState tracks per-probe path stability and flow rotation
type discoveryState struct {
	enabled              bool
	hopsMode             bool // count unique IPs instead of unique paths
	flowBudget           uint
	noNewPathsLimit      uint
	perProbeStableRounds uint
	flowsUsed            uint
	noNewPathsCount      uint
	confirmedProbes      uint
	allDiscoveredPaths   map[string]discoveredPathInfo // path hash -> info about first observation
	allDiscoveredIPs     map[string]struct{}           // all unique IPs seen (hops mode)
	perProbeState        map[uint16]*probeDiscoveryState
	activeProbes         map[uint16]struct{} // probeIDs currently running
	nextProbeID          uint16              // next probeID to assign
	stoppedByPortLimit   bool
}

// discoveredPathInfo stores metadata about a confirmed path.
type discoveredPathInfo struct {
	sourcePort uint16
	hops       []discoveredHop
}

// discoveredHop stores per-hop metadata.
type discoveredHop struct {
	IP  string
	PTR string
	ASN string
}

// probeDiscoveryState tracks stability for one probe's current flow
type probeDiscoveryState struct {
	lastPathHash      string // Last round's path hash
	stableRoundsCount uint   // How many consecutive rounds with same path
}

// ProbeManager coordinates multiple parallel probes to the same destination
type ProbeManager struct {
	// Coordination
	wg       sync.WaitGroup
	probesWg sync.WaitGroup // tracks probe goroutines only (for probesDone signaling)
	stop     chan struct{}
	stopOnce sync.Once

	// Statistics aggregation
	statsChan chan ProbeEvent

	// Shared resources
	handle       *pcap.Handle
	outputChan   chan outputMsg
	transmitChan chan TransmitEvent
	ptrManager   *ptr.PtrManager
	asnManager   *asn.ASNManager

	// Probe Configuration
	probeConfig  Config
	probeTarget  target
	probeTracker ProbeTracker

	stats       ProbeManagerStats
	discoveryMu sync.RWMutex
	discovery   discoveryState
}

// NewProbeManager creates and initializes a probe manager
func NewProbeManager(ctx context.Context, cfg Config) (*ProbeManager, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	pm := &ProbeManager{
		// Coordination
		wg:   sync.WaitGroup{},
		stop: make(chan struct{}),

		statsChan:    make(chan ProbeEvent, 100),
		outputChan:   make(chan outputMsg, 100),
		transmitChan: make(chan TransmitEvent, 100),
		ptrManager:   ptr.NewPtrManager(),
		asnManager:   asn.NewASNManager(),

		probeTracker: ProbeTracker{
			probes: make(map[uint16]*Probe),
			mutex:  sync.Mutex{},
		},

		// Probe Configuration
		probeConfig: cfg,

		discovery: discoveryState{
			enabled:            cfg.Discovery != nil,
			allDiscoveredPaths: make(map[string]discoveredPathInfo),
			allDiscoveredIPs:   make(map[string]struct{}),
			perProbeState:      make(map[uint16]*probeDiscoveryState),
			activeProbes:       make(map[uint16]struct{}),
		},
	}

	if d := cfg.Discovery; d != nil {
		pm.discovery.hopsMode = d.Hops
		pm.discovery.flowBudget = d.MaxFlows
		pm.discovery.noNewPathsLimit = d.NoNewPathsRounds
		pm.discovery.perProbeStableRounds = d.StableRounds
	}
	pm.discovery.nextProbeID = pm.probeConfig.ParallelProbes
	pm.discovery.flowsUsed = uint(pm.probeConfig.ParallelProbes) // initial probes count toward the budget

	// Initialize per-probe discovery state
	if pm.discovery.enabled {
		for p := range pm.probeConfig.ParallelProbes {
			pm.discovery.perProbeState[p] = &probeDiscoveryState{}
			pm.discovery.activeProbes[p] = struct{}{}
		}
	}

	err := pm.init(ctx)
	if err != nil {
		return nil, err
	}

	return pm, nil
}

// init sets up the route, pcap handle, and probes
func (pm *ProbeManager) init(ctx context.Context) (err error) {
	pm.probeTarget, err = resolveTarget(ctx, pm.probeConfig)
	if err != nil {
		return err
	}
	tgt := &pm.probeTarget

	// Resolve gateway MAC address for Ethernet interfaces
	// if gw is empty, this is a directly connected route, so use dst IP
	if tgt.route.Gateway == (netip.Addr{}) {
		tgt.route.Gateway = tgt.route.Destination
	}

	// Initialize pcap handle first so we can determine link type
	pm.handle, err = pcap.OpenLive(tgt.route.Interface.Name, 65536, true, 10*time.Millisecond)
	if err != nil {
		return err
	}
	slog.Debug("Opened pcap handle", "interface", tgt.route.Interface.Name)
	tgt.useEthernet = pm.handle.LinkType() == layers.LinkTypeEthernet

	// Close pcap handle if init fails
	defer func() {
		if err != nil {
			pm.handle.Close()
		}
	}()

	// We currently do not support non-Ethernet interfaces on OpenBSD and NetBSD
	if !tgt.useEthernet {
		if runtime.GOOS == "openbsd" {
			err = errors.New("Non-Ethernet interfaces are not currently supported on OpenBSD")
			return err
		}
		if runtime.GOOS == "netbsd" {
			err = errors.New("Non-Ethernet interfaces are not currently supported on NetBSD")
			return err
		}
	}

	// Only resolve MAC addresses for Ethernet interfaces
	// VPN/tunnel interfaces (utun, tun, etc.) don't use MAC addresses
	if tgt.useEthernet {
		// Use the ARP package to resolve MAC for IPv4 neighbors
		switch tgt.inet {
		case layers.IPProtocolIPv4:
			tgt.dstMAC, err = arp.Get(tgt.route.Gateway.AsSlice(), tgt.route.Interface, tgt.route.Source.AsSlice())
			if err != nil {
				return err
			}
		case layers.IPProtocolIPv6:
			tgt.dstMAC, err = ndp.Get(tgt.route.Gateway.AsSlice(), tgt.route.Interface)
			if err != nil {
				return err
			}
		}
	} else {
		slog.Debug("Skipping MAC resolution for non-Ethernet interface", "interface", tgt.route.Interface.Name)
		// For non-Ethernet interfaces, leave dstMAC as nil
		// The packet construction will handle this case
	}

	// Set BPF filter after configuring the handle
	err = pm.setBPFFilter()
	if err != nil {
		return err
	}

	// Add all probes
	for i := range pm.probeConfig.ParallelProbes {
		err := pm.addProbe(i)
		if err != nil {
			return err
		}
	}

	return nil
}

// Create and set probe BPF filter string to capture returning probes.
func (pm *ProbeManager) setBPFFilter() error {
	filter, err := buildBPFFilter(pm.probeConfig, pm.probeTarget, false)
	if err != nil {
		return err
	}
	return pm.handle.SetBPFFilter(filter)
}

// AddProbe initializes and adds a probe to the manager
func (pm *ProbeManager) addProbe(probeIndex uint16) error {
	p := new(Probe)
	p.probeID = probeIndex
	p.cfg = &pm.probeConfig
	p.target = &pm.probeTarget
	p.transmitChan = pm.transmitChan
	p.responseChan = make(chan ResponseEvent, 100)
	p.statsChan = pm.statsChan
	p.stop = pm.stop
	if pm.discovery.enabled {
		p.discoveryStop = make(chan struct{})
	}
	p.wg = &pm.wg

	pm.probeTracker.mutex.Lock()
	defer pm.probeTracker.mutex.Unlock()
	pm.probeTracker.probes[probeIndex] = p

	return nil
}

// getProbe safely retrieves a probe by its ID, ensuring thread-safe access to
// the probe tracker.
func (pm *ProbeManager) getProbe(probeID uint16) *Probe {
	pm.probeTracker.mutex.Lock()
	defer pm.probeTracker.mutex.Unlock()
	return pm.probeTracker.probes[probeID]
}

// spawnDiscoveryProbe creates and starts a new probe with the given ID.
// Called from the stats goroutine (via TrackDiscoveryPath) when a probe's
// path has been confirmed, just before the old probe is retired.
func (pm *ProbeManager) spawnDiscoveryProbe(probeID uint16) {
	if err := pm.addProbe(probeID); err != nil {
		slog.Error("Failed to create discovery probe", "probe_id", probeID, "error", err)
		return
	}
	pm.probeTracker.mutex.Lock()
	p := pm.probeTracker.probes[probeID]
	pm.probeTracker.mutex.Unlock()

	pm.wg.Add(1)
	pm.probesWg.Add(1)
	go func() {
		defer pm.wg.Done()
		defer pm.probesWg.Done()
		p.Run()
	}()
}

// Run executes all probes in parallel and sends results to sink until the
// probes finish or ctx is cancelled. A nil sink discards results. Run does not
// close the sink.
func (pm *ProbeManager) Run(ctx context.Context, sink Sink) (*Result, error) {
	// Close pcap handle on run completion
	defer pm.handle.Close()

	stopOnCancel := context.AfterFunc(ctx, pm.signalStop)
	defer stopOnCancel()

	// Start stats processor
	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()
		pm.statsProcessor()
	}()

	// Start receiving routine
	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()
		pm.recvProbes(pm.stop)
	}()

	// Start transmit routine
	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()
		err := pm.transmitRoutine()
		if err != nil {
			slog.Error("Transmit routine error", "error", err)
		}
	}()

	// Start output routine (separate wait group to avoid circular dependency)
	var outputWg sync.WaitGroup
	outputWg.Add(1)
	go func() {
		defer outputWg.Done()
		pm.outputRoutine(sink)
	}()

	// Start all probes
	pm.probeTracker.mutex.Lock()
	for _, p := range pm.probeTracker.probes {
		pm.wg.Add(1)
		pm.probesWg.Add(1)
		go func(p *Probe) {
			defer pm.wg.Done()
			defer pm.probesWg.Done()
			p.Run()
		}(p)
	}
	pm.probeTracker.mutex.Unlock()

	// Create a channel that signals when probes are done (not all goroutines)
	probesDone := make(chan struct{})
	go func() {
		pm.probesWg.Wait()
		close(probesDone)
	}()

	// Wait for all probes to finish. Cancelling ctx makes them exit early.
	<-probesDone
	slog.Debug("All probes finished, signaling stop for cleanup")
	pm.signalStop()
	// Wait for other goroutines (transmit, recv, stats) to exit
	pm.wg.Wait()

	// All goroutines done (they listen to pm.stop and exit gracefully)
	slog.Debug("All goroutines finished")

	// Close output channel to signal outputRoutine to exit
	slog.Debug("Closing outputChan")
	close(pm.outputChan)

	// Wait for output routine to finish processing remaining messages
	slog.Debug("Waiting for output routine")
	outputWg.Wait()

	return &Result{Discovery: pm.discoverySummary()}, nil
}

// signalStop tells all goroutines to stop
func (pm *ProbeManager) signalStop() {
	pm.stopOnce.Do(func() {
		slog.Debug("Stopping ProbeManager")
		close(pm.stop)
	})
}

// outputRoutine forwards output messages to the sink
func (pm *ProbeManager) outputRoutine(sink Sink) {
	for msg := range pm.outputChan {
		if sink == nil {
			continue
		}
		switch msg.msgType {
		case "hop":
			if probeHopStats, exists := pm.getProbeHopStats(uint16(msg.probeNum), msg.ttl); exists {
				sink.UpdateHop(uint16(msg.probeNum), msg.ttl, probeHopStats)
			}
		case "delete_hops":
			// Notify outputs to delete specific hops
			sink.DeleteHops(uint16(msg.probeNum), msg.deleteTTLs)
		case "probe_run":
			// Output individual probe run (for JSON)
			if msg.run != nil {
				sink.CompleteProbeRun(msg.run)
			}
		case "discovery_update":
			if msg.discoveryStats != nil {
				sink.UpdateDiscoveryStats(*msg.discoveryStats)
			}
		case "complete":
			if probeStats, exists := pm.getProbeStats(uint16(msg.probeNum)); exists {
				sink.CompleteProbe(uint16(msg.probeNum), probeStats)
			}
		}
	}
}
