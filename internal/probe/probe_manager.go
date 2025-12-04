package probe

import (
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tkjaer/etr/pkg/arp"
	"github.com/tkjaer/etr/pkg/ndp"
	"github.com/tkjaer/etr/pkg/ptr"
	"github.com/tkjaer/etr/pkg/route"

	"github.com/tkjaer/etr/internal/config"
	"github.com/tkjaer/etr/internal/output"
	"github.com/tkjaer/etr/internal/shared"
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

type outputConfig struct {
	jsonOutput    bool
	jsonFile      string
	hashAlgorithm string
}

type outputMsg struct {
	msgType    string           // Message type: "hop", "probe_run", "complete", "delete_hops"
	run        *shared.ProbeRun // For probe_run messages
	deleteTTLs []uint8          // For delete_hops messages
	probeNum   uint             // Probe number for hop/delete_hops/complete messages
	ttl        uint8            // TTL for hop messages
}

// ProbeManager coordinates multiple parallel probes to the same destination
type ProbeManager struct {
	// Coordination
	wg       sync.WaitGroup
	stop     chan struct{}
	stopOnce sync.Once

	// Statistics aggregation
	// aggregatedStats map[string]probeStats
	// statsMutex      sync.RWMutex
	statsChan chan ProbeEvent

	// Shared resources
	handle       *pcap.Handle
	outputChan   chan outputMsg
	transmitChan chan TransmitEvent
	ptrManager   *ptr.PtrManager

	// Probe Configuration
	parallelProbes uint16
	probeConfig    ProbeConfig
	probeTracker   ProbeTracker

	stats        ProbeManagerStats
	outputConfig outputConfig
}

type ProtocolConfig struct {
	inet      layers.IPProtocol
	transport layers.IPProtocol
	etherType layers.EthernetType
}

// NewProbeManager creates and initializes a probe manager
func NewProbeManager(a config.Args) (*ProbeManager, error) {
	pm := &ProbeManager{
		// Coordination
		wg:   sync.WaitGroup{},
		stop: make(chan struct{}),

		statsChan:    make(chan ProbeEvent, 100),
		outputChan:   make(chan outputMsg, 100),
		transmitChan: make(chan TransmitEvent, 100),
		ptrManager:   ptr.NewPtrManager(),

		probeTracker: ProbeTracker{
			probes: make(map[uint16]*Probe),
			mutex:  sync.Mutex{},
		},

		// Probe Configuration
		parallelProbes: uint16(a.ParallelProbes),
		probeConfig: ProbeConfig{
			destination:     a.Destination,
			numProbes:       uint(a.NumProbes),
			protocolConfig:  ProtocolConfig{},
			dstPort:         uint16(a.DestinationPort),
			srcPort:         uint16(a.SourcePort),
			route:           route.Route{},
			maxTTL:          uint8(a.MaxTTL),
			interProbeDelay: a.InterProbeDelay,
			interTTLDelay:   a.InterTTLDelay,
			timeout:         a.Timeout,
			NoResolve:       a.NoResolve,
		},

		outputConfig: outputConfig{
			jsonOutput:    a.Json,
			jsonFile:      a.JsonFile,
			hashAlgorithm: a.HashAlgorithm,
		},
	}

	err := pm.init(a)
	if err != nil {
		return nil, err
	}

	return pm, nil
}

// init initializes the probe manager by setting up routes, pcap handles, and probes
func (pm *ProbeManager) init(a config.Args) error {
	var err error

	probeConfig := &pm.probeConfig
	protocolConfig := &probeConfig.protocolConfig

	// Populate route struct
	d, err := getDestinationIP(a)
	if err != nil {
		return err
	}
	probeConfig.route, err = route.Get(d)
	if err != nil {
		return err
	}

	// Set protocol configuration (etherType, inet, transport)
	if probeConfig.route.Destination.Is4() {
		protocolConfig.etherType = layers.EthernetTypeIPv4
		protocolConfig.inet = layers.IPProtocolIPv4
	} else if probeConfig.route.Destination.Is6() {
		protocolConfig.etherType = layers.EthernetTypeIPv6
		protocolConfig.inet = layers.IPProtocolIPv6
	}
	if a.TCP {
		protocolConfig.transport = layers.IPProtocolTCP
	} else if a.UDP {
		protocolConfig.transport = layers.IPProtocolUDP
	}

	// Resolve gateway MAC address for Ethernet interfaces
	// if gw is empty, this is a directly connected route, so use dst IP
	if probeConfig.route.Gateway == (netip.Addr{}) {
		probeConfig.route.Gateway = probeConfig.route.Destination
	}

	// Initialize pcap handle first so we can determine link type
	pm.handle, err = pcap.OpenLive(probeConfig.route.Interface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	slog.Debug("Opened pcap handle", "interface", probeConfig.route.Interface.Name)
	probeConfig.useEthernet = pm.handle.LinkType() == layers.LinkTypeEthernet

	// Only resolve MAC addresses for Ethernet interfaces
	// VPN/tunnel interfaces (utun, tun, etc.) don't use MAC addresses
	if probeConfig.useEthernet {
		// Use the ARP package to resolve MAC for IPv4 neighbors
		switch pm.probeConfig.protocolConfig.inet {
		case layers.IPProtocolIPv4:
			probeConfig.dstMAC, err = arp.Get(probeConfig.route.Gateway.AsSlice(), probeConfig.route.Interface, probeConfig.route.Source.AsSlice())
			if err != nil {
				return err
			}
		case layers.IPProtocolIPv6:
			probeConfig.dstMAC, err = ndp.Get(probeConfig.route.Gateway.AsSlice(), probeConfig.route.Interface)
			if err != nil {
				return err
			}
		}
	} else {
		slog.Debug("Skipping MAC resolution for non-Ethernet interface", "interface", probeConfig.route.Interface.Name)
		// For non-Ethernet interfaces, leave dstMAC as nil
		// The packet construction will handle this case
	}

	// Set BPF filter after configuring the handle
	err = pm.setBPFFilter()
	if err != nil {
		return err
	}

	// Add all probes
	for i := range pm.parallelProbes {
		err := pm.addProbe(i)
		if err != nil {
			return err
		}
	}

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

	return nil
}

// AddProbe initializes and adds a probe to the manager
func (pm *ProbeManager) addProbe(probeIndex uint16) error {
	p := new(Probe)
	p.probeID = probeIndex
	p.config = &pm.probeConfig
	p.transmitChan = pm.transmitChan
	p.responseChan = make(chan ResponseEvent, 100)
	p.statsChan = pm.statsChan
	p.stop = pm.stop
	p.wg = &pm.wg

	pm.probeTracker.mutex.Lock()
	defer pm.probeTracker.mutex.Unlock()
	pm.probeTracker.probes[probeIndex] = p

	return nil
}

// Run initializes and executes all probes in parallel
func (pm *ProbeManager) Run() error {

	// Start transmit routine
	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()
		err := pm.transmitRoutine()
		if err != nil {
			slog.Error("Transmit routine error", "error", err)
		}
	}()

	// Create and start output formatter (separate wait group to avoid circular dependency)
	var outputWg sync.WaitGroup
	bubbleTUI, om := pm.createOutputs()
	outputWg.Add(1)
	go func() {
		defer outputWg.Done()
		pm.outputRoutine(om)
	}()

	// Track just the probe goroutines separately
	var probesWg sync.WaitGroup

	// Start all probes
	for _, p := range pm.probeTracker.probes {
		pm.wg.Add(1)
		probesWg.Add(1)
		go func(p *Probe) {
			defer pm.wg.Done()
			defer probesWg.Done()
			p.Run()
		}(p)
	}

	// Create a channel that signals when probes are done (not all goroutines)
	probesDone := make(chan struct{})
	go func() {
		probesWg.Wait()
		close(probesDone)
	}()

	// Wait for either all probes to complete or user to quit TUI
	if bubbleTUI != nil {
		select {
		case <-probesDone:
			// All probes completed normally, signal stop for cleanup
			slog.Debug("All probes completed normally, signaling stop for cleanup")
			pm.stopOnce.Do(func() {
				close(pm.stop)
			})
			// Wait for other goroutines (transmit, recv, stats) to exit
			pm.wg.Wait()
		case <-bubbleTUI.QuitChan():
			// User quit the TUI, stop all probes
			slog.Debug("User quit TUI, stopping probes")
			pm.stopOnce.Do(func() {
				close(pm.stop)
			})
			// Wait for all goroutines to exit (they listen to pm.stop)
			pm.wg.Wait()
		}
	} else {
		// No TUI, just wait for probes then signal stop
		<-probesDone
		slog.Debug("All probes completed normally, signaling stop for cleanup")
		pm.stopOnce.Do(func() {
			close(pm.stop)
		})
		// Wait for other goroutines to finish
		pm.wg.Wait()
	}

	// All goroutines done (they listen to pm.stop and exit gracefully)
	slog.Debug("All goroutines finished")

	// Close output channel to signal outputRoutine to exit
	slog.Debug("Closing outputChan")
	close(pm.outputChan)

	// Wait for output routine to finish processing remaining messages
	slog.Debug("Waiting for output routine")
	outputWg.Wait()

	// Generate summary
	pm.generateSummary()

	return nil
}

// generateSummary creates a final summary of all probe results
func (pm *ProbeManager) generateSummary() {
	// FIXME:
	// Implement summary generation
}

// Stop terminates all probes and cleans up resources
func (pm *ProbeManager) Stop() {
	pm.stopOnce.Do(func() {
		slog.Debug("Stopping ProbeManager")
		close(pm.stop)
	})
	pm.wg.Wait()
	pm.handle.Close()
}

// createOutputs creates and initializes output handlers
// Returns the BubbleTUIOutput instance (may be nil) and the OutputManager
func (pm *ProbeManager) createOutputs() (*output.BubbleTUIOutput, *output.OutputManager) {
	om := &output.OutputManager{}

	info := shared.OutputInfo{
		Destination:    pm.probeConfig.destination,
		Protocol:       "TCP",
		SrcPort:        pm.probeConfig.srcPort,
		DstPort:        pm.probeConfig.dstPort,
		ParallelProbes: pm.parallelProbes,
		HashAlgorithm:  pm.outputConfig.hashAlgorithm,
	}
	if pm.probeConfig.protocolConfig.transport == layers.IPProtocolUDP {
		info.Protocol = "UDP"
	}

	var bubbleTUI *output.BubbleTUIOutput

	// If JSON output is enabled, output to stdout and disable TUI
	if pm.outputConfig.jsonOutput {
		jsonOut, err := output.NewJSONOutput("") // empty string = stdout
		if err == nil {
			om.Register(jsonOut)
		}
	} else {
		// TUI mode: show interactive interface
		bubbleTUI = output.NewBubbleTUIOutput(info)
		bubbleTUI.Start()
		om.Register(bubbleTUI)
	}

	// If JSON file output is enabled, write to file (alongside TUI if not disabled)
	if pm.outputConfig.jsonFile != "" {
		jsonOut, err := output.NewJSONOutput(pm.outputConfig.jsonFile)
		if err == nil {
			om.Register(jsonOut)
		} else {
			slog.Warn("Failed to create JSON file output", "error", err)
		}
	}

	return bubbleTUI, om
}

// outputRoutine processes output messages and updates displays
func (pm *ProbeManager) outputRoutine(om *output.OutputManager) {
	for msg := range pm.outputChan {
		switch msg.msgType {
		case "hop":
			if probeHopStats, exists := pm.getProbeHopStats(uint16(msg.probeNum), msg.ttl); exists {
				om.UpdateHop(uint16(msg.probeNum), msg.ttl, probeHopStats)
			}
		case "delete_hops":
			// Notify outputs to delete specific hops
			om.DeleteHops(uint16(msg.probeNum), msg.deleteTTLs)
		case "probe_run":
			// Output individual probe run (for JSON)
			if msg.run != nil {
				om.CompleteProbeRun(msg.run)
			}
		case "complete":
			if probeStats, exists := pm.getProbeStats(uint16(msg.probeNum)); exists {
				om.CompleteProbe(uint16(msg.probeNum), probeStats)
			}
		}
	}
	om.Close()
}
