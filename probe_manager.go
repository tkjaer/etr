package main

import (
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tkjaer/etr/pkg/arp"
	"github.com/tkjaer/etr/pkg/ptr"
	"github.com/tkjaer/etr/pkg/route"
)

type ProbeTracker struct {
	probes map[uint16]*newProbe
	mutex  sync.Mutex
}

// Event structure for probe statistics
type ProbeEvent struct {
	ProbeID   uint16
	EventType string // "sent", "received", "timeout", etc.
	Data      interface{}
}

type ProbeEventDataSent struct {
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
	TTL      uint8
}

// ProbeManager coordinates multiple parallel probes to the same destination
type ProbeManager struct {
	// Coordination
	wg   sync.WaitGroup
	stop chan struct{}

	// Statistics aggregation
	// aggregatedStats map[string]probeStats
	// statsMutex      sync.RWMutex
	statsChan chan ProbeEvent

	// Shared resources
	handle       *pcap.Handle
	outputChan   chan outputMsg
	transmitChan chan TransmitEvent
	responseChan chan uint
	ptrManager   *ptr.PtrManager

	// Probe Configuration
	parallelProbes uint16
	probeConfig    ProbeConfig
	probeTracker   ProbeTracker
}

type ProtocolConfig struct {
	inet      layers.IPProtocol
	transport layers.IPProtocol
	etherType layers.EthernetType
}

// NewProbeManager creates and initializes a probe manager
func NewProbeManager(a Args) (*ProbeManager, error) {
	pm := &ProbeManager{
		// Coordination
		wg:   sync.WaitGroup{},
		stop: make(chan struct{}),

		statsChan:    make(chan ProbeEvent, 100),
		transmitChan: make(chan TransmitEvent, 100),
		responseChan: make(chan uint, 100),
		ptrManager:   ptr.NewPtrManager(),

		probeTracker: ProbeTracker{
			probes: make(map[uint16]*newProbe),
			mutex:  sync.Mutex{},
		},

		// Probe Configuration
		parallelProbes: uint16(a.parallelProbes),
		probeConfig: ProbeConfig{
			destination:     a.destination,
			numProbes:       uint(a.numProbes),
			protocolConfig:  ProtocolConfig{},
			dstPort:         uint16(a.destinationPort),
			srcPort:         uint16(a.sourcePort),
			route:           route.Route{},
			maxTTL:          uint8(a.maxTTL),
			interProbeDelay: a.interProbeDelay,
			interTTLDelay:   a.interTTLDelay,
			timeout:         a.timeout,
		},
	}

	err := pm.init(a)
	if err != nil {
		return nil, err
	}

	return pm, nil
}

// init initializes the probe manager by setting up routes, pcap handles, and probes
func (pm *ProbeManager) init(a Args) error {
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

	// Resolve gateway MAC address
	probeConfig.dstMAC, err = arp.Get(probeConfig.route.Gateway.AsSlice(), probeConfig.route.Interface, probeConfig.route.Source.AsSlice())
	if err != nil {
		return err
	}

	// Initialize pcap handle and set BPF filter
	pm.handle, err = pcap.OpenLive(probeConfig.route.Interface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
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

	return nil
}

// AddProbe initializes and adds a probe to the manager
func (pm *ProbeManager) addProbe(probeIndex uint16) error {
	p := new(newProbe)
	p.probeID = probeIndex
	p.config = &pm.probeConfig
	p.transmitChan = pm.transmitChan
	p.responseChan = pm.responseChan

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
			log.Errorf("Transmit routine error: %v", err)
		}
	}()

	// Start output formatter
	go pm.outputRoutine()

	// Start all probes
	for _, p := range pm.probeTracker.probes {
		pm.wg.Add(1)
		go func(p *newProbe) {
			defer pm.wg.Done()
			p.Run()
		}(p)
	}

	// Wait for all probes to complete
	pm.wg.Wait()

	// Generate summary
	pm.generateSummary()

	// Signal stats processor to exit
	close(pm.statsChan)

	return nil
}

// outputRoutine formats and displays probe results
func (pm *ProbeManager) outputRoutine() {
	// Implementation to display results
}

// generateSummary creates a final summary of all probe results
func (pm *ProbeManager) generateSummary() {
	// Implement summary generation
}

// Stop terminates all probes and cleans up resources
func (pm *ProbeManager) Stop() {
	close(pm.stop)
	pm.wg.Wait()
	pm.handle.Close()
}
