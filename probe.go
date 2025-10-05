package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
)

type probe struct {
	protocolConfig  ProtocolConfig
	dstPort         uint16
	srcPort         uint16
	dstMAC          net.HardwareAddr
	interProbeDelay time.Duration
	interTTLDelay   time.Duration
	numProbes       uint
	maxTTL          uint8
	timeout         time.Duration
	outputType      string

	// Add a unique identifier for this probe instance
	probeID string

	// Add a map to store hostnames
	hostnames map[string]string
	// Mutex to protect the map
	hostnamesMutex sync.RWMutex

	// Channel for notifications of received responses from the destination
	responseReceivedChan chan uint
}

// Message type for communication between transmitProbes() and sendStats().
type sentMsg struct {
	probeNum  uint
	ttl       uint8
	timestamp time.Time
}

// Message type for communication between recvProbes() and sendStats().
type recvMsg struct {
	probeNum  uint
	ttl       uint8
	timestamp time.Time
	ip        net.IP
	flag      string
}

type expiredMsg struct {
	origProbeNum uint
	probeNum     uint8
	ttl          uint8
}

// Message type for communication between sendStats() and outputStats().
type outputMsg struct {
	probeNum uint
	ttl      uint8
	ip       string
	// host     string
	// sentTime time.Time
	// rtt      time.Duration
	// delayVariation time.Duration
	// avgRTT time.Duration
	// minRTT time.Duration
	// maxRTT time.Duration
	loss    uint
	flag    string
	msgType string // Added to differentiate message types: "probe_result", "ptr_result", etc.
	ptrName string // Added for PTR results
}

// Modified run method to use shared resources
func (p *probe) run(handle *pcap.Handle, ptrLookupChan chan []string, outputChan chan outputMsg) {
	// Create channels for communication
	sentChan := make(chan sentMsg, 100)
	recvChan := make(chan recvMsg, 100)
	stop := make(chan struct{})
	// ptrResultChan := make(chan outputMsg, 100) // New channel for PTR results

	var wg sync.WaitGroup

	// Start a goroutine to listen for PTR results
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case outputMsg := <-outputChan:
				if outputMsg.msgType == "ptr_result" {
					// Store the hostname in the probe's map
					p.hostnamesMutex.Lock()
					p.hostnames[outputMsg.ip] = outputMsg.ptrName
					p.hostnamesMutex.Unlock()
				}
			}
		}
	}()

	// Channel for reporting sent probes
	sentChan = make(chan sentMsg, 100)

	// Channel for reporting received probes
	recvChan = make(chan recvMsg, 100)

	// Channel for sending stop signal to goroutines
	stop = make(chan struct{})
	defer close(stop)

	// Channel for reporting received responses from the destination
	// This is used to stop incrementing the TTL for this probe
	responseReceivedChan := make(chan uint)

	// Start sender routine
	wg.Add(1)
	go p.transmitProbes(handle, sentChan, responseReceivedChan, stop, &wg)

	// Start receiver routine
	wg.Add(1)
	go p.recvProbes(handle, recvChan, responseReceivedChan, stop, &wg)

	// Start stats processor - use shared ptrLookupChan
	wg.Add(1)
	go p.stats(sentChan, recvChan, outputChan, ptrLookupChan, stop, &wg)

	// Wait for all goroutines to finish
	wg.Wait()
}

// Helper method to get hostname for an IP
func (p *probe) getHostname(ip string) string {
	p.hostnamesMutex.RLock()
	defer p.hostnamesMutex.RUnlock()

	if hostname, ok := p.hostnames[ip]; ok && hostname != "" {
		return hostname
	}
	return ip // Return IP if no hostname is available
}

// Request PTR lookup for an IP
func (p *probe) requestPtrLookup(ip string, ptrLookupChan chan []string) {
	// Send request with probe ID
	ptrLookupChan <- []string{ip, p.probeID}
}

func (p *probe) output(outputChan chan outputMsg, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	// TODO: Clear terminal

	// var out []string

	select {
	case <-stop:
		log.Debug("stopping output")
		return
	case msg := <-outputChan:
		fmt.Printf("%2v. %-15v %3v - %v (%v)\n", msg.ttl, msg.ip, msg.loss, msg.probeNum, msg.flag)
	}
	// fmt.Printf("%3v. %-15v %3v - %v (%v)\n", ttl, ip, timestamp.Sub(start), probeNum, flag)
}

func (p *probe) init() error {
	// existing initialization...

	// Initialize the hostnames map
	p.hostnames = make(map[string]string)

	return nil
}
