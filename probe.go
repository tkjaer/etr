package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tkjaer/etr/pkg/route"
)

type probe struct {
	destination     string
	route           route.Route
	proto           layers.IPProtocol
	inet            layers.IPProtocol
	etherType       layers.EthernetType
	dstPort         uint16
	srcPort         uint16
	dstMAC          net.HardwareAddr
	interProbeDelay time.Duration
	interTTLDelay   time.Duration
	numProbes       uint
	maxTTL          uint8
	timeout         time.Duration
	outputType      string
}

// GetDestinationIP resolves the destination IP address if necessary, validates it and returns it
func (p *probe) GetDestinationIP() (netip.Addr, error) {
	// Check if destination is an IP address
	d, err := netip.ParseAddr(Args.destination)
	if err == nil {
		return d, nil
	} else {
		// If not, resolve it
		lookup, err := net.LookupHost(Args.destination)
		if err != nil {
			return netip.Addr{}, err
		}

		// Find the first valid IP that meets our criteria
		for _, record := range lookup {
			ip, err := netip.ParseAddr(record)
			if err != nil {
				continue
			}
			switch {
			case Args.forceIPv4 && ip.Is4():
				d = ip
			case Args.forceIPv6 && ip.Is6():
				d = ip
			case !Args.forceIPv4 && !Args.forceIPv6:
				d = ip
			}
			// Return once we succeed
			if d.IsValid() {
				return d, nil
			}
		}
	}

	return netip.Addr{}, errors.New("could not resolve destination")
}

// Message type for communication between sendProbes() and sendStats().
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
	loss uint
	flag string
}

// Encode the probe number and TTL into a single value.
//
// As some operating systems still use the historic RFC 792 format for ICMP
// error messages, we need to encode the TTL and probe number into a field
// within the first 64 bit of the TCP and UDP protocol headers.
//
// For TCP we use the 32-bit sequence number field that follows source and
// destination port which takes up the first 32 bit.
//
// For UDP, we use the 16-bit length field, as the first 32 bits are used for
// source and destination port and the last 16 bits for checksum.
//
// To keep the sequence number small enough to fit into the UDP length field,
// while ensuring that the packet still is valid and fits into a 1500 byte
// Ethernet MTU, TTL is multiplied by 20 and the probe number added.  This also
// allows manual decoding of the sequence number if needed.
//
// This encoding leaves room for 20 probes (0-19) and the RFC1812 "common" TTL
// of 64 while keeping the MTU below 1500 bytes including IPv4 or IPv6 header.
//
// TTL + probe + UDP header = 64*20 + 19 + 8 == 1307
func encodeSeq(ttl uint8, probeNum uint) (seq uint32) {
	return uint32(ttl)*20 + uint32(probeNum%20)
}

// Decode the sequence and return TTL and probe number.
func decodeSeq(seq uint32) (ttl uint8, probeNum uint) {
	return uint8(seq / 20), uint(seq % 20)
}

func createKey(probeNum uint, ttl uint8) string {
	return fmt.Sprintf("%v:%v", probeNum, ttl)
}

func splitKey(key string) (probeNum uint, ttl uint8) {
	split := strings.Split(key, ":")
	if probeNum, err := strconv.Atoi(split[0]); err == nil {
		if t, err := strconv.Atoi(split[1]); err == nil {
			return uint(probeNum), uint8(t)
		}
	}
	return
}

func (p *probe) run() {
	log.Info("Starting probe")

	handle, err := pcap.OpenLive(p.route.Interface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Channel for reporting sent probes.
	// The probeNum reported here is the total probe number.
	sentChan := make(chan sentMsg)

	// Channel for reporting received probes.
	// The probeNum reported here is the encoded probe number (0-19).
	recvChan := make(chan recvMsg)

	// Channel for sending results to output.
	outputChan := make(chan outputMsg)

	// Channel for sending PTR lookup results.
	ptrLookupChan := make(chan []string)

	responseReceivedChan := make(chan uint)

	// Channel for sending stop signal to goroutines.
	stop := make(chan struct{})
	// defer close(stop)

	var wg sync.WaitGroup

	wg.Add(4)

	go p.output(outputChan, stop, &wg)
	go p.stats(sentChan, recvChan, outputChan, ptrLookupChan, stop, &wg)
	go p.recvProbes(handle, recvChan, responseReceivedChan, stop, &wg)
	go p.sendProbes(handle, sentChan, responseReceivedChan, stop, &wg)

	// TODO: replace with waitgroup.
	// time.Sleep(35 * time.Second)

	wg.Wait()

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
