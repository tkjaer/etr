package main

import (
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func (p *probe) recvProbes(handle *pcap.Handle, recvChan chan recvMsg, responseReceivedChan chan uint, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	if err := handle.SetBPFFilter(p.pcapFilter()); err != nil {
		log.Fatal(err)
	}
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			log.Debug("stopping recvProbes")
			return
		case packet = <-in:
			ttl, probeNum, timestamp, ip, flag := p.decodeRecvProbe(packet)
			// All valid received probes will have a TTL.
			if ttl > 0 {
				// Report received probe.
				recvChan <- recvMsg{probeNum, ttl, timestamp, ip, flag}
				// Report if we've received a non-"TTL exceeded" response so we
				// stop sending further packets for this probe number.
				if flag != "TTL" {
					go func(responseReceivedChan chan uint, probeNum uint) {
						responseReceivedChan <- probeNum
					}(responseReceivedChan, probeNum)
				}
			}
		}
	}
}

// Create BPF filter string to capture returning probes.
func (p *probe) pcapFilter() string {
	var proto string
	switch p.proto {
	case layers.IPProtocolTCP:
		proto = "tcp"
	case layers.IPProtocolUDP:
		proto = "udp"
	}
	var ttl_exceeded string
	switch p.inet {
	case layers.IPProtocolIPv4:
		ttl_exceeded = "icmp and icmp[0] == 11 and icmp[1] == 0"
	case layers.IPProtocolIPv6:
		ttl_exceeded = "icmp6 and icmp6.type == 3 and icmp6.code == 0"
	}
	return fmt.Sprintf("(%v and src host %v and dst host %v and src port %v and dst port %v) or (%v)", proto, p.route.Destination, p.route.Source, p.dstPort, p.srcPort, ttl_exceeded)
}
