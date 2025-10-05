package main

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// recvProbes listens for incoming probe responses on the provided pcap handle.
// It decodes the packets to extract TTL, probe number, timestamp, IP address, and flag.
// It sends the decoded information to the recvChan channel and notifies
// the responseReceivedChan channel when a non-"TTL exceeded" response is received.
func (pm *ProbeManager) recvProbes(handle *pcap.Handle, recvChan chan recvMsg, responseReceivedChan chan uint, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	if err := pm.setBPFFilter(); err != nil {
		log.Fatal("Failed to set BPF filter: ", err)
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
			// FIXME: Add port number so we can steer the packet to the right probe
			ttl, probeNum, timestamp, ip, port, flag := pm.decodeRecvProbe(packet)
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
