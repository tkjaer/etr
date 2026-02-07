package probe

import (
	"log/slog"

	"github.com/google/gopacket"
)

// recvProbes listens for incoming probe responses on the provided pcap handle.
// It decodes the packets to extract TTL, probe number, timestamp, IP address, and flag.
// It sends the decoded information to the recvChan channel and notifies
// the responseReceivedChan channel when a non-"TTL exceeded" response is received.
func (pm *ProbeManager) recvProbes(stop chan struct{}) {
	src := gopacket.NewPacketSource(pm.handle, pm.handle.LinkType())
	in := src.Packets()

	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			slog.Debug("Stopping receive probes")
			return
		case packet = <-in:
			ttl, probeNum, timestamp, ip, port, flag := pm.decodeRecvProbe(packet)
			probeID := uint16(port) - pm.probeConfig.srcPort
			// All valid received probes will have a TTL.
			if ttl > 0 {
				if _, exists := pm.probeTracker.probes[probeID]; exists {
					// Update stats
					pm.probeTracker.probes[probeID].statsChan <- ProbeEvent{
						ProbeID:   probeID,
						EventType: "received",
						Data: &ProbeEventDataReceived{
							ProbeNum:  probeNum,
							TTL:       ttl,
							Timestamp: timestamp,
							IP:        ip.String(),
							Flag:      flag,
						},
					}
					// Update probe
					pm.probeTracker.probes[probeID].responseChan <- ResponseEvent{
						ProbeNum: probeNum,
						TTL:      ttl,
						Flag:     flag,
					}
				}
			}
		}
	}
}
