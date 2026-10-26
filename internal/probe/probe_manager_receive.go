package probe

import (
	"log/slog"

	"github.com/google/gopacket"
)

// recvProbes listens for incoming probe responses on the provided pcap handle.
// It decodes the packets to extract TTL, probe number, timestamp, IP address,
// and flag, and passes each response to the stats processor and its probe.
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
			probeID := uint16(port) - pm.probeConfig.SrcPort
			// All valid received probes will have a TTL.
			if ttl > 0 {
				if p := pm.getProbe(probeID); p != nil {
					stats := probeEvent{
						ProbeID:   probeID,
						EventType: "received",
						Data: &probeEventDataReceived{
							ProbeNum:  probeNum,
							TTL:       ttl,
							Timestamp: timestamp,
							IP:        ip.String(),
							Flag:      flag,
						},
					}
					resp := responseEvent{
						ProbeNum: probeNum,
						TTL:      ttl,
						Flag:     flag,
					}
					if !deliverResponse(p, stop, stats, resp) {
						slog.Debug("Stopping receive probes")
						return
					}
				}
			}
		}
	}
}

// deliverResponse passes a received response to the stats processor and to
// the probe. It never blocks once stop is closed, and returns false if stop
// was closed before the stats processor took the event.
func deliverResponse(p *Probe, stop <-chan struct{}, stats probeEvent, resp responseEvent) bool {
	// The stats processor stops reading once stop is closed.
	select {
	case p.statsChan <- stats:
	case <-stop:
		return false
	}
	// The probe uses this to stop sending higher TTLs. Retired and finished
	// probes no longer read it, so drop the event rather than block once
	// their buffer is full.
	select {
	case p.responseChan <- resp:
	default:
	}
	return true
}
