package etr

import (
	"log/slog"
	"time"
)

// transmitRoutine handles sending packets via the pcap handle.
// It listens for TransmitEvent messages on the transmitChan channel,
// sends the packets, and notifies the stats processor of sent packets.
func (pm *probeManager) transmitRoutine() error {
	for {
		select {
		case event := <-pm.transmitChan:
			sent := time.Now()
			err := pm.handle.WritePacketData(event.Buffer.Bytes())
			if err != nil {
				slog.Error("Error sending packet", "error", err)
				return err
			} else {
				// Notify stats processor of sent packet
				pm.statsChan <- probeEvent{
					ProbeID:   event.ProbeID,
					EventType: "sent",
					Data: &probeEventDataSent{
						ProbeNum:  event.ProbeNum,
						TTL:       event.TTL,
						Timestamp: sent,
					},
				}
			}
		case <-pm.stop:
			slog.Debug("Stopping transmit routine")
			return nil
		}
	}
}
