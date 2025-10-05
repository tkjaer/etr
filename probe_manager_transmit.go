package main

import "time"

// transmitRoutine handles sending packets via the pcap handle.
// It listens for TransmitEvent messages on the transmitChan channel,
// sends the packets, and notifies the stats processor of sent packets.
func (pm *ProbeManager) transmitRoutine() error {
	for {
		select {
		case event := <-pm.transmitChan:
			err := pm.handle.WritePacketData(event.Buffer.Bytes())
			if err != nil {
				log.Debugf("Error sending packet: %v", err)
				return err
			} else {
				// Notify stats processor of sent packet
				pm.statsChan <- ProbeEvent{
					ProbeID:   event.ProbeID,
					EventType: "sent",
					Data: map[string]interface{}{
						"ttl":       event.TTL,
						"timestamp": time.Now(),
					},
				}
			}
		case <-pm.stop:
			log.Debug("Stopping transmit routine")
			return nil
		}
	}
}
