package main

import "github.com/google/gopacket/layers"

// decodeUDPLayer decodes a UDP layer and returns the TTL and probe number.
func decodeUDPLayer(udpLayer *layers.UDP) (ttl uint8, probeNum uint, port uint) {
	// Remove 8 bytes (UDP header) from length and decode the sequence number
	ttl, probeNum = decodeTTLAndProbe(uint32(udpLayer.Length - 8))

	// We only support TTLExceeded responses for UDP, so we just use the dstPort
	port = uint(udpLayer.DstPort) // Use destination port for UDP packets
	return
}
