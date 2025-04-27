package main

import "github.com/google/gopacket/layers"

func decodeUDPLayer(udpLayer *layers.UDP) (ttl uint8, probeNum uint) {
	// Remove 8 bytes (UDP header) from length and decode the sequence number
	return decodeSeq(uint32(udpLayer.Length - 8))
}
