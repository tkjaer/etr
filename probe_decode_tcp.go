package main

import "github.com/google/gopacket/layers"

func decodeTCPLayer(tcpLayer *layers.TCP) (ttl uint8, probeNum uint, flag string) {
	if tcpLayer.SYN && tcpLayer.ACK || tcpLayer.RST {
		// The returned ACK number is the *sent* sequence number + 1
		ttl, probeNum = decodeTTLAndProbe(tcpLayer.Ack - 1)
		if tcpLayer.SYN && tcpLayer.ACK {
			flag = "SYN-ACK"
		} else if tcpLayer.RST {
			flag = "RST"
		}
	} else if tcpLayer.SYN {
		// If we're decoding a SYN-only packet, it's a probe returned
		// ICMP-encapsulated and we'll look at the original sequence number
		ttl, probeNum = decodeTTLAndProbe(tcpLayer.Seq)
		if tcpLayer.SYN {
			flag = "SYN"
		}
	}
	return
}
