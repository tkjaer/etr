package probe

import "github.com/google/gopacket/layers"

// decodeTCPLayer decodes a TCP layer and returns the TTL, probe number, and flag.
func decodeTCPLayer(tcpLayer *layers.TCP) (ttl uint8, probeNum uint, port uint, flag string) {
	if tcpLayer.SYN && tcpLayer.ACK || tcpLayer.RST {
		// The returned ACK number is the *sent* sequence number + 1
		ttl, probeNum = decodeTTLAndProbe(tcpLayer.Ack - 1)
		if tcpLayer.SYN && tcpLayer.ACK {
			flag = "SYN-ACK"
		} else if tcpLayer.RST {
			flag = "RST"
		}
		// Use destination port for SYN-ACK and RST packets
		port = uint(tcpLayer.DstPort)

	} else if tcpLayer.SYN {
		// If we're decoding a SYN-only packet, it's a probe returned
		// ICMP-encapsulated and we'll look at the original sequence number
		ttl, probeNum = decodeTTLAndProbe(tcpLayer.Seq)
		if tcpLayer.SYN {
			flag = "SYN"
		}
		// Use source port for SYN packets as they're TCP headers we sent
		// that now return encapsulated in ICMP.
		port = uint(tcpLayer.SrcPort)
	}

	return
}
