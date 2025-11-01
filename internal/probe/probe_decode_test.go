package probe

import (
	"testing"

	"github.com/google/gopacket/layers"
)

func TestDecodeTCPLayer_SYNACK(t *testing.T) {
	tests := []struct {
		name      string
		ack       uint32
		syn       bool
		ackFlag   bool
		rst       bool
		dstPort   uint16
		wantTTL   uint8
		wantProbe uint
		wantPort  uint
		wantFlag  string
	}{
		{
			name:      "SYN-ACK response",
			ack:       41, // 40 + 1 (TTL=2, probe=0)
			syn:       true,
			ackFlag:   true,
			rst:       false,
			dstPort:   65000,
			wantTTL:   2,
			wantProbe: 0,
			wantPort:  65000,
			wantFlag:  "SYN-ACK",
		},
		{
			name:      "RST response",
			ack:       22, // 21 + 1 (TTL=1, probe=1)
			syn:       false,
			ackFlag:   false,
			rst:       true,
			dstPort:   65005,
			wantTTL:   1,
			wantProbe: 1,
			wantPort:  65005,
			wantFlag:  "RST",
		},
		{
			name:      "high TTL SYN-ACK",
			ack:       1300, // 1299 + 1 (TTL=64, probe=19)
			syn:       true,
			ackFlag:   true,
			rst:       false,
			dstPort:   65010,
			wantTTL:   64,
			wantProbe: 19,
			wantPort:  65010,
			wantFlag:  "SYN-ACK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tcp := &layers.TCP{
				Ack:     tt.ack,
				SYN:     tt.syn,
				ACK:     tt.ackFlag,
				RST:     tt.rst,
				DstPort: layers.TCPPort(tt.dstPort),
			}

			gotTTL, gotProbe, gotPort, gotFlag := decodeTCPLayer(tcp)

			if gotTTL != tt.wantTTL {
				t.Errorf("TTL = %d, want %d", gotTTL, tt.wantTTL)
			}
			if gotProbe != tt.wantProbe {
				t.Errorf("probe = %d, want %d", gotProbe, tt.wantProbe)
			}
			if gotPort != tt.wantPort {
				t.Errorf("port = %d, want %d", gotPort, tt.wantPort)
			}
			if gotFlag != tt.wantFlag {
				t.Errorf("flag = %q, want %q", gotFlag, tt.wantFlag)
			}
		})
	}
}

func TestDecodeTCPLayer_SYN(t *testing.T) {
	// Test decoding SYN packets (ICMP-encapsulated probes)
	tests := []struct {
		name      string
		seq       uint32
		srcPort   uint16
		wantTTL   uint8
		wantProbe uint
		wantPort  uint
	}{
		{
			name:      "ICMP-encapsulated SYN",
			seq:       20, // TTL=1, probe=0
			srcPort:   65000,
			wantTTL:   1,
			wantProbe: 0,
			wantPort:  65000,
		},
		{
			name:      "ICMP-encapsulated SYN probe 5",
			seq:       45, // TTL=2, probe=5
			srcPort:   65002,
			wantTTL:   2,
			wantProbe: 5,
			wantPort:  65002,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tcp := &layers.TCP{
				Seq:     tt.seq,
				SYN:     true,
				ACK:     false,
				RST:     false,
				SrcPort: layers.TCPPort(tt.srcPort),
			}

			gotTTL, gotProbe, gotPort, gotFlag := decodeTCPLayer(tcp)

			if gotTTL != tt.wantTTL {
				t.Errorf("TTL = %d, want %d", gotTTL, tt.wantTTL)
			}
			if gotProbe != tt.wantProbe {
				t.Errorf("probe = %d, want %d", gotProbe, tt.wantProbe)
			}
			if gotPort != tt.wantPort {
				t.Errorf("port = %d, want %d", gotPort, tt.wantPort)
			}
			if gotFlag != "SYN" {
				t.Errorf("flag = %q, want SYN", gotFlag)
			}
		})
	}
}

func TestDecodeUDPLayer(t *testing.T) {
	tests := []struct {
		name      string
		length    uint16
		srcPort   uint16
		wantTTL   uint8
		wantProbe uint
		wantPort  uint
	}{
		{
			name:      "UDP probe TTL=1",
			length:    28, // 20 + 8 (UDP header)
			srcPort:   65000,
			wantTTL:   1,
			wantProbe: 0,
			wantPort:  65000,
		},
		{
			name:      "UDP probe TTL=2, probe=5",
			length:    53, // 45 + 8
			srcPort:   65005,
			wantTTL:   2,
			wantProbe: 5,
			wantPort:  65005,
		},
		{
			name:      "UDP probe TTL=64, probe=19",
			length:    1307, // 1299 + 8
			srcPort:   65010,
			wantTTL:   64,
			wantProbe: 19,
			wantPort:  65010,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			udp := &layers.UDP{
				Length:  tt.length,
				SrcPort: layers.UDPPort(tt.srcPort),
			}

			gotTTL, gotProbe, gotPort := decodeUDPLayer(udp)

			if gotTTL != tt.wantTTL {
				t.Errorf("TTL = %d, want %d", gotTTL, tt.wantTTL)
			}
			if gotProbe != tt.wantProbe {
				t.Errorf("probe = %d, want %d", gotProbe, tt.wantProbe)
			}
			if gotPort != tt.wantPort {
				t.Errorf("port = %d, want %d", gotPort, tt.wantPort)
			}
		})
	}
}
