package probe

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestLocateInnerIPv6Header(t *testing.T) {
	tests := []struct {
		name       string
		payload    []byte
		wantOffset int
		wantFound  bool
	}{
		{
			name:       "too short",
			payload:    make([]byte, 30),
			wantOffset: 0,
			wantFound:  false,
		},
		{
			name:       "IPv6 at start",
			payload:    append([]byte{0x60, 0x00, 0x00, 0x00}, make([]byte, 36)...),
			wantOffset: 0,
			wantFound:  true,
		},
		{
			name:       "IPv6 at offset 4",
			payload:    append([]byte{0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00}, make([]byte, 36)...),
			wantOffset: 4,
			wantFound:  true,
		},
		{
			name:       "IPv6 at offset 10",
			payload:    append(make([]byte, 10), append([]byte{0x60, 0x00, 0x00, 0x00}, make([]byte, 36)...)...),
			wantOffset: 10,
			wantFound:  true,
		},
		{
			name:       "no IPv6 header",
			payload:    make([]byte, 50),
			wantOffset: 0,
			wantFound:  false,
		},
		{
			name:       "IPv4 only (version 4)",
			payload:    append([]byte{0x45, 0x00, 0x00, 0x00}, make([]byte, 36)...),
			wantOffset: 0,
			wantFound:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOffset, gotFound := locateInnerIPv6Header(tt.payload)
			if gotOffset != tt.wantOffset {
				t.Errorf("offset = %d, want %d", gotOffset, tt.wantOffset)
			}
			if gotFound != tt.wantFound {
				t.Errorf("found = %v, want %v", gotFound, tt.wantFound)
			}
		})
	}
}

func TestProtoToLayerType(t *testing.T) {
	tests := []struct {
		proto layers.IPProtocol
		want  gopacket.LayerType
	}{
		{layers.IPProtocolIPv4, layers.LayerTypeIPv4},
		{layers.IPProtocolIPv6, layers.LayerTypeIPv6},
		{layers.IPProtocolTCP, layers.LayerTypeTCP},
		{layers.IPProtocolUDP, layers.LayerTypeUDP},
		// Default case: unknown protocols return TCP
		{layers.IPProtocolICMPv4, layers.LayerTypeTCP},
		{layers.IPProtocolICMPv6, layers.LayerTypeTCP},
		{layers.IPProtocol(255), layers.LayerTypeTCP},
	}

	for _, tt := range tests {
		got := protoToLayerType(tt.proto)
		if got != tt.want {
			t.Errorf("protoToLayerType(%v) = %v, want %v", tt.proto, got, tt.want)
		}
	}
}
