package probe

import (
	"math"
	"testing"
)

func TestEncodeTTLAndProbe(t *testing.T) {
	tests := []struct {
		ttl      uint8
		probeNum uint
		want     uint32
	}{
		{ttl: 1, probeNum: 0, want: 20},
		{ttl: 1, probeNum: 1, want: 21},
		{ttl: 1, probeNum: 19, want: 39},
		{ttl: 2, probeNum: 0, want: 40},
		{ttl: 2, probeNum: 5, want: 45},
		{ttl: 64, probeNum: 0, want: 1280},
		{ttl: 64, probeNum: 19, want: 1299},
		{ttl: 255, probeNum: 0, want: 5100},
		{ttl: 255, probeNum: 19, want: 5119},
		// Test probe wrapping (20+ becomes 0-19)
		{ttl: 1, probeNum: 20, want: 20}, // 20 % 20 = 0
		{ttl: 1, probeNum: 21, want: 21}, // 21 % 20 = 1
		{ttl: 1, probeNum: 39, want: 39}, // 39 % 20 = 19
	}

	for _, tt := range tests {
		got := encodeTTLAndProbe(tt.ttl, tt.probeNum)
		if got != tt.want {
			t.Errorf("encodeTTLAndProbe(%d, %d) = %d, want %d", tt.ttl, tt.probeNum, got, tt.want)
		}
	}
}

func TestDecodeTTLAndProbe(t *testing.T) {
	tests := []struct {
		seq       uint32
		wantTTL   uint8
		wantProbe uint
	}{
		{seq: 20, wantTTL: 1, wantProbe: 0},
		{seq: 21, wantTTL: 1, wantProbe: 1},
		{seq: 39, wantTTL: 1, wantProbe: 19},
		{seq: 40, wantTTL: 2, wantProbe: 0},
		{seq: 45, wantTTL: 2, wantProbe: 5},
		{seq: 1280, wantTTL: 64, wantProbe: 0},
		{seq: 1299, wantTTL: 64, wantProbe: 19},
		{seq: 5100, wantTTL: 255, wantProbe: 0},
		{seq: 5119, wantTTL: 255, wantProbe: 19},
		{seq: 0, wantTTL: 0, wantProbe: 0},
	}

	for _, tt := range tests {
		gotTTL, gotProbe := decodeTTLAndProbe(tt.seq)
		if gotTTL != tt.wantTTL || gotProbe != tt.wantProbe {
			t.Errorf("decodeTTLAndProbe(%d) = (%d, %d), want (%d, %d)",
				tt.seq, gotTTL, gotProbe, tt.wantTTL, tt.wantProbe)
		}
	}
}

func TestEncodeDecode_RoundTrip(t *testing.T) {
	// Test that encode and decode are inverse operations
	tests := []struct {
		ttl      uint8
		probeNum uint
	}{
		{1, 0}, {1, 5}, {1, 19},
		{10, 0}, {10, 10}, {10, 19},
		{64, 0}, {64, 19},
		{255, 0}, {255, 19},
	}

	for _, tt := range tests {
		encoded := encodeTTLAndProbe(tt.ttl, tt.probeNum%20)
		gotTTL, gotProbe := decodeTTLAndProbe(encoded)

		expectedProbe := tt.probeNum % 20
		if gotTTL != tt.ttl || gotProbe != expectedProbe {
			t.Errorf("Round trip failed for TTL=%d, probe=%d: got TTL=%d, probe=%d",
				tt.ttl, tt.probeNum, gotTTL, gotProbe)
		}
	}
}

func TestCalculateStdDev(t *testing.T) {
	tests := []struct {
		name       string
		sum        int64
		sumSquares int64
		n          uint
		want       float64
	}{
		{
			name:       "all same values (no variance)",
			sum:        50, // 5 values of 10 each
			sumSquares: 500,
			n:          5,
			want:       0,
		},
		{
			name:       "simple variance",
			sum:        15, // values: 1, 2, 3, 4, 5 (mean=3)
			sumSquares: 55, // 1 + 4 + 9 + 16 + 25
			n:          5,
			want:       math.Sqrt(2), // StdDev ≈ 1.414
		},
		{
			name:       "single value",
			sum:        10,
			sumSquares: 100,
			n:          1,
			want:       0,
		},
		{
			name:       "negative variance protection",
			sum:        100,
			sumSquares: 50, // Deliberately wrong to test protection
			n:          10,
			want:       0, // Should clamp to 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateStdDev(tt.sum, tt.sumSquares, tt.n)
			if math.Abs(got-tt.want) > 0.001 {
				t.Errorf("calculateStdDev(%d, %d, %d) = %f, want %f",
					tt.sum, tt.sumSquares, tt.n, got, tt.want)
			}
		})
	}
}

func TestCalculateLossPct(t *testing.T) {
	tests := []struct {
		lost     uint
		received uint
		want     float64
	}{
		{lost: 0, received: 10, want: 0},
		{lost: 10, received: 0, want: 100},
		{lost: 5, received: 5, want: 50},
		{lost: 1, received: 9, want: 10},
		{lost: 3, received: 7, want: 30},
		{lost: 0, received: 0, want: 0}, // No packets = no loss
		{lost: 25, received: 75, want: 25},
		{lost: 1, received: 99, want: 1},
	}

	for _, tt := range tests {
		got := calculateLossPct(tt.lost, tt.received)
		if got != tt.want {
			t.Errorf("calculateLossPct(%d, %d) = %f, want %f",
				tt.lost, tt.received, got, tt.want)
		}
	}
}
