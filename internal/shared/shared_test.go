package shared

import (
	"testing"
)

func Test_calculatePathHash(t *testing.T) {
	tests := []struct {
		name      string
		ips       []string
		algorithm string
		want      string
	}{
		{
			name:      "empty path sha256",
			ips:       []string{},
			algorithm: "sha256",
			want:      "0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name:      "empty path crc32",
			ips:       []string{},
			algorithm: "crc32",
			want:      "00000000",
		},
		{
			name:      "single IP sha256",
			ips:       []string{"192.0.2.1"},
			algorithm: "sha256",
			want:      "1533777cbe5eb51a9de765ea723f093bb753862f1a1e9245124dc5ce21eee04f",
		},
		{
			name:      "single IP crc32",
			ips:       []string{"192.0.2.1"},
			algorithm: "crc32",
			want:      "33d71695",
		},
		{
			name:      "multiple IPs crc32",
			ips:       []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"},
			algorithm: "crc32",
			want:      "845425ea",
		},
		{
			name:      "IPs with empty string",
			ips:       []string{"192.0.2.1", "", "192.0.2.3"},
			algorithm: "crc32",
			want:      "6ceacc8b",
		},
		{
			name:      "unknown algorithm defaults to crc32",
			ips:       []string{"192.0.2.1"},
			algorithm: "unknown",
			want:      "33d71695",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculatePathHash(tt.ips, tt.algorithm)
			if got != tt.want {
				t.Errorf("calculatePathHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCalculatePathHashFromHops(t *testing.T) {
	tests := []struct {
		name      string
		hops      []*HopRun
		algorithm string
		want      string
	}{
		{
			name:      "nil hops",
			hops:      nil,
			algorithm: "crc32",
			want:      "00000000",
		},
		{
			name:      "empty hops",
			hops:      []*HopRun{},
			algorithm: "sha256",
			want:      "0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name: "single hop",
			hops: []*HopRun{
				{TTL: 1, IP: "192.0.2.1"},
			},
			algorithm: "crc32",
			want:      "33d71695",
		},
		{
			name: "multiple hops",
			hops: []*HopRun{
				{TTL: 1, IP: "192.0.2.1"},
				{TTL: 2, IP: "192.0.2.2"},
				{TTL: 3, IP: "192.0.2.3"},
			},
			algorithm: "crc32",
			want:      "845425ea",
		},
		{
			name: "hops with timeout (empty IP)",
			hops: []*HopRun{
				{TTL: 1, IP: "192.0.2.1"},
				{TTL: 2, IP: "", Timeout: true},
				{TTL: 3, IP: "192.0.2.3"},
			},
			algorithm: "crc32",
			want:      "6ceacc8b",
		},
		{
			name: "nil hop in slice",
			hops: []*HopRun{
				{TTL: 1, IP: "192.0.2.1"},
				nil,
				{TTL: 3, IP: "192.0.2.3"},
			},
			algorithm: "crc32",
			want:      "6ceacc8b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculatePathHashFromHops(tt.hops, tt.algorithm)
			if got != tt.want {
				t.Errorf("CalculatePathHashFromHops() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCalculatePathHashFromProbe(t *testing.T) {
	tests := []struct {
		name      string
		probe     *ProbeStats
		algorithm string
		want      string
	}{
		{
			name:      "nil probe",
			probe:     nil,
			algorithm: "crc32",
			want:      "00000000",
		},
		{
			name:      "empty hops",
			probe:     &ProbeStats{Hops: map[uint8]*HopStats{}},
			algorithm: "sha256",
			want:      "0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			name: "single hop",
			probe: &ProbeStats{
				Hops: map[uint8]*HopStats{
					1: {CurrentIP: "192.0.2.1"},
				},
			},
			algorithm: "crc32",
			want:      "33d71695",
		},
		{
			name: "multiple hops ordered by TTL",
			probe: &ProbeStats{
				Hops: map[uint8]*HopStats{
					3: {CurrentIP: "192.0.2.3"},
					1: {CurrentIP: "192.0.2.1"},
					2: {CurrentIP: "192.0.2.2"},
				},
			},
			algorithm: "crc32",
			want:      "845425ea",
		},
		{
			name: "hop with empty IP",
			probe: &ProbeStats{
				Hops: map[uint8]*HopStats{
					1: {CurrentIP: "192.0.2.1"},
					2: {CurrentIP: ""},
					3: {CurrentIP: "192.0.2.3"},
				},
			},
			algorithm: "crc32",
			want:      "6ceacc8b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculatePathHashFromProbe(tt.probe, tt.algorithm)
			if got != tt.want {
				t.Errorf("CalculatePathHashFromProbe() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCalculatePathHash_Consistency(t *testing.T) {
	// Verify that the same input produces the same hash
	ips := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}

	hash1 := calculatePathHash(ips, "crc32")
	hash2 := calculatePathHash(ips, "crc32")

	if hash1 != hash2 {
		t.Errorf("Hash inconsistent: first=%s, second=%s", hash1, hash2)
	}
}

func TestCalculatePathHash_Uniqueness(t *testing.T) {
	// Verify different paths produce different hashes
	path1 := []string{"192.0.2.1", "192.0.2.2"}
	path2 := []string{"192.0.2.1", "192.0.2.3"}

	hash1 := calculatePathHash(path1, "crc32")
	hash2 := calculatePathHash(path2, "crc32")

	if hash1 == hash2 {
		t.Errorf("Different paths produced same hash: %s", hash1)
	}
}

func TestCalculatePathHash_OrderMatters(t *testing.T) {
	// Verify order affects the hash
	path1 := []string{"192.0.2.1", "192.0.2.2"}
	path2 := []string{"192.0.2.2", "192.0.2.1"}

	hash1 := calculatePathHash(path1, "crc32")
	hash2 := calculatePathHash(path2, "crc32")

	if hash1 == hash2 {
		t.Errorf("Different order produced same hash: %s", hash1)
	}
}
