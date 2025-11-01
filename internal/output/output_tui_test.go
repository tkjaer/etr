package output

import (
	"testing"

	"github.com/tkjaer/etr/internal/shared"
)

func TestFormatCell(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		width     int
		alignment cellAlignment
		want      string
	}{
		{
			name:      "left align short",
			value:     "hello",
			width:     10,
			alignment: alignLeft,
			want:      "hello     ",
		},
		{
			name:      "right align short",
			value:     "world",
			width:     10,
			alignment: alignRight,
			want:      "     world",
		},
		{
			name:      "left align exact",
			value:     "exact",
			width:     5,
			alignment: alignLeft,
			want:      "exact",
		},
		{
			name:      "right align exact",
			value:     "exact",
			width:     5,
			alignment: alignRight,
			want:      "exact",
		},
		{
			name:      "left align wide",
			value:     "toolong",
			width:     3,
			alignment: alignLeft,
			want:      "toolong",
		},
		{
			name:      "right align wide",
			value:     "toolong",
			width:     3,
			alignment: alignRight,
			want:      "toolong",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCell(tt.value, tt.width, tt.alignment)
			if got != tt.want {
				t.Errorf("formatCell(%q, %d, %v) = %q, want %q", tt.value, tt.width, tt.alignment, got, tt.want)
			}
		})
	}
}

func TestTruncateToWidth(t *testing.T) {
	tests := []struct {
		name  string
		value string
		width int
		want  string
	}{
		{
			name:  "shorter than width",
			value: "short",
			width: 10,
			want:  "short",
		},
		{
			name:  "exact width",
			value: "exact",
			width: 5,
			want:  "exact",
		},
		{
			name:  "zero width",
			value: "anything",
			width: 0,
			want:  "",
		},
		{
			name:  "negative width",
			value: "test",
			width: -1,
			want:  "",
		},
		{
			name:  "empty string",
			value: "",
			width: 5,
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateToWidth(tt.value, tt.width)
			if got != tt.want {
				t.Errorf("truncateToWidth(%q, %d) = %q, want %q", tt.value, tt.width, got, tt.want)
			}
		})
	}
}

func TestCalculateProbeAggregateStats(t *testing.T) {
	tests := []struct {
		name      string
		probe     *shared.ProbeStats
		algorithm string
		want      probeAggregateStats
	}{
		{
			name: "empty probe",
			probe: &shared.ProbeStats{
				ProbeID: 1,
				Hops:    map[uint8]*shared.HopStats{},
			},
			algorithm: "crc32",
			want: probeAggregateStats{
				NumHops: 0,
				MinRTT:  0,
			},
		},
		{
			name: "single hop no responses",
			probe: &shared.ProbeStats{
				ProbeID: 1,
				Hops: map[uint8]*shared.HopStats{
					1: {
						IPs:      map[string]*shared.HopIPStats{},
						Received: 0,
						Lost:     5,
					},
				},
			},
			algorithm: "crc32",
			want: probeAggregateStats{
				NumHops: 1,
				LossPct: 100.0,
				MinRTT:  0,
			},
		},
		{
			name: "single hop with responses",
			probe: &shared.ProbeStats{
				ProbeID: 1,
				Hops: map[uint8]*shared.HopStats{
					1: {
						IPs: map[string]*shared.HopIPStats{
							"192.0.2.1": {
								Responses: 5,
								Avg:       10000, // 10ms in microseconds
								Min:       8000,  // 8ms
								Max:       12000, // 12ms
								StdDev:    1000,  // 1ms
							},
						},
						Received: 5,
						Lost:     0,
					},
				},
			},
			algorithm: "crc32",
			want: probeAggregateStats{
				NumHops: 1,
				LossPct: 0.0,
				AvgRTT:  10.0,
				MinRTT:  8.0,
				MaxRTT:  12.0,
				StdDev:  1.0,
			},
		},
		{
			name: "multiple hops uses destination only",
			probe: &shared.ProbeStats{
				ProbeID: 1,
				Hops: map[uint8]*shared.HopStats{
					1: {
						IPs: map[string]*shared.HopIPStats{
							"192.0.2.1": {
								Responses: 5,
								Avg:       5000,
								Min:       4000,
								Max:       6000,
								StdDev:    500,
							},
						},
						Received: 5,
						Lost:     0,
					},
					3: { // This is the destination (highest TTL)
						IPs: map[string]*shared.HopIPStats{
							"203.0.113.1": {
								Responses: 8,
								Avg:       20000, // 20ms
								Min:       15000, // 15ms
								Max:       25000, // 25ms
								StdDev:    2000,  // 2ms
							},
						},
						Received: 8,
						Lost:     2,
					},
				},
			},
			algorithm: "crc32",
			want: probeAggregateStats{
				NumHops: 2,
				LossPct: 20.0, // 2 lost out of 10
				AvgRTT:  20.0,
				MinRTT:  15.0,
				MaxRTT:  25.0,
				StdDev:  2.0,
			},
		},
		{
			name: "multiple IPs at destination",
			probe: &shared.ProbeStats{
				ProbeID: 1,
				Hops: map[uint8]*shared.HopStats{
					1: {
						IPs: map[string]*shared.HopIPStats{
							"192.0.2.1": {
								Responses: 3,
								Avg:       10000,
								Min:       8000,
								Max:       12000,
								StdDev:    1000,
							},
							"192.0.2.2": {
								Responses: 2,
								Avg:       15000,
								Min:       14000,
								Max:       16000,
								StdDev:    500,
							},
						},
						Received: 5,
						Lost:     0,
					},
				},
			},
			algorithm: "sha256",
			want: probeAggregateStats{
				NumHops: 1,
				LossPct: 0.0,
				AvgRTT:  12.5, // (10 + 15) / 2
				MinRTT:  8.0,
				MaxRTT:  16.0,
				StdDev:  0.75, // (1 + 0.5) / 2
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateProbeAggregateStats(tt.probe, tt.algorithm)

			if got.NumHops != tt.want.NumHops {
				t.Errorf("NumHops = %d, want %d", got.NumHops, tt.want.NumHops)
			}
			if got.LossPct != tt.want.LossPct {
				t.Errorf("LossPct = %f, want %f", got.LossPct, tt.want.LossPct)
			}
			if got.AvgRTT != tt.want.AvgRTT {
				t.Errorf("AvgRTT = %f, want %f", got.AvgRTT, tt.want.AvgRTT)
			}
			if got.MinRTT != tt.want.MinRTT {
				t.Errorf("MinRTT = %f, want %f", got.MinRTT, tt.want.MinRTT)
			}
			if got.MaxRTT != tt.want.MaxRTT {
				t.Errorf("MaxRTT = %f, want %f", got.MaxRTT, tt.want.MaxRTT)
			}
			if got.StdDev != tt.want.StdDev {
				t.Errorf("StdDev = %f, want %f", got.StdDev, tt.want.StdDev)
			}
			// PathHash is calculated, just verify it's not empty for non-empty probes
			if len(tt.probe.Hops) > 0 && got.PathHash == "" {
				t.Error("PathHash should not be empty for non-empty probe")
			}
		})
	}
}
