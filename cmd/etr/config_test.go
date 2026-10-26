package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/tkjaer/etr/internal/config"
	"github.com/tkjaer/etr/pkg/etr"
)

func TestConfigFromArgs(t *testing.T) {
	tests := []struct {
		name string
		args config.Args
		want etr.Config
	}{
		{
			name: "defaults",
			args: config.Args{Destination: "x", InterTTLDelay: time.Millisecond},
			want: etr.Config{Destination: "x", ResolvePTR: true, InterTTLDelay: time.Millisecond},
		},
		{
			name: "UDP, IPv6, no resolve, sha256",
			args: config.Args{Destination: "x", UDP: true, ForceIPv6: true, NoResolve: true, HashAlgorithm: "sha256", InterTTLDelay: time.Millisecond},
			want: etr.Config{Destination: "x", Protocol: etr.ProtocolUDP, Family: etr.FamilyIPv6, HashAlgorithm: etr.HashSHA256, InterTTLDelay: time.Millisecond},
		},
		{
			name: "IPv4",
			args: config.Args{Destination: "x", ForceIPv4: true, InterTTLDelay: time.Millisecond},
			want: etr.Config{Destination: "x", Family: etr.FamilyIPv4, ResolvePTR: true, InterTTLDelay: time.Millisecond},
		},
		{
			name: "zero inter-TTL delay disables delay",
			args: config.Args{Destination: "x"},
			want: etr.Config{Destination: "x", ResolvePTR: true, InterTTLDelay: -time.Nanosecond},
		},
		{
			name: "discovery",
			args: config.Args{Destination: "x", Discover: true, DiscoverHops: true, DiscoverFlows: 7, DiscoverNoNewPathsRounds: 3, DiscoverPerProbeStableRounds: 4, InterTTLDelay: time.Millisecond},
			want: etr.Config{Destination: "x", ResolvePTR: true, InterTTLDelay: time.Millisecond, Discovery: &etr.DiscoveryConfig{Hops: true, MaxFlows: 7, NoNewPathsRounds: 3, StableRounds: 4}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := configFromArgs(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("configFromArgs() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
