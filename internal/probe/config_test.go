package probe

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tkjaer/etr/internal/config"
)

func TestConfig_withDefaults(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want Config
	}{
		{
			name: "zero value",
			cfg:  Config{Destination: "x"},
			want: Config{
				Destination:     "x",
				SrcPort:         DefaultSrcPort,
				DstPort:         DefaultTCPDstPort,
				ParallelProbes:  DefaultParallelProbes,
				MaxTTL:          DefaultMaxTTL,
				InterTTLDelay:   DefaultInterTTLDelay,
				InterProbeDelay: DefaultInterProbeDelay,
				Timeout:         DefaultTimeout,
				HashAlgorithm:   HashCRC32,
			},
		},
		{
			name: "UDP destination port",
			cfg:  Config{Destination: "x", Protocol: ProtocolUDP},
			want: Config{
				Destination:     "x",
				Protocol:        ProtocolUDP,
				SrcPort:         DefaultSrcPort,
				DstPort:         DefaultUDPDstPort,
				ParallelProbes:  DefaultParallelProbes,
				MaxTTL:          DefaultMaxTTL,
				InterTTLDelay:   DefaultInterTTLDelay,
				InterProbeDelay: DefaultInterProbeDelay,
				Timeout:         DefaultTimeout,
				HashAlgorithm:   HashCRC32,
			},
		},
		{
			name: "discovery mode",
			cfg:  Config{Destination: "x", Discovery: &DiscoveryConfig{}},
			want: Config{
				Destination:     "x",
				SrcPort:         DefaultSrcPort,
				DstPort:         DefaultTCPDstPort,
				ParallelProbes:  DefaultDiscoveryParallelProbes,
				MaxTTL:          DefaultMaxTTL,
				InterTTLDelay:   DefaultInterTTLDelay,
				InterProbeDelay: DefaultDiscoveryInterProbeDelay,
				Timeout:         DefaultTimeout,
				HashAlgorithm:   HashCRC32,
				Discovery: &DiscoveryConfig{
					NoNewPathsRounds: DefaultNoNewPathsRounds,
					StableRounds:     DefaultStableRounds,
				},
			},
		},
		{
			name: "explicit values kept",
			cfg: Config{
				Destination:     "x",
				Protocol:        ProtocolUDP,
				SrcPort:         1000,
				DstPort:         53,
				ParallelProbes:  3,
				Count:           4,
				MaxTTL:          10,
				InterTTLDelay:   -1,
				InterProbeDelay: time.Second,
				Timeout:         time.Second,
				HashAlgorithm:   HashSHA256,
			},
			want: Config{
				Destination:     "x",
				Protocol:        ProtocolUDP,
				SrcPort:         1000,
				DstPort:         53,
				ParallelProbes:  3,
				Count:           4,
				MaxTTL:          10,
				InterTTLDelay:   -1,
				InterProbeDelay: time.Second,
				Timeout:         time.Second,
				HashAlgorithm:   HashSHA256,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.withDefaults()
			if !configEqual(got, tt.want) {
				t.Errorf("withDefaults() = %+v, want %+v", got, tt.want)
			}
			if err := got.validate(); err != nil {
				t.Errorf("validate() after withDefaults() = %v, want nil", err)
			}
		})
	}
}

func TestConfig_withDefaultsDoesNotModifyDiscovery(t *testing.T) {
	d := &DiscoveryConfig{}
	Config{Destination: "x", Discovery: d}.withDefaults()
	if *d != (DiscoveryConfig{}) {
		t.Errorf("withDefaults() modified caller's DiscoveryConfig: %+v", *d)
	}
}

func TestConfig_validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"missing destination", Config{}, "destination is required"},
		{"bad protocol", Config{Destination: "x", Protocol: 9}, "unsupported protocol"},
		{"bad family", Config{Destination: "x", Family: 9}, "unsupported address family"},
		{"bad hash", Config{Destination: "x", HashAlgorithm: "md5"}, "hash algorithm must be either 'crc32' or 'sha256'"},
		{"port range overflow", Config{Destination: "x", SrcPort: 65530, ParallelProbes: 10}, "source port range (base + parallel probes - 1) must not exceed 65535"},
		{"port range at limit", Config{Destination: "x", SrcPort: 65531, ParallelProbes: 5}, ""},
		{"negative inter-probe delay", Config{Destination: "x", InterProbeDelay: -1}, "inter-probe delay must not be negative"},
		{"negative timeout", Config{Destination: "x", Timeout: -1}, "timeout must not be negative"},
		{"timeout too long", Config{Destination: "x", InterProbeDelay: time.Second, Timeout: 20 * time.Second}, "timeout must be less than 20 times inter-probe delay"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.withDefaults().validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestConfigFromArgs(t *testing.T) {
	tests := []struct {
		name string
		args config.Args
		want Config
	}{
		{
			name: "defaults",
			args: config.Args{Destination: "x", InterTTLDelay: time.Millisecond},
			want: Config{Destination: "x", ResolvePTR: true, InterTTLDelay: time.Millisecond},
		},
		{
			name: "UDP, IPv6, no resolve, sha256",
			args: config.Args{Destination: "x", UDP: true, ForceIPv6: true, NoResolve: true, HashAlgorithm: "sha256", InterTTLDelay: time.Millisecond},
			want: Config{Destination: "x", Protocol: ProtocolUDP, Family: FamilyIPv6, HashAlgorithm: HashSHA256, InterTTLDelay: time.Millisecond},
		},
		{
			name: "IPv4",
			args: config.Args{Destination: "x", ForceIPv4: true, InterTTLDelay: time.Millisecond},
			want: Config{Destination: "x", Family: FamilyIPv4, ResolvePTR: true, InterTTLDelay: time.Millisecond},
		},
		{
			name: "zero inter-TTL delay disables delay",
			args: config.Args{Destination: "x"},
			want: Config{Destination: "x", ResolvePTR: true, InterTTLDelay: -time.Nanosecond},
		},
		{
			name: "discovery",
			args: config.Args{Destination: "x", Discover: true, DiscoverHops: true, DiscoverFlows: 7, DiscoverNoNewPathsRounds: 3, DiscoverPerProbeStableRounds: 4, InterTTLDelay: time.Millisecond},
			want: Config{Destination: "x", ResolvePTR: true, InterTTLDelay: time.Millisecond, Discovery: &DiscoveryConfig{Hops: true, MaxFlows: 7, NoNewPathsRounds: 3, StableRounds: 4}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ConfigFromArgs(tt.args); !configEqual(got, tt.want) {
				t.Errorf("ConfigFromArgs() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestGetDestinationIP_literalFamily(t *testing.T) {
	tests := []struct {
		name    string
		dest    string
		family  Family
		wantErr bool
	}{
		{"IPv4 any", "192.0.2.1", FamilyAny, false},
		{"IPv6 any", "2001:db8::1", FamilyAny, false},
		{"IPv4 forced IPv4", "192.0.2.1", FamilyIPv4, false},
		{"IPv6 forced IPv6", "2001:db8::1", FamilyIPv6, false},
		{"IPv4 forced IPv6", "192.0.2.1", FamilyIPv6, true},
		{"IPv6 forced IPv4", "2001:db8::1", FamilyIPv4, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getDestinationIP(context.Background(), tt.dest, tt.family)
			if (err != nil) != tt.wantErr {
				t.Errorf("getDestinationIP(%q, %v) error = %v, wantErr %v", tt.dest, tt.family, err, tt.wantErr)
			}
		})
	}
}

func TestGetDestinationIPCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := getDestinationIP(ctx, "etr-test.invalid", FamilyAny)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("getDestinationIP() error = %v, want context.Canceled", err)
	}
}

// configEqual compares Configs, including the DiscoveryConfig they point to.
func configEqual(a, b Config) bool {
	ad, bd := a.Discovery, b.Discovery
	a.Discovery, b.Discovery = nil, nil
	if a != b {
		return false
	}
	if ad == nil || bd == nil {
		return ad == bd
	}
	return *ad == *bd
}
