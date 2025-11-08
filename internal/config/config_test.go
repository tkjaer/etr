package config

import (
	"log/slog"
	"os"
	"testing"
	"time"

	flag "github.com/spf13/pflag"
)

func TestArgs_ProtocolName(t *testing.T) {
	tests := []struct {
		name string
		args Args
		want string
	}{
		{
			name: "TCP",
			args: Args{TCP: true},
			want: "TCP",
		},
		{
			name: "UDP",
			args: Args{UDP: true},
			want: "UDP",
		},
		{
			name: "neither (defaults to TCP)",
			args: Args{},
			want: "TCP",
		},
		{
			name: "both set (TCP takes precedence)",
			args: Args{TCP: true, UDP: true},
			want: "TCP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.args.ProtocolName(); got != tt.want {
				t.Errorf("ProtocolName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseLogLevel(t *testing.T) {
	tests := []struct {
		level string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"unknown", slog.LevelInfo}, // default
		{"", slog.LevelInfo},        // default
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			if got := parseLogLevel(tt.level); got != tt.want {
				t.Errorf("parseLogLevel(%q) = %v, want %v", tt.level, got, tt.want)
			}
		})
	}
}

func TestParseArgs_Validation(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "missing destination",
			args:    []string{},
			wantErr: "destination is required",
		},
		{
			name:    "both json and json-file",
			args:    []string{"--json", "--json-file", "test.json", "example.com"},
			wantErr: "cannot use both --json and --json-file",
		},
		{
			name:    "invalid hash algorithm",
			args:    []string{"--hash-algorithm", "md5", "example.com"},
			wantErr: "hash algorithm must be either 'crc32' or 'sha256'",
		},
		{
			name:    "both TCP and UDP",
			args:    []string{"--tcp", "--udp", "example.com"},
			wantErr: "cannot use both TCP and UDP",
		},
		{
			name:    "both IPv4 and IPv6 with TCP",
			args:    []string{"--tcp", "--ipv4", "--ipv6", "example.com"},
			wantErr: "cannot force both IPv4 and IPv6",
		},
		{
			name:    "destination port too large with TCP",
			args:    []string{"--tcp", "--dest-port", "70000", "example.com"},
			wantErr: "destination port must be between 0 and 65535",
		},
		{
			name:    "source port + parallel probes exceeds limit with TCP",
			args:    []string{"--tcp", "--source-port", "65530", "--parallel-probes", "10", "example.com"},
			wantErr: "source port+parallel probes must be below 65535",
		},
		{
			name:    "max ttl too large with TCP",
			args:    []string{"--tcp", "--max-ttl", "300", "example.com"},
			wantErr: "maximum TTL must be between 0 and 255",
		},
		{
			name: "valid minimal config",
			args: []string{"example.com"},
		},
		{
			name: "valid with TCP",
			args: []string{"--tcp", "example.com"},
		},
		{
			name: "valid with UDP",
			args: []string{"--udp", "example.com"},
		},
		{
			name: "valid with IPv4",
			args: []string{"--ipv4", "example.com"},
		},
		{
			name: "valid with custom ports",
			args: []string{"--dest-port", "80", "--source-port", "50000", "example.com"},
		},
		{
			name: "valid sha256 hash",
			args: []string{"--hash-algorithm", "sha256", "example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset flag package for each test
			flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)

			// Mock os.Args
			oldArgs := os.Args
			os.Args = append([]string{"cmd"}, tt.args...)
			defer func() { os.Args = oldArgs }()

			args, err := ParseArgs()

			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("ParseArgs() expected error %q, got nil", tt.wantErr)
				} else if err.Error() != tt.wantErr {
					t.Errorf("ParseArgs() error = %v, want %v", err.Error(), tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("ParseArgs() unexpected error: %v", err)
				}
				// Verify destination was set
				if args.Destination == "" {
					t.Error("ParseArgs() destination should be set for valid args")
				}
			}
		})
	}
}

func TestParseArgs_Defaults(t *testing.T) {
	// Reset flag package
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)

	oldArgs := os.Args
	os.Args = []string{"cmd", "example.com"}
	defer func() { os.Args = oldArgs }()

	args, err := ParseArgs()
	if err != nil {
		t.Fatalf("ParseArgs() unexpected error: %v", err)
	}

	// Check defaults
	if !args.TCP {
		t.Error("Default should be TCP")
	}
	if args.UDP {
		t.Error("UDP should be false by default")
	}
	if args.DestinationPort != 443 {
		t.Errorf("Default destination port = %v, want 443", args.DestinationPort)
	}
	if args.SourcePort != 50000 {
		t.Errorf("Default source port = %v, want 50000", args.SourcePort)
	}
	if args.NumProbes != 0 {
		t.Errorf("Default probe count = %v, want 0 (infinite)", args.NumProbes)
	}
	if args.MaxTTL != 30 {
		t.Errorf("Default max TTL = %v, want 30", args.MaxTTL)
	}
	if args.ParallelProbes != 5 {
		t.Errorf("Default parallel probes = %v, want 5", args.ParallelProbes)
	}
	if args.InterTTLDelay != 100*time.Millisecond {
		t.Errorf("Default inter-TTL delay = %v, want 100ms", args.InterTTLDelay)
	}
	if args.InterProbeDelay != 2*time.Second {
		t.Errorf("Default inter-probe delay = %v, want 2s", args.InterProbeDelay)
	}
	if args.Timeout != 1*time.Second {
		t.Errorf("Default timeout = %v, want 1s", args.Timeout)
	}
	if args.HashAlgorithm != "crc32" {
		t.Errorf("Default hash algorithm = %v, want crc32", args.HashAlgorithm)
	}
	if args.LogLevel != "error" {
		t.Errorf("Default log level = %v, want error", args.LogLevel)
	}
	if args.Destination != "example.com" {
		t.Errorf("Destination = %v, want example.com", args.Destination)
	}
}

func TestParseArgs_UDPDefaults(t *testing.T) {
	// Reset flag package
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)

	oldArgs := os.Args
	os.Args = []string{"cmd", "--udp", "example.com"}
	defer func() { os.Args = oldArgs }()

	args, err := ParseArgs()
	if err != nil {
		t.Fatalf("ParseArgs() unexpected error: %v", err)
	}

	// Check UDP-specific defaults
	if args.TCP {
		t.Error("TCP should be false when UDP is specified")
	}
	if !args.UDP {
		t.Error("UDP should be true")
	}
	if args.DestinationPort != 33434 {
		t.Errorf("Default destination port for UDP = %v, want 33434", args.DestinationPort)
	}
	if args.SourcePort != 50000 {
		t.Errorf("Default source port = %v, want 50000", args.SourcePort)
	}
}
