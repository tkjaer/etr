package config

import (
	"errors"
	"time"

	flag "github.com/spf13/pflag"
)

type Args struct {
	TCP             bool
	UDP             bool
	ForceIPv4       bool
	ForceIPv6       bool
	DestinationPort uint
	SourcePort      uint
	NumProbes       uint
	MaxTTL          uint
	// FIXME: Clean this up
	InterProbeDelay time.Duration
	InterTTLDelay   time.Duration
	Timeout         time.Duration
	Json            bool   // output json to stdout
	JsonFile        string // output json to file while showing TUI
	HashAlgorithm   string // hash algorithm: crc32, sha256
	Log             string // log file path, empty means no logging
	LogLevel        string // log level: debug, info, warn, error
	Destination     string
	ParallelProbes  uint
}

func ParseArgs() (Args, error) {
	var args Args
	flag.BoolVarP(&args.TCP, "tcp", "T", false, "Use TCP (default)")
	flag.BoolVarP(&args.UDP, "udp", "U", false, "Use UDP: note UDP probes vary in size as packet length is used to encode the probe details")
	flag.BoolVarP(&args.ForceIPv4, "ipv4", "4", false, "Force IPv4")
	flag.BoolVarP(&args.ForceIPv6, "ipv6", "6", false, "Force IPv6")
	flag.UintVarP(&args.DestinationPort, "dest-port", "p", 443, "Destination port")
	flag.UintVarP(&args.SourcePort, "source-port", "s", 65000, "Source port")

	flag.UintVarP(&args.NumProbes, "count", "c", 10, "Probe count")
	flag.UintVarP(&args.MaxTTL, "max-ttl", "m", 30, "Maximum TTL")
	flag.UintVarP(&args.ParallelProbes, "parallel-probes", "P", 5, "Number of parallel probes")
	flag.DurationVarP(&args.InterTTLDelay, "inter-ttl-delay", "h", 100*time.Millisecond, "Inter-TTL delay (delay between each TTL or hop for a probe)")
	flag.DurationVarP(&args.InterProbeDelay, "inter-probe-delay", "d", 2*time.Second, "Inter-probe delay (delay between each probe)")
	flag.DurationVarP(&args.Timeout, "timeout", "t", 1*time.Second, "Timeout")
	flag.BoolVarP(&args.Json, "json", "j", false, "Output JSON to stdout (disables TUI)")
	flag.StringVarP(&args.JsonFile, "json-file", "J", "", "Output JSON to file (keeps TUI enabled)")
	flag.StringVar(&args.HashAlgorithm, "hash-algorithm", "crc32", "Hash algorithm for path hash: crc32, sha256 (truncated to 8 hex chars in TUI)")
	flag.StringVarP(&args.Log, "log", "l", "", "Diagnostic log file path (empty = no diagnostic logs)")
	flag.StringVar(&args.LogLevel, "log-level", "error", "Diagnostic log level: debug, info, warn, error")
	flag.Parse()

	args.Destination = flag.Arg(0)
	if args.Destination == "" {
		return args, errors.New("destination is required")
	}

	switch {
	case args.Json && args.JsonFile != "":
		return args, errors.New("cannot use both --json and --json-file")
	case args.HashAlgorithm != "crc32" && args.HashAlgorithm != "sha256":
		return args, errors.New("hash algorithm must be either 'crc32' or 'sha256'")
	case args.TCP && args.UDP:
		return args, errors.New("cannot use both TCP and UDP")
	case !args.TCP && !args.UDP:
		args.TCP = true // default to TCP
	case args.ForceIPv6 && args.ForceIPv4:
		return args, errors.New("cannot force both IPv4 and IPv6")
	case args.DestinationPort > 65535:
		return args, errors.New("destination port must be between 0 and 65535")
	case args.SourcePort+args.ParallelProbes > 65535:
		return args, errors.New("source port+parallel probes must be below 65535")
	case args.MaxTTL > 255:
		return args, errors.New("maximum TTL must be between 0 and 255")
	case args.Timeout >= 20*args.InterProbeDelay*1000:
		return args, errors.New("timeout must be less than 20 times the inter-probe delay in seconds, as active probe count is limited to 20")
	}

	return args, nil
}

// ProtocolName returns the protocol name based on args
func (a Args) ProtocolName() string {
	if a.TCP {
		return "TCP"
	}
	if a.UDP {
		return "UDP"
	}
	return "TCP"
}
