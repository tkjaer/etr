package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/tkjaer/etr/internal/version"
)

type Args struct {
	Destination    string
	ParallelProbes uint
	NumProbes      uint
	MaxTTL         uint
	NoResolve      bool

	// Protocol and ports
	TCP             bool
	UDP             bool
	ForceIPv4       bool
	ForceIPv6       bool
	DestinationPort uint
	SourcePort      uint

	// Timing
	InterProbeDelay time.Duration
	InterTTLDelay   time.Duration
	Timeout         time.Duration

	// Output
	Json     bool   // output json to stdout
	JsonFile string // output json to file while showing TUI

	// Path hashing
	HashAlgorithm string // hash algorithm: crc32, sha256

	// Logging
	Log      string // log file path, empty means no logging
	LogLevel string // log level: debug, info, warn, error
}

func ParseArgs() (Args, error) {
	var args Args
	var showVersion bool

	// Set custom usage message
	flag.Usage = func() {
		println("ETR - ECMP Traceroute")
		println()
		println("A modern traceroute tool with ECMP path detection and visualization support.")
		println()
		println("Usage:")
		println("  etr [OPTIONS] DESTINATION")
		println()
		println("Examples:")
		println("  etr <destination>                    # Basic TCP traceroute")
		println("  etr --udp <destination>              # UDP traceroute")
		println("  etr -c 10 -J <destination>           # 10 probes, JSON to stdout")
		println("  etr -j results.json <destination>    # Save JSON while showing TUI")
		println()
		println("Options:")
		flag.PrintDefaults()
		println()
		println("Documentation: https://github.com/tkjaer/etr")
		println("Report issues: https://github.com/tkjaer/etr/issues")
	}

	flag.BoolVarP(&showVersion, "version", "v", false, "Show version information")
	flag.BoolVarP(&args.TCP, "tcp", "T", false, "Use TCP probes (default)")
	flag.BoolVarP(&args.UDP, "udp", "U", false, "Use UDP probes (payload length encodes probe details)")
	flag.BoolVarP(&args.ForceIPv4, "ipv4", "4", false, "Force IPv4")
	flag.BoolVarP(&args.ForceIPv6, "ipv6", "6", false, "Force IPv6")
	flag.UintVarP(&args.DestinationPort, "dest-port", "p", 0, "Destination port (default: 443 for TCP, 33434 for UDP)")
	flag.UintVarP(&args.SourcePort, "source-port", "s", 50000, "Base source port")

	flag.UintVarP(&args.NumProbes, "count", "c", 0, "Number of probe iterations (0 = infinite)")
	flag.UintVarP(&args.MaxTTL, "max-ttl", "m", 30, "Maximum TTL hops")
	flag.BoolVarP(&args.NoResolve, "no-resolve", "n", false, "Do not resolve IP addresses to hostnames")
	flag.UintVarP(&args.ParallelProbes, "parallel-probes", "P", 5, "Number of parallel probes")
	flag.DurationVarP(&args.InterTTLDelay, "inter-ttl-delay", "i", 100*time.Millisecond, "Delay between each TTL hop in a probe")
	flag.DurationVarP(&args.InterProbeDelay, "inter-probe-delay", "d", 2*time.Second, "Delay between probe iterations")
	flag.DurationVarP(&args.Timeout, "timeout", "t", 1*time.Second, "Response timeout")
	flag.StringVarP(&args.JsonFile, "json-file", "j", "", "Write JSON output to file (keeps TUI)")
	flag.BoolVarP(&args.Json, "json", "J", false, "Write JSON output to stdout (disables TUI)")
	flag.StringVar(&args.HashAlgorithm, "hash-algorithm", "crc32", "Path hash algorithm: crc32 or sha256")
	flag.StringVarP(&args.Log, "log", "l", "", "Diagnostic log file (empty = no logging)")
	flag.StringVar(&args.LogLevel, "log-level", "error", "Log level: debug, info, warn, error")
	flag.Parse()

	// Handle version flag
	if showVersion {
		fmt.Println(version.FullVersion())
		os.Exit(0)
	}

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
	case args.Timeout >= 20*args.InterProbeDelay:
		return args, errors.New("timeout must be less than 20 times inter-probe delay to prevent probe number wrapping issues")
	}

	// Set protocol-specific default destination port if not specified
	if args.DestinationPort == 0 {
		if args.UDP {
			args.DestinationPort = 33434 // IANA allocated traceroute port
		} else {
			args.DestinationPort = 443 // HTTPS port
		}
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
