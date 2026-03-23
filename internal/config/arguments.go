package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/tkjaer/etr/internal/version"
)

var ErrMissingDestination = errors.New("destination is required")

type Args struct {
	Destination    string
	ParallelProbes uint
	NumProbes      uint
	MaxTTL         uint
	NoResolve      bool
	LookupASN      bool
	PrintBPFFilter bool

	// Protocol and ports
	TCP             bool
	UDP             bool
	ForceIPv4       bool
	ForceIPv6       bool
	DestinationPort uint
	SourcePort      uint

	// Discovery mode
	Discover                     bool
	Disco                        bool // easter egg: discovery with disco visuals
	DiscoverFlows                uint // Max source ports to probe (0 = unlimited)
	DiscoverNoNewPathsRounds     uint // Stop after N rounds with no new paths
	DiscoverPerProbeStableRounds uint // Move probe to new port after N identical rounds

	// Timing
	InterProbeDelay time.Duration
	InterTTLDelay   time.Duration
	Timeout         time.Duration

	// Output
	Json       bool          // output json to stdout
	JsonFile   string        // output json to file while showing TUI
	TUIRefresh time.Duration // TUI refresh interval
	NoStyle    bool          // disable TUI styling

	// Path hashing
	HashAlgorithm string // hash algorithm: crc32, sha256

	// Logging
	Log      string // log file path, empty means no logging
	LogLevel string // log level: debug, info, warn, error
}

func ParseArgs() (Args, error) {
	var args Args
	var showVersion bool
	var showDiscoverHelp bool
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		args.NoStyle = true
	}

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
		println("  etr -U <destination>                 # UDP traceroute")
		println("  etr -c 10 -J <destination>           # 10 probes, JSON to stdout")
		println("  etr -j results.json <destination>    # Save JSON while showing TUI")
		println("  etr -B <destination>                 # Print tcpdump filter and exit")
		println("  etr -D <destination>                 # Discover ECMP paths")
		println()
		println("Options:")
		flag.PrintDefaults()
		println()
		println("Run 'etr --discover-help' for discovery mode tuning details.")
		println()
		println("Documentation: https://github.com/tkjaer/etr")
		println("Report issues: https://github.com/tkjaer/etr/issues")
	}

	flag.BoolVarP(&showVersion, "version", "v", false, "Show version information")

	// Protocol selection, ports and addressing
	flag.BoolVarP(&args.TCP, "tcp", "T", false, "Use TCP probes (default)")
	flag.BoolVarP(&args.UDP, "udp", "U", false, "Use UDP probes (payload length encodes probe details)")
	flag.BoolVarP(&args.ForceIPv4, "ipv4", "4", false, "Force IPv4")
	flag.BoolVarP(&args.ForceIPv6, "ipv6", "6", false, "Force IPv6")
	flag.BoolVarP(&args.NoResolve, "no-resolve", "n", false, "Do not resolve IP addresses to hostnames")
	flag.BoolVarP(&args.LookupASN, "asn", "a", false, "Lookup ASN for hop and destination IPs via DNS (Team Cymru, cached) with WHOIS fallback")
	flag.BoolVarP(&args.PrintBPFFilter, "print-bpf", "B", false, "Print tcpdump-compatible BPF filter and exit")
	flag.UintVarP(&args.DestinationPort, "dest-port", "p", 0, "Destination port (default: 443 for TCP, 33434 for UDP)")
	flag.UintVarP(&args.SourcePort, "source-port", "s", 50000, "Base source port")

	// Probe counts and concurrency
	flag.UintVarP(&args.ParallelProbes, "parallel-probes", "P", 5, "Number of parallel probes")
	flag.UintVarP(&args.NumProbes, "count", "c", 0, "Number of probe iterations (0 = infinite)")
	flag.UintVarP(&args.MaxTTL, "max-ttl", "m", 30, "Maximum TTL hops")
	// Discovery mode
	flag.BoolVarP(&args.Discover, "discover", "D", false, "Discover ECMP paths and exit (see --discover-help)")
	flag.BoolVar(&showDiscoverHelp, "discover-help", false, "Show discovery mode help and exit")
	_ = flag.CommandLine.MarkHidden("discover-help")
	flag.BoolVar(&args.Disco, "disco", false, "")
	_ = flag.CommandLine.MarkHidden("disco")
	flag.UintVar(&args.DiscoverFlows, "discover-flows", 0, "Max source ports to use during discovery (0 = unlimited)")
	flag.UintVar(&args.DiscoverNoNewPathsRounds, "discover-no-new-paths-rounds", 20, "Stop after N consecutive rounds with no new paths")
	flag.UintVar(&args.DiscoverPerProbeStableRounds, "discover-per-probe-stable-rounds", 10, "Confirm path after N identical rounds")
	_ = flag.CommandLine.MarkHidden("discover-flows")
	_ = flag.CommandLine.MarkHidden("discover-no-new-paths-rounds")
	_ = flag.CommandLine.MarkHidden("discover-per-probe-stable-rounds")

	// Timing controls
	flag.DurationVarP(&args.InterTTLDelay, "inter-ttl-delay", "i", 100*time.Millisecond, "Delay between each TTL hop in a probe")
	flag.DurationVarP(&args.InterProbeDelay, "inter-probe-delay", "d", 2*time.Second, "Delay between probe iterations")
	flag.DurationVarP(&args.Timeout, "timeout", "t", 1*time.Second, "Response timeout")

	// Output and logging
	flag.BoolVarP(&args.Json, "json", "J", false, "Write JSON output to stdout (disables TUI)")
	flag.StringVarP(&args.JsonFile, "json-file", "j", "", "Write JSON output to file (keeps TUI)")
	flag.DurationVar(&args.TUIRefresh, "tui-refresh", 60*time.Millisecond, "TUI refresh interval (0 disables periodic refresh)")
	flag.StringVar(&args.LogLevel, "log-level", "error", "Log level: debug, info, warn, error")
	flag.StringVarP(&args.Log, "log", "l", "", "Diagnostic log file (empty = no logging)")
	flag.StringVar(&args.HashAlgorithm, "hash-algorithm", "crc32", "Path hash algorithm: crc32 or sha256")
	// Disable alphabetical sorting of flags
	// flag.CommandLine.SortFlags = false
	flag.Parse()

	// Handle version flag
	if showVersion {
		fmt.Println(version.FullVersion())
		os.Exit(0)
	}

	// Handle discover help flag
	if showDiscoverHelp {
		println("Discovery mode (--discover):")
		println()
		println("  Probes with sequential source ports to discover ECMP paths.")
		println("  Each source port gets its own probe with independent statistics.")
		println("  A path is confirmed once its hash is stable for 2 consecutive rounds")
		println("  where all hops responded, OR 10 rounds when some hops timed out.")
		println("  Once confirmed, the probe is retired and a new one is spawned.")
		println()
		println("  Defaults adjusted for discovery (override with explicit flags):")
		println("    -P 2        Fewer parallel probes reduces ICMP pressure on routers")
		println("    -d 500ms    Faster rounds (fewer probes make this safe)")
		println()
		println("  Tuning flags:")
		println("    --discover-flows uint                      Max source ports to try (default unlimited)")
		println("    --discover-no-new-paths-rounds uint        Stop after N rounds with no new paths (default 20)")
		println("    --discover-per-probe-stable-rounds uint    Rounds with timeouts before confirming path (default 10)")
		println()
		println("  Stopping conditions (OR):")
		println("    --discover-no-new-paths-rounds consecutive rounds with no new paths")
		println("    --discover-flows exhausted AND at least 1 no-new-paths round")
		os.Exit(0)
	}

	args.Destination = flag.Arg(0)
	if args.Destination == "" {
		return args, ErrMissingDestination
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
	case args.SourcePort > 65535:
		return args, errors.New("source port must be between 0 and 65535")
	case args.ParallelProbes == 0:
		return args, errors.New("parallel probes must be at least 1")
	case args.SourcePort+(args.ParallelProbes-1) > 65535:
		return args, errors.New("source port range (base + parallel probes - 1) must be below 65535")
	case args.MaxTTL > 255:
		return args, errors.New("maximum TTL must be between 0 and 255")
	case args.Timeout >= 20*args.InterProbeDelay:
		return args, errors.New("timeout must be less than 20 times inter-probe delay to prevent probe number wrapping issues")
	}

	if args.Disco {
		args.Discover = true
	}

	if args.Discover {
		if args.DiscoverPerProbeStableRounds == 0 {
			return args, errors.New("discover per probe stable rounds must be at least 1")
		}
		if args.DiscoverNoNewPathsRounds == 0 {
			return args, errors.New("discover no new paths rounds must be at least 1")
		}
		// Default to fewer parallel probes and slower probing in discovery mode
		// to reduce ICMP pressure on intermediate hops, unless user overrode them.
		if !flag.CommandLine.Changed("parallel-probes") {
			args.ParallelProbes = 2
		}
		if !flag.CommandLine.Changed("inter-probe-delay") {
			args.InterProbeDelay = 500 * time.Millisecond
		}
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

func PrintShortUsage() {
	fmt.Fprintln(os.Stderr, "Usage: etr [OPTIONS] DESTINATION")
	fmt.Fprintln(os.Stderr, "Try 'etr --help' for more information.")
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
