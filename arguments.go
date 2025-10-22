package main

import (
	"errors"
	"time"

	flag "github.com/spf13/pflag"
)

type Args struct {
	TCP             bool
	UDP             bool
	forceIPv4       bool
	forceIPv6       bool
	destinationPort uint
	sourcePort      uint
	numProbes       uint
	maxTTL          uint
	// FIXME: Clean this up
	interProbeDelay time.Duration
	interTTLDelay   time.Duration
	timeout         time.Duration
	json            bool   // output json to stdout
	log             string // log file path, empty means no logging
	logLevel        string // log level: debug, info, warn, error
	destination     string
	parallelProbes  uint
}

func ParseArgs() (Args, error) {
	var args Args
	flag.BoolVarP(&args.TCP, "tcp", "T", false, "Use TCP (default)")
	flag.BoolVarP(&args.UDP, "udp", "U", false, "Use UDP: note UDP probes vary in size as packet length is used to encode the probe details")
	flag.BoolVarP(&args.forceIPv4, "ipv4", "4", false, "Force IPv4")
	flag.BoolVarP(&args.forceIPv6, "ipv6", "6", false, "Force IPv6")
	flag.UintVarP(&args.destinationPort, "dest-port", "p", 443, "Destination port")
	flag.UintVarP(&args.sourcePort, "source-port", "s", 65000, "Source port")

	flag.UintVarP(&args.numProbes, "count", "c", 10, "Probe count")
	flag.UintVarP(&args.maxTTL, "max-ttl", "m", 30, "Maximum TTL")
	flag.UintVarP(&args.parallelProbes, "parallel-probes", "P", 5, "Number of parallel probes")
	flag.DurationVarP(&args.interTTLDelay, "inter-ttl-delay", "h", 100*time.Millisecond, "Inter-TTL delay (delay between each TTL or hop for a probe)")
	flag.DurationVarP(&args.interProbeDelay, "inter-probe-delay", "d", 2*time.Second, "Inter-probe delay (delay between each probe)")
	flag.DurationVarP(&args.timeout, "timeout", "t", 1*time.Second, "Timeout")
	flag.BoolVarP(&args.json, "json", "j", false, "Output json to stdout")
	flag.StringVarP(&args.log, "log", "l", "", "Log file path, empty means no logging")
	flag.StringVar(&args.logLevel, "log-level", "error", "Log level: debug, info, warn, error")
	flag.Parse()

	args.destination = flag.Arg(0)
	if args.destination == "" {
		return args, errors.New("destination is required")
	}

	switch {
	case args.TCP && args.UDP:
		return args, errors.New("cannot use both TCP and UDP")
	case !args.TCP && !args.UDP:
		args.TCP = true // default to TCP
	case args.forceIPv6 && args.forceIPv4:
		return args, errors.New("cannot force both IPv4 and IPv6")
	case args.destinationPort > 65535:
		return args, errors.New("destination port must be between 0 and 65535")
	case args.sourcePort+args.parallelProbes > 65535:
		return args, errors.New("source port+parallel probes must be below 65535")
	case args.maxTTL > 255:
		return args, errors.New("maximum TTL must be between 0 and 255")
	case args.timeout >= 20*args.interProbeDelay*1000:
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
