package main

import (
	"errors"
	"flag"
	"time"
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
	destination     string
	parallelProbes  uint
}

func ParseArgs() (Args, error) {
	var args Args
	flag.BoolVar(&args.TCP, "T", false, "use TCP (default)")
	flag.BoolVar(&args.UDP, "U", false, "use UDP: note UDP probes vary in size as packet length is used to encode the probe details")
	flag.BoolVar(&args.forceIPv4, "4", false, "force IPv4")
	flag.BoolVar(&args.forceIPv6, "6", false, "force IPv6")
	flag.UintVar(&args.destinationPort, "p", 443, "destination port")
	flag.UintVar(&args.sourcePort, "s", 65000, "source port")

	flag.UintVar(&args.numProbes, "c", 10, "probe count")
	flag.UintVar(&args.maxTTL, "m", 30, "maximum TTL")
	flag.UintVar(&args.parallelProbes, "P", 5, "number of parallel probes")
	flag.DurationVar(&args.interTTLDelay, "h", 100*time.Millisecond, "inter-TTL delay (delay between each TTL or hop for a probe)")
	flag.DurationVar(&args.interProbeDelay, "d", 2*time.Second, "inter-probe delay (delay between each probe)")
	flag.DurationVar(&args.timeout, "t", 1*time.Second, "timeout")
	flag.BoolVar(&args.json, "json", false, "output json to stdout")
	flag.StringVar(&args.log, "log", "", "log file path, empty means no logging")
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
