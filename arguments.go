package main

import (
	"errors"
	"flag"
)

var Args struct {
	TCP             bool
	UDP             bool
	forceIPv4       bool
	forceIPv6       bool
	destination     string
	destinationPort uint
	sourceInterface string
	sourceIP        string
	sourcePort      uint
	numProbes       uint
	maxTTL          uint
	interProbeDelay uint
}

func getArgs() error {

	flag.BoolVar(&Args.TCP, "T", false, "use TCP")
	flag.BoolVar(&Args.UDP, "U", false, "use UDP")
	flag.BoolVar(&Args.forceIPv4, "4", false, "force IPv4")
	flag.BoolVar(&Args.forceIPv6, "6", false, "force IPv6")
	flag.UintVar(&Args.destinationPort, "p", 443, "destination port")
	flag.StringVar(&Args.sourceInterface, "i", "", "source interface")
	flag.StringVar(&Args.sourceIP, "S", "", "source IP")
	flag.UintVar(&Args.sourcePort, "s", 0, "source port")
	flag.UintVar(&Args.numProbes, "n", 10, "number of probes")
	flag.UintVar(&Args.maxTTL, "n", 30, "maximum TTL")
	flag.UintVar(&Args.interProbeDelay, "d", 0, "inter-probe delay")
	flag.Parse()

	Args.destination = flag.Arg(0)

	switch {
	case Args.TCP && Args.UDP:
		return errors.New("cannot use both TCP and UDP")
	case Args.forceIPv6 && Args.forceIPv4:
		return errors.New("cannot force both IPv4 and IPv6")
	case Args.destinationPort > 65535:
		return errors.New("destination port must be between 0 and 65535")
	case Args.sourcePort > 65535:
		return errors.New("source port must be between 0 and 65535")
	case Args.maxTTL > 255:
		return errors.New("maximum TTL must be between 0 and 255")
	}

	return nil
}
