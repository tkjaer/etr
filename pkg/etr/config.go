package etr

import (
	"errors"
	"fmt"
	"time"
)

// Protocol selects the transport protocol used for probes.
type Protocol uint8

const (
	ProtocolTCP Protocol = iota // TCP SYN probes (default)
	ProtocolUDP                 // UDP probes; payload length encodes probe details
)

func (p Protocol) String() string {
	switch p {
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	default:
		return fmt.Sprintf("Protocol(%d)", uint8(p))
	}
}

// Family restricts which address family is used when resolving Destination.
type Family uint8

const (
	FamilyAny  Family = iota // first address returned by the resolver (default)
	FamilyIPv4               // IPv4 only
	FamilyIPv6               // IPv6 only
)

// HashAlgorithm selects the algorithm used to identify unique paths.
type HashAlgorithm string

const (
	HashCRC32  HashAlgorithm = "crc32" // default
	HashSHA256 HashAlgorithm = "sha256"
)

// Default values applied to zero-valued Config fields.
const (
	DefaultSrcPort          uint16 = 50000
	DefaultTCPDstPort       uint16 = 443
	DefaultUDPDstPort       uint16 = 33434 // IANA allocated traceroute port
	DefaultParallelProbes   uint16 = 5
	DefaultMaxTTL           uint8  = 30
	DefaultInterTTLDelay           = 100 * time.Millisecond
	DefaultInterProbeDelay         = 2 * time.Second
	DefaultTimeout                 = 1 * time.Second
	DefaultNoNewPathsRounds uint   = 20
	DefaultStableRounds     uint   = 10

	// Fewer parallel probes in discovery mode reduces ICMP pressure on routers
	DefaultDiscoveryParallelProbes  uint16 = 2
	DefaultDiscoveryInterProbeDelay        = 500 * time.Millisecond
)

// Config describes a traceroute run. Zero-valued fields get defaults.
type Config struct {
	Destination string // hostname or IP address (required)
	Protocol    Protocol
	Family      Family

	SrcPort        uint16 // base source port; probe N uses SrcPort+N
	DstPort        uint16 // 0 = protocol default
	ParallelProbes uint16
	Count          uint // probe iterations, 0 = until stopped
	MaxTTL         uint8

	InterTTLDelay   time.Duration // negative = no delay
	InterProbeDelay time.Duration
	Timeout         time.Duration // must be < 20*InterProbeDelay

	ResolvePTR    bool
	LookupASN     bool
	HashAlgorithm HashAlgorithm

	Discovery *DiscoveryConfig // nil = normal traceroute mode
}

// DiscoveryConfig tunes ECMP discovery mode.
type DiscoveryConfig struct {
	Hops             bool // discover unique hops instead of unique paths
	MaxFlows         uint // max source ports to probe, 0 = unlimited
	NoNewPathsRounds uint // stop after N rounds with no new paths
	StableRounds     uint // confirm path after N identical rounds
}

// withDefaults returns a copy of c with zero-valued fields set to defaults.
func (c Config) withDefaults() Config {
	if c.SrcPort == 0 {
		c.SrcPort = DefaultSrcPort
	}
	if c.DstPort == 0 {
		if c.Protocol == ProtocolUDP {
			c.DstPort = DefaultUDPDstPort
		} else {
			c.DstPort = DefaultTCPDstPort
		}
	}
	if c.ParallelProbes == 0 {
		if c.Discovery != nil {
			c.ParallelProbes = DefaultDiscoveryParallelProbes
		} else {
			c.ParallelProbes = DefaultParallelProbes
		}
	}
	if c.MaxTTL == 0 {
		c.MaxTTL = DefaultMaxTTL
	}
	if c.InterTTLDelay == 0 {
		c.InterTTLDelay = DefaultInterTTLDelay
	}
	if c.InterProbeDelay == 0 {
		if c.Discovery != nil {
			c.InterProbeDelay = DefaultDiscoveryInterProbeDelay
		} else {
			c.InterProbeDelay = DefaultInterProbeDelay
		}
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if c.HashAlgorithm == "" {
		c.HashAlgorithm = HashCRC32
	}
	if c.Discovery != nil {
		d := *c.Discovery
		if d.NoNewPathsRounds == 0 {
			d.NoNewPathsRounds = DefaultNoNewPathsRounds
		}
		if d.StableRounds == 0 {
			d.StableRounds = DefaultStableRounds
		}
		c.Discovery = &d
	}
	return c
}

// validate checks a Config that has had defaults applied.
func (c Config) validate() error {
	switch {
	case c.Destination == "":
		return errors.New("destination is required")
	case c.Protocol != ProtocolTCP && c.Protocol != ProtocolUDP:
		return fmt.Errorf("unsupported protocol: %v", c.Protocol)
	case c.Family > FamilyIPv6:
		return fmt.Errorf("unsupported address family: %d", c.Family)
	case c.HashAlgorithm != HashCRC32 && c.HashAlgorithm != HashSHA256:
		return errors.New("hash algorithm must be either 'crc32' or 'sha256'")
	case uint32(c.SrcPort)+uint32(c.ParallelProbes)-1 > 65535:
		return errors.New("source port range (base + parallel probes - 1) must not exceed 65535")
	case c.InterProbeDelay < 0:
		return errors.New("inter-probe delay must not be negative")
	case c.Timeout < 0:
		return errors.New("timeout must not be negative")
	case c.Timeout >= 20*c.InterProbeDelay:
		// Probe numbers are encoded modulo 20; a longer timeout could match
		// a late response to a newer probe with the same number.
		return errors.New("timeout must be less than 20 times inter-probe delay to prevent probe number wrapping issues")
	}
	return nil
}
