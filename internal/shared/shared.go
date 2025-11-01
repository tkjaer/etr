package shared

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"slices"
	"strings"
	"time"
)

// Holds stats for a single IP at a given hop
type HopIPStats struct {
	Min        int64   `json:"min"`         // RTT in microseconds
	Max        int64   `json:"max"`         // RTT in microseconds
	Avg        int64   `json:"avg"`         // RTT in microseconds
	Last       int64   `json:"last"`        // Last RTT in microseconds
	StdDev     float64 `json:"stddev"`      // RTT standard deviation in microseconds
	Lost       uint    `json:"lost"`        // Number of timeouts/losses
	LossPct    float64 `json:"loss_pct"`    // Percentage loss
	Responses  uint    `json:"responses"`   // Number of responses
	Sum        int64   `json:"sum"`         // Sum of RTTs for calculating average
	SumSquares int64   `json:"sum_squares"` // Sum of squares for stddev calculation
	PTR        string  `json:"ptr"`         // PTR record for this IP
}

// Holds stats for a single hop (TTL)
type HopStats struct {
	IPs       map[string]*HopIPStats `json:"ips"`        // IP string -> stats
	CurrentIP string                 `json:"current_ip"` // Most recent IP seen at this hop
	Received  uint                   `json:"received"`   // Number of probes received at this TTL
	Lost      uint                   `json:"lost"`       // Number of probes lost at this TTL
	LossPct   float64                `json:"loss_pct"`   // Percentage loss at this TTL
}

type OutputInfo struct {
	Destination    string
	Protocol       string
	SrcPort        uint16
	DstPort        uint16
	ParallelProbes uint16
	HashAlgorithm  string
}

// Holds stats for a single probe instance
type ProbeStats struct {
	ProbeID uint16              `json:"probe_id"`
	Hops    map[uint8]*HopStats `json:"hops"` // TTL -> hop stats
}

// ProbeRun represents a single TTL iteration for one probe
type ProbeRun struct {
	ProbeID         uint16    `json:"probe_id"`
	ProbeNum        uint      `json:"probe_num"`        // Which iteration (0, 1, 2, ...)
	PathHash        string    `json:"path_hash"`        // Hash of the path taken
	SourceIP        string    `json:"source_ip"`        // Source IP address
	SourcePort      uint16    `json:"source_port"`      // Source port
	DestinationIP   string    `json:"destination_ip"`   // Destination IP address
	DestinationPort uint16    `json:"destination_port"` // Destination port
	DestinationPTR  string    `json:"destination_ptr"`  // PTR record for destination
	Protocol        string    `json:"protocol"`         // Protocol (TCP/UDP)
	ReachedDest     bool      `json:"reached_dest"`     // Whether destination was reached
	Hops            []*HopRun `json:"hops"`             // Hops sorted by TTL
	Timestamp       time.Time `json:"timestamp"`
}

// HopRun represents the result for a single TTL in one probe run
type HopRun struct {
	TTL      uint8     `json:"ttl"`
	IP       string    `json:"ip"`        // IP that responded (empty if timeout)
	RTT      int64     `json:"rtt"`       // RTT in microseconds (0 if timeout)
	Timeout  bool      `json:"timeout"`   // Whether this hop timed out
	PTR      string    `json:"ptr"`       // PTR record for this IP
	RecvTime time.Time `json:"recv_time"` // When response was received
}

// calculatePathHash computes a hash of the network path using the specified algorithm
// It takes a slice of IP addresses representing the path and returns a hash string
func calculatePathHash(ips []string, algorithm string) string {
	if len(ips) == 0 {
		switch algorithm {
		case "sha256":
			return "0000000000000000000000000000000000000000000000000000000000000000"
		case "crc32":
			return "00000000"
		default:
			return "00000000"
		}
	}

	// Build path string from IPs
	var pathBuilder strings.Builder
	for _, ip := range ips {
		if ip != "" {
			pathBuilder.WriteString(ip)
			pathBuilder.WriteString("|")
		}
	}

	pathString := pathBuilder.String()

	// Calculate hash based on algorithm
	switch algorithm {
	case "sha256":
		hash := sha256.Sum256([]byte(pathString))
		return hex.EncodeToString(hash[:])
	case "crc32":
		hash := crc32.ChecksumIEEE([]byte(pathString))
		return fmt.Sprintf("%08x", hash)
	default:
		// Default to CRC32
		hash := crc32.ChecksumIEEE([]byte(pathString))
		return fmt.Sprintf("%08x", hash)
	}
}

// CalculatePathHashFromHops computes a hash from a slice of HopRun structs
func CalculatePathHashFromHops(hops []*HopRun, algorithm string) string {
	// Extract IPs from hops
	ips := make([]string, 0, len(hops))
	for _, hop := range hops {
		if hop != nil && hop.IP != "" {
			ips = append(ips, hop.IP)
		}
	}
	return calculatePathHash(ips, algorithm)
}

// calculatePathHashFromProbe computes a hash from a ProbeStats struct
func CalculatePathHashFromProbe(probe *ProbeStats, algorithm string) string {
	if probe == nil || len(probe.Hops) == 0 {
		switch algorithm {
		case "sha256":
			return "0000000000000000000000000000000000000000000000000000000000000000"
		case "crc32":
			return "00000000"
		default:
			return "00000000"
		}
	}

	// Get sorted TTLs to ensure consistent ordering
	ttls := make([]uint8, 0, len(probe.Hops))
	for ttl := range probe.Hops {
		ttls = append(ttls, ttl)
	}
	slices.Sort(ttls)

	// Extract IPs from sorted hops
	ips := make([]string, 0, len(probe.Hops))
	for _, ttl := range ttls {
		hop := probe.Hops[ttl]
		if hop.CurrentIP != "" {
			ips = append(ips, hop.CurrentIP)
		}
	}

	return calculatePathHash(ips, algorithm)
}
