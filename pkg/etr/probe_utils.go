package etr

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
)

// Encode the probe number and TTL into a single value.
//
// As some operating systems still use the historic RFC 792 format for ICMP
// error messages, we need to encode the TTL and probe number into a field
// within the first 64 bit of the TCP and UDP protocol headers.
//
// For TCP we use the 32-bit sequence number field that follows source and
// destination port which takes up the first 32 bit.
//
// For UDP, we use the 16-bit length field, as the first 32 bits are used for
// source and destination port and the last 16 bits for checksum.
//
// To keep the sequence number small enough to fit into the UDP length field,
// while ensuring that the packet still is valid and fits into a 1500 byte
// Ethernet MTU, TTL is multiplied by 20 and the probe number added.  This also
// allows manual decoding of the sequence number if needed.
//
// This encoding leaves room for 20 probes (0-19) and the RFC1812 "common" TTL
// of 64 while keeping the MTU below 1500 bytes including IPv4 or IPv6 header.
//
// TTL + probe + UDP header = 64*20 + 19 + 8 == 1307
func encodeTTLAndProbe(ttl uint8, probeNum uint) (seq uint32) {
	return uint32(ttl)*20 + uint32(probeNum%20)
}

// Decode the sequence and return TTL and probe number.
func decodeTTLAndProbe(seq uint32) (ttl uint8, probeNum uint) {
	return uint8(seq / 20), uint(seq % 20)
}

// getDestinationIP resolves dest if necessary and returns the first address
// matching family.
func getDestinationIP(ctx context.Context, dest string, family Family) (netip.Addr, error) {
	matches := func(ip netip.Addr) bool {
		switch family {
		case FamilyIPv4:
			return ip.Is4()
		case FamilyIPv6:
			return ip.Is6()
		default:
			return true
		}
	}

	if d, err := netip.ParseAddr(dest); err == nil {
		if !matches(d) {
			return netip.Addr{}, fmt.Errorf("destination %v does not match requested address family", d)
		}
		return d, nil
	}

	lookup, err := net.DefaultResolver.LookupHost(ctx, dest)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, record := range lookup {
		if ip, err := netip.ParseAddr(record); err == nil && matches(ip) {
			return ip, nil
		}
	}

	return netip.Addr{}, errors.New("could not resolve destination")
}

func calculateStdDev(sum int64, sumSquares int64, n uint) float64 {
	mean := float64(sum) / float64(n)
	variance := float64(sumSquares)/float64(n) - mean*mean
	if variance < 0 {
		variance = 0 // Prevent negative due to floating point errors
	}
	return math.Sqrt(variance)
}

func calculateLossPct(lost uint, received uint) float64 {
	total := lost + received
	if total == 0 {
		return 0
	}
	return (100 * float64(lost)) / float64(total)
}
