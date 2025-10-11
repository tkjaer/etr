package main

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
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

// GetDestinationIP resolves the destination IP address if necessary, validates it and returns it
func getDestinationIP(a Args) (netip.Addr, error) {
	// Check if destination is an IP address
	d, err := netip.ParseAddr(a.destination)
	if err == nil {
		return d, nil
	} else {
		// If not, resolve it
		lookup, err := net.LookupHost(a.destination)
		if err != nil {
			return netip.Addr{}, err
		}

		// Find the first valid IP that meets our criteria
		for _, record := range lookup {
			ip, err := netip.ParseAddr(record)
			if err != nil {
				continue
			}
			switch {
			case a.forceIPv4 && ip.Is4():
				d = ip
			case a.forceIPv6 && ip.Is6():
				d = ip
			case !a.forceIPv4 && !a.forceIPv6:
				d = ip
			}
			// Return if we succeed
			if d.IsValid() {
				return d, nil
			}
		}
	}

	return netip.Addr{}, errors.New("could not resolve destination")
}

func createKey(probeNum uint, ttl uint8) string {
	return fmt.Sprintf("%v:%v", probeNum, ttl)
}

func splitKey(key string) (probeNum uint, ttl uint8) {
	split := strings.Split(key, ":")
	if probeNum, err := strconv.Atoi(split[0]); err == nil {
		if t, err := strconv.Atoi(split[1]); err == nil {
			return uint(probeNum), uint8(t)
		}
	}
	return
}

func calculateStdev(sum int64, sumSquares int64, n uint) float64 {
	mean := float64(sum) / float64(n)
	variance := float64(sumSquares)/float64(n) - mean*mean
	if variance < 0 {
		variance = 0 // Prevent negative due to floating point errors
	}
	return math.Sqrt(variance)
}
