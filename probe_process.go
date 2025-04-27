package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

// TODO: Break this up into multiple functions:
// updateIPStatistics
// handleExpiredProbe
// processReceivedProbe

// TODO: See if we can come up with a better name for this function.
// processStats()?
// processProbeResult()?
// TODO: Add a function to print a summary of the results.  Maybe catch SIGINT
// and print summary before exiting?
func (p *probe) stats(sentChan chan sentMsg, recvChan chan recvMsg, outputChan chan outputMsg, ptrLookupChan chan []string, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	// Keep count of total probes sent.
	var totalProbesSent uint

	// Store data for in-flight probes.
	type probeStatEntry struct {
		sentTime time.Time
		// TODO: Remove recvTime and just calculate RTT directly instead?
		// recvTime time.Time
		origSeq uint
		rtt     int64 // microseconds
		ip      string
		flag    string
	}
	// type probeStat [][]probeStatEntry
	// type probeStat []probeStatEntry
	/*
		ps := make(probeStat, 20)
		for i := range ps {
			ps[i] = make([]probeStatEntry, p.maxTTL)
		}
	*/
	ps := make(map[string]probeStatEntry)

	// Store statistics for each IP.
	type ipStat struct {
		avg, min, max int64 // microseconds
		ptr           string
		received      uint
		lost          uint
	}
	ips := make(map[string]ipStat)

	// Keep map of last IPs seen for a given hop, so we can guess what IPs we're
	// missing a response from.
	lastHops := make(map[uint8]string)

	// Create a new TTL cache with automatic expiration of timed out probes.
	cache := ttlcache.New[string, uint8](ttlcache.WithTTL[string, uint8](p.timeout))
	go cache.Start()

	// Channel to send expired probes to.
	expiredChan := make(chan expiredMsg)

	// Send notifications when probes expire.
	cache.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, item *ttlcache.Item[string, uint8]) {
		if reason == ttlcache.EvictionReasonExpired {
			// Split the key into the original probe number and TTL.
			origProbeNum, t := splitKey(item.Key())
			/*
				func(string) (uint, uint8) {
					if probeNum, err := strconv.Atoi(strings.Split(item.Key(), ".")[0]); err == nil {
						if t, err := strconv.Atoi(strings.Split(item.Key(), ".")[1]); err == nil {
							return uint(probeNum), uint8(t)
						} else {
							log.Fatal(err)
						}
					} else {
						log.Fatal(err)
					}
					return 0, 0
				}(item.Key())
			*/

			n := item.Value()
			expiredChan <- expiredMsg{origProbeNum, n, t}
		}
	})

	// TODO: Exit program when cache is completely empty and we have no more
	// probes to send.

	// TODO: Add functionality to keep track of sent probe timestamps and
	// probe timeout so we know when to print stats.
	// Include functionality to print stats before timer expires if we have
	// received a non-ICMP response and responses for all intermediate TTLs.
	// TODO: Before printing stats, update the lossStats to include a loss for
	// the hops we're missing a response from.  The missing response can be seen
	// from empty timestamps in recvTimes.
	// TODO: Make sure to emtpty the recvTimes for the hops we're sending output
	// for, so they're ready for the next run.

	for {
		select {
		case <-stop:
			log.Debug("stopping stats")
			return

		case sent := <-sentChan:
			n := sent.probeNum % 20
			t := sent.ttl
			k := createKey(n, t)
			// Store total probes sent and then probe timestamp and
			// original-to-encoded sequence numbers for the last 20 probes.
			if totalProbesSent < sent.probeNum {
				totalProbesSent = sent.probeNum
			}
			entry := probeStatEntry{sent.timestamp, sent.probeNum, 0, "", ""}
			ps[k] = entry
			/*
				ps[n][t].sentTime = sent.timestamp
				ps[n][t].origSeq = sent.probeNum
			*/
			// cacheKey := fmt.Sprintf("%d.%d", n, t)
			// Add sent probe to cache.
			cache.Set(k, uint8(n), ttlcache.DefaultTTL)
			// fmt.Printf("Cache set: %+v\n", cache.Get(cacheKey))

		case recv := <-recvChan:
			n := recv.probeNum
			t := recv.ttl
			k := createKey(n, t)
			// origSeq := ps[k].origSeq
			// cacheKey := fmt.Sprintf("%d.%d", n, t)
			// cacheKey := fmt.Sprintf("%d.%d", origSeq, t)

			// Check if the probe has already expired.
			if _, present := cache.GetAndDelete(k); present {
				// Update RTT for this probe.
				rtt := int64(recv.timestamp.Sub(ps[k].sentTime) / time.Microsecond) // Convert time.Duration to microseconds.
				if entry, ok := ps[k]; ok {
					entry.rtt = rtt
					ps[k] = entry
				}

				// Update last seen IP for this hop/TTL.
				ip := recv.ip.String()
				lastHops[t] = ip

				// Update IP stats.
				if entry, ok := ips[ip]; ok {
					if rtt < entry.min {
						entry.min = rtt
					}
					if rtt > entry.max {
						entry.max = rtt
					}
					entry.avg = ((entry.avg * int64(entry.received)) + rtt) / int64(entry.received+1)
					entry.received++
					ips[ip] = entry
				} else {
					// Add new IP stats entry.
					ips[ip] = ipStat{rtt, rtt, rtt, ip, 1, 0}
					// Start goroutine to look up PTR in the background.
					go func(ip string, ptrLookupChan chan []string) {
						ptr, err := net.LookupAddr(ip)
						if err == nil && len(ptr) > 0 {
							// Return first PTR record with trailing period removed.
							ptrLookupChan <- []string{ip, ptr[0][:len(ptr[0])-1]}
						}
					}(ip, ptrLookupChan)
				}
				fmt.Printf("%2d. %s (%s)  %d.%d ms\n", t, ips[ip].ptr, ip, rtt/1000, rtt%1000)
				// outputChan <- outputMsg{
				// 	probeNum: n,
				// 	ttl: 	t,
				// 	ip: 	ip,
				// 	loss: ips[ip].lost,
				// 	flag: recv.flag,
				// }
			} else {
				log.Debugf("received probe %d for TTL %d, but probe already expired. (key: %v)", n, t, k)
				// TODO: Do we need to do anything else with this returning expired probe?
			}

		// Add returning PTR result.
		case ptrResult := <-ptrLookupChan:
			ip, ptr := ptrResult[0], ptrResult[1]
			if entry := ips[ip]; entry.ptr == ip {
				entry.ptr = ptr
				ips[ip] = entry
			}

		case expired := <-expiredChan:
			// outputChan <- outputMsg{
			// 	probeNum: expired.probeNum,
			// 	ttl: 	expired.ttl,
			// 	ip: ps[expired.probeNum].ip,
			// 	loss: ips[ps[expired.probeNum].ip].lost,
			// 	flag: "E",
			// }
			fmt.Printf("Expired: %+v\n", expired)
			// TODO: Add functionality for expired probe.

			/*
				default:
				// TODO: Do we need a default function?
			*/
		}
	}
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
