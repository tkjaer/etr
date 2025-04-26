package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jellydator/ttlcache/v3"
	"github.com/sirupsen/logrus"
	"github.com/tkjaer/etr/pkg/arp"
	"github.com/tkjaer/etr/pkg/route"
	"golang.org/x/term"
)

type probe struct {
	proto           layers.IPProtocol
	inet            layers.IPProtocol
	etherType       layers.EthernetType
	dstIP           netip.Addr
	srcIP           netip.Addr
	dstPort         uint16
	srcPort         uint16
	srcIface        net.Interface
	srcMAC          net.HardwareAddr
	dstMAC          net.HardwareAddr
	interProbeDelay time.Duration
	interTTLDelay   time.Duration
	numProbes       uint
	maxTTL          uint8
	timeout         time.Duration
	outputType      string
}

var log = logrus.New()

func (p *probe) init() {

	log.Out = os.Stdout
	log.SetLevel(logrus.InfoLevel)

	err := getArgs()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
		// 	log.Fatal(err)
	}

	if Args.json {
		p.outputType = "json"
	} else {
		if term.IsTerminal(int(os.Stdout.Fd())) {
			p.outputType = "terminal"
		} else {
			p.outputType = "ascii"
		}
	}

	// set probe protocol
	switch {
	case Args.TCP:
		p.proto = layers.IPProtocolTCP
	case Args.UDP:
		p.proto = layers.IPProtocolUDP
	default:
		p.proto = layers.IPProtocolTCP
	}

	d, err := GetDestinationIP()
	if err != nil {
		log.Fatal(err)
	}
	log.Debug("Destination IP: ", d)

	// route, err := GetRouteInformation()
	route, err := route.Get(d)
	if err != nil {
		log.Fatal(err)
	}
	log.Debugf("Route: %+v\n", route)

	p.dstMAC, err = arp.Get(route.Gateway.AsSlice(), route.Interface, route.Source.AsSlice())
	if err != nil {
		log.Fatal(err)
	}

	p.dstIP = route.Destination
	p.srcIP = route.Source
	p.srcMAC = route.Interface.HardwareAddr
	p.srcIface = *route.Interface

	// set EtherType and INET Protocol based on dstIP version
	switch {
	case p.dstIP.Is4():
		p.etherType = layers.EthernetTypeIPv4
		p.inet = layers.IPProtocolIPv4
	case p.dstIP.Is6():
		p.etherType = layers.EthernetTypeIPv6
		p.inet = layers.IPProtocolIPv6
	}

	p.dstPort = uint16(Args.destinationPort)
	p.srcPort = uint16(Args.sourcePort)
	p.numProbes = Args.numProbes
	p.interProbeDelay = Args.interProbeDelay
	p.interTTLDelay = Args.interTTLDelay
	p.maxTTL = uint8(Args.maxTTL)
	p.timeout = Args.timeout
}

func decodeTCPLayer(tcpLayer *layers.TCP) (ttl uint8, probeNum uint, flag string) {
	if tcpLayer.SYN && tcpLayer.ACK || tcpLayer.RST {
		// The returned ACK number is the *sent* sequence number + 1
		ttl, probeNum = decodeSeq(tcpLayer.Ack - 1)
		if tcpLayer.SYN && tcpLayer.ACK {
			flag = "SYN-ACK"
		} else if tcpLayer.RST {
			flag = "RST"
		}
	} else if tcpLayer.SYN {
		// If we're decoding a SYN-only packet, it's a probe returned
		// ICMP-encapsulated and we'll look at the original sequence number
		ttl, probeNum = decodeSeq(tcpLayer.Seq)
		if tcpLayer.SYN {
			flag = "SYN"
		}
	}
	return
}

func decodeUDPLayer(udpLayer *layers.UDP) (ttl uint8, probeNum uint) {
	// Remove 8 bytes (UDP header) from length and decode the sequence number
	return decodeSeq(uint32(udpLayer.Length - 8))
}

func protoToLayerType(proto layers.IPProtocol) gopacket.LayerType {
	switch proto {
	case layers.IPProtocolIPv4:
		return layers.LayerTypeIPv4
	case layers.IPProtocolIPv6:
		return layers.LayerTypeIPv6
	case layers.IPProtocolTCP:
		return layers.LayerTypeTCP
	case layers.IPProtocolUDP:
		return layers.LayerTypeUDP
	default:
		return layers.LayerTypeTCP
	}
}

func (p *probe) decodeICMPv4Layer(icmp4Layer *layers.ICMPv4) (ttl uint8, probeNum uint, flag string) {
	if icmp4Layer.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded && icmp4Layer.TypeCode.Code() == layers.ICMPv4CodeTTLExceeded {
		if packet := gopacket.NewPacket(icmp4Layer.Payload, protoToLayerType(p.inet), gopacket.Default); packet != nil {

			inetLayer := packet.Layer(protoToLayerType(p.inet))
			if inetLayer == nil {
				return
			}

			// Verify source and destination IP addresses
			switch p.inet {
			case layers.IPProtocolIPv4:
				if src := inetLayer.(*layers.IPv4).SrcIP; !src.Equal(net.IP(p.srcIP.AsSlice())) {
					return
				} else if dst := inetLayer.(*layers.IPv4).DstIP; !dst.Equal(net.IP(p.dstIP.AsSlice())) {
					return
				}
			case layers.IPProtocolIPv6:
				if src := inetLayer.(*layers.IPv6).SrcIP; !src.Equal(net.IP(p.srcIP.AsSlice())) {
					return
				} else if dst := inetLayer.(*layers.IPv6).DstIP; !dst.Equal(net.IP(p.dstIP.AsSlice())) {
					return
				}
			}

			// Verify source and destination ports.
			//
			// If we have an ErrorLayer, we're probably looking at a truncated TCP header, so we'll try
			// to decode this before potentially checking a TCP layer gopacket failed to decode.
			if errorLayer := packet.Layer(gopacket.LayerTypeDecodeFailure); errorLayer != nil {
				if srcPort := binary.BigEndian.Uint16(inetLayer.LayerPayload()[:2]); srcPort != p.srcPort {
					return
				} else if dstPort := binary.BigEndian.Uint16(inetLayer.LayerPayload()[2:4]); dstPort != p.dstPort {
					return
				} else {
					ttl, probeNum = decodeSeq(binary.BigEndian.Uint32(inetLayer.LayerPayload()[4:8]))
					return
				}
			}
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				if srcPort := tcpLayer.(*layers.TCP).SrcPort; srcPort != layers.TCPPort(p.srcPort) {
					return
				} else if dstPort := tcpLayer.(*layers.TCP).DstPort; dstPort != layers.TCPPort(p.dstPort) {
					return
				}
				ttl, probeNum, flag = decodeTCPLayer(tcpLayer.(*layers.TCP))
				return
			}
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				if srcPort := udpLayer.(*layers.UDP).SrcPort; srcPort != layers.UDPPort(p.srcPort) {
					return
				} else if dstPort := udpLayer.(*layers.UDP).DstPort; dstPort != layers.UDPPort(p.dstPort) {
					return
				}
				ttl, probeNum = decodeUDPLayer(udpLayer.(*layers.UDP))
				return
			}
		}
	}
	return
}

func (p *probe) decodeRecvProbe(packet gopacket.Packet) (ttl uint8, probeNum uint, timestamp time.Time, ip net.IP, flag string) {
	// Decode any ICMP layers first to ensure we're catching TTL exceeded and
	// not just parsing the inner layer.
	if icmp4Layer := packet.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
		ttl, probeNum, _ = p.decodeICMPv4Layer(icmp4Layer.(*layers.ICMPv4))
		flag = "TTL"
	} else if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		// TODO: implement decodeICMPv6Layer()
		fmt.Println("ICMPv6 decode not implemented yet")
	} else {
		switch p.proto {
		case layers.IPProtocolTCP:
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				ttl, probeNum, flag = decodeTCPLayer(tcpLayer.(*layers.TCP))
			}
		case layers.IPProtocolUDP:
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				ttl, probeNum = decodeUDPLayer(udpLayer.(*layers.UDP))
			}
		}
	}
	ip = packet.NetworkLayer().NetworkFlow().Src().Raw()
	timestamp = packet.Metadata().Timestamp
	return
}

// Create BPF filter string to capture returning probes.
func (p *probe) pcapFilter() string {
	var proto string
	switch p.proto {
	case layers.IPProtocolTCP:
		proto = "tcp"
	case layers.IPProtocolUDP:
		proto = "udp"
	}
	var ttl_exceeded string
	switch p.inet {
	case layers.IPProtocolIPv4:
		ttl_exceeded = "icmp and icmp[0] == 11 and icmp[1] == 0"
	case layers.IPProtocolIPv6:
		ttl_exceeded = "icmp6 and icmp6.type == 3 and icmp6.code == 0"
	}
	return fmt.Sprintf("(%v and src host %v and dst host %v and src port %v and dst port %v) or (%v)", proto, p.dstIP, p.srcIP, p.dstPort, p.srcPort, ttl_exceeded)
}

// Message type for communication between sendProbes() and sendStats().
type sentMsg struct {
	probeNum  uint
	ttl       uint8
	timestamp time.Time
}

// Message type for communication between recvProbes() and sendStats().
type recvMsg struct {
	probeNum  uint
	ttl       uint8
	timestamp time.Time
	ip        net.IP
	flag      string
}

type expiredMsg struct {
	origProbeNum uint
	probeNum     uint8
	ttl          uint8
}

// Message type for communication between sendStats() and outputStats().
type outputMsg struct {
	probeNum uint
	ttl      uint8
	ip       string
	// host     string
	// sentTime time.Time
	// rtt      time.Duration
	// delayVariation time.Duration
	// avgRTT time.Duration
	// minRTT time.Duration
	// maxRTT time.Duration
	loss uint
	flag string
}

func (p *probe) recvProbes(handle *pcap.Handle, recvChan chan recvMsg, responseReceivedChan chan uint, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	if err := handle.SetBPFFilter(p.pcapFilter()); err != nil {
		log.Fatal(err)
	}
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			log.Debug("stopping recvProbes")
			return
		case packet = <-in:
			ttl, probeNum, timestamp, ip, flag := p.decodeRecvProbe(packet)
			// All valid received probes will have a TTL.
			if ttl > 0 {
				// Report received probe.
				recvChan <- recvMsg{probeNum, ttl, timestamp, ip, flag}
				// Report if we've received a non-"TTL exceeded" response so we
				// stop sending further packets for this probe number.
				if flag != "TTL" {
					go func(responseReceivedChan chan uint, probeNum uint) {
						responseReceivedChan <- probeNum
					}(responseReceivedChan, probeNum)
				}
			}
		}
	}
}

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
func encodeSeq(ttl uint8, probeNum uint) (seq uint32) {
	return uint32(ttl)*20 + uint32(probeNum%20)
}

// Decode the sequence and return TTL and probe number.
func decodeSeq(seq uint32) (ttl uint8, probeNum uint) {
	return uint8(seq / 20), uint(seq % 20)
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

func (p *probe) run() {
	log.Info("Starting probe")

	handle, err := pcap.OpenLive(p.srcIface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Channel for reporting sent probes.
	// The probeNum reported here is the total probe number.
	sentChan := make(chan sentMsg)

	// Channel for reporting received probes.
	// The probeNum reported here is the encoded probe number (0-19).
	recvChan := make(chan recvMsg)

	// Channel for sending results to output.
	outputChan := make(chan outputMsg)

	// Channel for sending PTR lookup results.
	ptrLookupChan := make(chan []string)

	responseReceivedChan := make(chan uint)

	// Channel for sending stop signal to goroutines.
	stop := make(chan struct{})
	// defer close(stop)

	var wg sync.WaitGroup

	wg.Add(4)

	go p.output(outputChan, stop, &wg)
	go p.stats(sentChan, recvChan, outputChan, ptrLookupChan, stop, &wg)
	go p.recvProbes(handle, recvChan, responseReceivedChan, stop, &wg)
	go p.sendProbes(handle, sentChan, responseReceivedChan, stop, &wg)

	// TODO: replace with waitgroup.
	// time.Sleep(35 * time.Second)

	wg.Wait()

}

func (p *probe) output(outputChan chan outputMsg, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	// TODO: Clear terminal

	// var out []string

	select {
	case <-stop:
		log.Debug("stopping output")
		return
	case msg := <-outputChan:
		fmt.Printf("%2v. %-15v %3v - %v (%v)\n", msg.ttl, msg.ip, msg.loss, msg.probeNum, msg.flag)
	}
	// fmt.Printf("%3v. %-15v %3v - %v (%v)\n", ttl, ip, timestamp.Sub(start), probeNum, flag)
}

func (p *probe) sendProbes(handle *pcap.Handle, sentChan chan sentMsg, responseReceivedChan chan uint, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	eth := layers.Ethernet{
		SrcMAC:       p.srcMAC,
		DstMAC:       p.dstMAC,
		EthernetType: p.etherType,
	}

	// TODO: Maybe keep a single start time and use the offset from that for all probes?
	var lastProbeStart time.Time

	for n := uint(0); n < p.numProbes; n++ {
		// Probe number is 0-indexed, so we add 1 before logging
		log.Debugf("Sending probe %d", n)

		lastProbeStart = time.Now()

		t := uint8(0)

	TTLLoop:
		for t < p.maxTTL {

			select {
			// Stop sending TTL increments if we've received a response for this
			// probe.
			case response := <-responseReceivedChan:
				if response == n {
					break TTLLoop
				} else {
					log.Debugf("Received response for probe %d, but expected %d", response, n)
				}
			default:
				t++
				switch p.inet {
				case layers.IPProtocolIPv4:
					ip := layers.IPv4{
						Version:  4,
						TTL:      t,
						Protocol: p.proto,
						SrcIP:    p.srcIP.AsSlice(),
						DstIP:    p.dstIP.AsSlice(),
						Flags:    layers.IPv4DontFragment,
					}
					switch p.proto {
					case layers.IPProtocolTCP:
						tcp := layers.TCP{
							Seq:     encodeSeq(t, n),
							SrcPort: layers.TCPPort(p.srcPort),
							DstPort: layers.TCPPort(p.dstPort),
							SYN:     true,
							Window:  65535,
						}
						tcp.SetNetworkLayerForChecksum(&ip)
						gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp)
						handle.WritePacketData(buf.Bytes())
					case layers.IPProtocolUDP:
						udp := layers.UDP{
							SrcPort: layers.UDPPort(p.srcPort),
							DstPort: layers.UDPPort(p.dstPort),
							Length:  uint16(8 + encodeSeq(t, n)),
						}
						udp.SetNetworkLayerForChecksum(&ip)
						gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp)
						handle.WritePacketData(buf.Bytes())
					}
				case layers.IPProtocolIPv6:
					ip := layers.IPv6{
						Version:    6,
						HopLimit:   t,
						NextHeader: p.proto,
						SrcIP:      p.srcIP.AsSlice(),
						DstIP:      p.dstIP.AsSlice(),
					}
					switch p.proto {
					case layers.IPProtocolTCP:
						tcp := layers.TCP{
							Seq:     encodeSeq(t, n),
							SrcPort: layers.TCPPort(p.srcPort),
							DstPort: layers.TCPPort(p.dstPort),
							SYN:     true,
							Window:  65535,
						}
						tcp.SetNetworkLayerForChecksum(&ip)
						gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp)
						handle.WritePacketData(buf.Bytes())
					case layers.IPProtocolUDP:
						udp := layers.UDP{
							SrcPort: layers.UDPPort(p.srcPort),
							DstPort: layers.UDPPort(p.dstPort),
							Length:  uint16(8 + encodeSeq(t, n)),
						}
						udp.SetNetworkLayerForChecksum(&ip)
						gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp)
						handle.WritePacketData(buf.Bytes())
					}
				}
				sentChan <- sentMsg{n, t, time.Now()}
				time.Sleep(p.interTTLDelay)
			}

		}
		// Sleep for interProbeDelay if we haven't already spent that much time
		// sending the probe.
		if time.Since(lastProbeStart) < p.interProbeDelay {
			time.Sleep(p.interProbeDelay - time.Since(lastProbeStart))
		}
		fmt.Println("")
	}
	// Sleep for probe timeout to ensure we don't miss any late responses.
	time.Sleep(p.timeout)
	log.Debug("Finished sending probes")
	close(stop)
}
