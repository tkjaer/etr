package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
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
}

var log = logrus.New()

func (p *probe) init() {

	log.Out = os.Stdout
	log.SetLevel(logrus.DebugLevel)

	err := getArgs()
	if err != nil {
		log.Fatal(err)
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

	// check destination
	dstIP, err := lookupDst(Args.destination, Args.forceIPv4, Args.forceIPv6)
	if err != nil {
		log.Fatal(err)
	}
	p.dstIP = dstIP

	// set EtherType and INET Protocol based on dstIP version
	switch {
	case p.dstIP.Is4():
		p.etherType = layers.EthernetTypeIPv4
		p.inet = layers.IPProtocolIPv4
	case p.dstIP.Is6():
		p.etherType = layers.EthernetTypeIPv6
		p.inet = layers.IPProtocolIPv6
	}

	// lookup source IP, interface, and source + dest MAC with lookupSrc():
	// temporary values:
	if Args.sourceIP != "" {
		srcIP, err := netip.ParseAddr(Args.sourceIP)
		if err != nil {
			log.Fatal(err)
		}
		p.srcIP = srcIP
		// TODO: implement interface lookup
		p.srcIface = net.Interface{Index: 1, Name: Args.sourceInterface}
	} else {
		// TODO: implement lookupSrc()
		log.Fatal("source IP not specified, which is required for now")
	}

	// temporary flag based MAC assignment
	// TODO: remove this once the lookup function is implemented
	p.srcMAC, err = net.ParseMAC(Args.sourceMAC)
	if err != nil {
		log.Fatal(err)
	}
	p.dstMAC, err = net.ParseMAC(Args.destinationMAC)
	if err != nil {
		log.Fatal(err)
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

// Message type for communication between sendStats() and outputStats().
type outputMsg struct {
	probeNum       uint
	ttl            uint8
	ip             net.IP
	host           string
	sentTime       time.Time
	rtt            time.Duration
	// delayVariation time.Duration
	avgRTT         time.Duration
	minRTT         time.Duration
	maxRTT         time.Duration
	loss           uint
	flag           string
}
type outputMsgs []outputMsg

func (p *probe) recvProbes(handle *pcap.Handle, recvChan chan recvMsg, responseReceivedChan chan uint, stop chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
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
			wg.Done()
			return
		case packet = <-in:
			ttl, probeNum, timestamp, ip, flag := p.decodeRecvProbe(packet)
			// All valid received probes will have a TTL.
			if ttl > 0 {
				// Report received probe.
				recvChan <- recvMsg{probeNum, ttl, timestamp, ip, flag}
				// Report if we've received a non-"TTL exceeded" response.
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
// within the first 8 bytes of the TCP and protocol headers.
//
// For TCP we use the 32-bit sequence number field, as the first 32 bits are
// used for source and destination port.
//
// For UDP, we use the 16-bit length field, as the first 32 bits are used for
// source and destination port and the last 16 bits for checksum.
//
// To keep the sequence number small enough to fit into the UDP frame length
// field, while ensuring that the packet still is valid and fits into a 1500
// byte Ethernet MTU, TTL is multiplied by 20 and the probe number added.  This
// also allows manual decoding of the sequence number if needed.
//
// This encoding leaves room for 20 probes (0-19) and the RFC1812 "common" TTL
// of 64 while keeping the MTU below 1500 bytes including IPv4 or IPv6 header.
//
// TTL + probe + UDP header = 64*20 + 19 + 8 == 1307
func encodeSeq(ttl uint8, probeNum uint) (seq uint32) {
	return uint32(ttl)*20 + uint32(probeNum)
}

// Decode the sequence and return TTL and probe number.
func decodeSeq(seq uint32) (ttl uint8, probeNum uint) {
	return uint8(seq / 20), uint(seq % 20)
}

// TODO: See if we can come up with a better name for this function.
// processStats()?
// processProbeResult()?
// TODO: Add a function to print a summary of the results.  Maybe catch SIGINT
// and print summary before exiting?
func (p *probe) stats(sentChan chan sentMsg, recvChan chan recvMsg, outputChan chan outputMsgs, ptrLookupChan chan []string, stop chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)

	// Keep count of total probes sent.
	var totalProbesSent uint

	// Store data for in-flight probes.
	type probeStat struct {
		sentTime time.Time
		// TODO: Remove recvTime and just calculate RTT directly instead?
		// recvTime time.Time
		origSeq  uint32
		ttl      time.Duration
		ip       string
		flag     string
	}
	ps := [20][p.maxTTL]probeStat

	// Store statistics for each IP.
	type ipStat struct {
		avg, min, max time.Duration
		ptr           string
		received      uint
		lost          uint
	}
	ips := make(map[string]ipStat)




	// type ipStat struct {
	// avg, min, max time.Duration
	// ptr           string
	// received      uint
	// lost          uint
	// }
	// ipStats := make(map[string]ipStat)

	// List of resolved PTR records to include hostnames in output.
	// Key is string(IP), value is hostname.
	ptrs := make(map[string]string)

	// TTL history for each probe and hop.
	var ttls [20][p.maxTTL]time.Time

	// TTL stats on a per IP basis.
	type ttlStat struct {
		avg, min, max time.Duration
	}
	// Key is string(IP), value is ttlStat struct.
	ttlStats := make(map[string]ttlStat)

	// List of IPs and received / lost probes to calculate packet loss.
	type lossStat struct {
		lost     uint
		received uint
	}
	// Key is string(IP), value is lossStat struct.
	lossStats := make(map[string]lossStat)

	// Keep map of last hops (string(IP)), so we can guess what hops are
	// missing/have packet loss.
	lastHops := make(map[uint8]string)

	// Store sent and received probe timers so we can calculate latency.
	var (
		sentTimes [20][p.maxTTL]time.Time
		recvTimes [20][p.maxTTL]time.Time
	)

	// Store received flags so we can print them in the output.
	var recvFlags [20][p.maxTTL]string

	// Store original sequence numbers and what encoded sequence number they
	// were replaced with.
	// Value is the original sequence number, index is the encoded sequence number.
	var originalSeq [20]uint32

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
			wg.Done()
			return
		case sent := <-sentChan:
			n := sent.probeNum % 20
			t := sent.ttl
			// Store total probes sent and then probe timestamp and
			// original-to-encoded sequence numbers for the last 20 probes.
			if totalProbesSent < sent.probeNum {
				totalProbesSent = sent.probeNum
			}
			ps[n][t].sentTime = sent.timestamp
			ps[n][t].origSeq = sent.probeNum
			// TODO: removeme
			// sentTimes[sent.probeNum%20][sent.ttl] = sent.timestamp
			// TODO: removeme
			// originalSeq[uint8(sent.probeNum%20)] = uint32(sent.probeNum)
		case recv := <-recvChan:
			n := recv.probeNum
			t := recv.ttl
			// Store received probe timestamp.
			// TODO: removeme
			// recvTimes[recv.probeNum][recv.ttl] = recv.timestamp
			ttl := recv.timestamp.Sub(ps[n][t].sentTime)
			// TODO: Skip parsing if we're past timeout?
			ps[n][t].ttl = ttl

			// Store last seen IP for each hop/TTL.
			lastHops[t] = string(recv.ip)

			if entry, ok := ips[string(recv.ip)]; ok {
				// Update the IP stats.
				if ttl < entry.min {
					entry.min = ttl
				}
				if ttl > entry.max {
					entry.max = ttl
				}
				entry.avg = ((entry.avg * entry.received) + ttl) / (entry.received + 1)
				entry.received++
				ips[string(recv.ip)] = entry
			} else {
				// Add a new entry to the IP stats.
				ips[string(recv.ip)] = ipStat{ttl, ttl, ttl, "", 1, 0}
				// Start a goroutine to lookup the PTR record for the IP.
				go func(ip string, ptrLookupChan chan []string) {
					ptr, err := net.LookupAddr(ip)
					if err != nil || len(ptr) == 0 {
						ptrLookupChan <- []string{ip, ip}
					} else {
						ptrLookupChan <- []string{string(recv.ip), ptr[0]}
					}
				}(string(recv.ip), ptrLookupChan)
			}


			/*
			
			// Add the received probe to the lossStats map.
			if entry, ok := lossStats[string(recv.ip)]; ok {
				entry.received++
				lossStats[string(recv.ip)] = entry
			} else {
				lossStats[string(recv.ip)] = lossStat{0, 1}
			}

			recvFlags[recv.probeNum][recv.ttl] = recv.flag

			// Update the ptrs map with either the first PTR record or the IP
			// address if no PTR record was found.
			if _, ok := ptrs[string(recv.ip)]; !ok {
				go func(ip string, ptrLookupChan chan []string) {
					ptr, err := net.LookupAddr(ip)
					if err != nil || len(ptr) == 0 {
						ptrLookupChan <- []string{ip, ip}
					} else {
						ptrLookupChan <- []string{string(recv.ip), ptr[0]}
					}
				}(string(recv.ip), ptrLookupChan)
			}

			if entry, ok := ttlStats[string(recv.ip)]; ok {
				// TODO: update ttlStats.
				// Calculate avg. RTT based on current time, existing avg. RTT
				// and number of received probes.
				// entry.avg = time.Duration(int64(entry.avg) + (recv.timestamp.Sub(entry.avg) / time.Duration(entry.received)))
				ttlStats[string(recv.ip)] = entry
			}
			*/
		// Add returning PTR lookup results to the ptrs map.
		case ptr := <-ptrLookupChan:
			ptrs[ptr[0]] = ptr[1]
		// Check if any probes are ready to be printed and print them.
		default:
			for n, prs := range ps {
				for t := p.maxTTL-1; t >= 0; t-- {





			for n, p := range recvFlags {
			probeCheck:
			for t := len(p)-1 ; t >= 0; t-- {
				for ttl, flag := range p {
					// We've received a response for this probe.
					if len(flag) > 0 && flag != "TTL" {
						// Check if we've either received a response for all
						// intermediate TTLs of if they have reached the
						// timeout.
						for t := ttl; t >= 0; t-- {
							if len(ps[n][t]) == 0 {
								// Return if we've not yet reached our timeout.
								if time.Since(sentTimes[n][t]) < p.timeout {
									return probeCheck
								}
								// Update lost stats if we don't have a response.
								if len(ps[n][t].ip) == 0 {
									if len(lastHops[t]) > 0 {
										l := lastHops[t]
										ps[n][t].ip = l
										ips[l].lost++
									}
								}
							}
						}
						// TODO: Update lost count in ipStat.
						var output outputMsgs
						for t, flag := range p {
							append(output, outputMsg{
								probeNum: 	 ps[n][t].origSeq,
								ttl: 	   ps[n][t].ttl,
								ip: 	   ps[n][t].ip,
								)

							/*
								// Message type for communication between sendStats() and outputStats().
								type outputMsg struct {
									probeNum       uint
									ttl            uint8
									ip             net.IP
									host           string
									sentTime       time.Time
									rtt            time.Duration
									delayVariation time.Duration
									avgRTT         time.Duration
									minRTT         time.Duration
									maxRTT         time.Duration
									loss           uint
									flag           string
								}
								type outputMsgs []outputMsg
							*/

						}

						// TODO: This is where we calculate stats and print the
						// output.
					}
					log.Debug(flag)
				}
			}
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
	outputChan := make(chan outputMsgs)

	// Channel for sending PTR lookup results.
	ptrLookupChan := make(chan []string)

	responseReceivedChan := make(chan uint)

	// Channel for sending stop signal to goroutines.
	stop := make(chan struct{})
	defer close(stop)

	var wg sync.WaitGroup

	go p.output(outputChan, stop, &wg)
	go p.stats(sentChan, recvChan, outputChan, ptrLookupChan, stop, &wg)
	go p.recvProbes(handle, recvChan, responseReceivedChan, stop, &wg)
	go p.sendProbes(handle, sentChan, responseReceivedChan, stop, &wg)

	// TODO: replace with waitgroup.
	time.Sleep(10 * time.Second)

}

func (p *probe) output(outputChan chan outputMsgs, stop chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	select {
	case <-stop:
		wg.Done()
		return
	case output := <-outputChan:
		for _, msg := range output {
			fmt.Printf("%2v. %-15v %3v - %v (%v)\n", msg.ttl, msg.ip, msg.loss, msg.probeNum, msg.flag)
		}
	}
	// fmt.Printf("%3v. %-15v %3v - %v (%v)\n", ttl, ip, timestamp.Sub(start), probeNum, flag)
}

func (p *probe) sendProbes(handle *pcap.Handle, sentChan chan sentMsg, responseReceivedChan chan uint, stop chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)

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

	var lastProbeStart time.Time
	var lastTTLTime time.Time

	for n := uint(0); n < p.numProbes; n++ {
		// Probe number is 0-indexed, so we add 1 before logging
		log.Debugf("Sending probe %d", n+1)

		lastProbeStart = time.Now()

		log.Info("Sending probe")

	TTLLoop:
		for t := uint8(1); t <= p.maxTTL; t++ {
			lastTTLTime = time.Now()

			select {
			// Stop sending TTL increments if we've received a response for this
			// probe.
			case response := <-responseReceivedChan:
				if response == n {
					break TTLLoop
				}
			default:
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
	}
	// TODO: Wait for our final probe to have finished.
	wg.Done()
}
