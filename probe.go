package main

import (
	"net"
	"net/netip"
	"os"
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
	interProbeDelay uint
	numProbes       uint // TODO: change to uint32
	maxTTL          uint8
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
	p.maxTTL = uint8(Args.maxTTL)
}

// Encode the probe number and TTL into a single value.
//
// To keep the sequence number small enough to fit into the UDP frame
// length, TTL is multiplied by 20 and the probe number added.
//
// This leaves room for 20 probes (0-19) and a max TTL of 60 while
// keeping the UDP payload length well under 1500 bytes.
//
// TTL + probe + UDP header = 60*20 + 19 + 8 == 1227
func encodeSeq(ttl uint8, probeNum uint) (seq uint32) {
	return uint32(ttl)*20 + uint32(probeNum)
}

// Decode the sequence and return TTL and probe number.
func decodeSeq(seq uint32) (ttl uint8, probeNum uint) {
	return uint8(seq / 20), uint(seq % 20)
}

func (p *probe) run() {
	log.Info("Starting probe")

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

	handle, err := pcap.OpenLive(p.srcIface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	for i := uint(0); i < p.numProbes; i++ {
		// Probe number is 0-indexed, so we add 1 before logging
		log.Debugf("Sending probe %d", i+1)
		for j := uint8(1); j <= p.maxTTL; j++ {
			log.Debugf("TTL: %d", j)

			switch p.inet {
			case layers.IPProtocolIPv4:
				ip := layers.IPv4{
					Version:  4,
					TTL:      j,
					Protocol: p.proto,
					SrcIP:    p.srcIP.AsSlice(),
					DstIP:    p.dstIP.AsSlice(),
					Flags:    layers.IPv4DontFragment,
				}
				switch p.proto {
				case layers.IPProtocolTCP:
					tcp := layers.TCP{
						Seq:     encodeSeq(j, i),
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
						Length:  uint16(8 + encodeSeq(j, i)),
					}
					udp.SetNetworkLayerForChecksum(&ip)
					gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp)
					handle.WritePacketData(buf.Bytes())
				}
			case layers.IPProtocolIPv6:
				ip := layers.IPv6{
					Version:    6,
					HopLimit:   j,
					NextHeader: p.proto,
					SrcIP:      p.srcIP.AsSlice(),
					DstIP:      p.dstIP.AsSlice(),
				}
				switch p.proto {
				case layers.IPProtocolTCP:
					tcp := layers.TCP{
						Seq:     encodeSeq(j, i),
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
						Length:  uint16(8 + encodeSeq(j, i)),
					}
					udp.SetNetworkLayerForChecksum(&ip)
					gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp)
					handle.WritePacketData(buf.Bytes())
				}
			}
		}
		// TODO: should this be a timer "since last probe run was started" instead?
		time.Sleep(time.Duration(p.interProbeDelay) * time.Second)
	}
	// TODO: Remove this once we have timing properly implemented
	// and possibly a return channel that tells us when the final
	// SYNACK has been received.
	time.Sleep(time.Duration(p.interProbeDelay) * time.Second)
}
