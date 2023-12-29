package main

import (
	"encoding/binary"
	"fmt"
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
	numProbes       uint
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
	switch p.proto {
	case layers.IPProtocolTCP:
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			ttl, probeNum, flag = decodeTCPLayer(tcpLayer.(*layers.TCP))
		} else if icmp4Layer := packet.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
			ttl, probeNum, _ = p.decodeICMPv4Layer(icmp4Layer.(*layers.ICMPv4))
			flag = "TTL"
		} else if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
			// TODO: implement decodeICMPv6Layer()
			fmt.Println("ICMPv6 decode not implemented yet")
		}
	case layers.IPProtocolUDP:
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			ttl, probeNum = decodeUDPLayer(udpLayer.(*layers.UDP))
		} else if icmp4Layer := packet.Layer(layers.LayerTypeICMPv4); icmp4Layer != nil {
			ttl, probeNum, _ = p.decodeICMPv4Layer(icmp4Layer.(*layers.ICMPv4))
			flag = "TTL"
		} else if icmp6Layer := packet.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
			// TODO: implement decodeICMPv6Layer()
			fmt.Println("ICMPv6 decode not implemented yet")
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

func (p *probe) recvProbe(handle *pcap.Handle, stop chan struct{}) {
	if err := handle.SetBPFFilter(p.pcapFilter()); err != nil {
		log.Fatal(err)
	}

	start := time.Now()

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	in := src.Packets()
	// TODO: add timeout
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			log.Debug("stopping recvProbe")
			return
		case packet = <-in:
			ttl, probeNum, timestamp, ip, flag := p.decodeRecvProbe(packet)
			fmt.Printf("%3v. %-15v %3v - %v (%v)\n", ttl, ip, timestamp.Sub(start), probeNum, flag)
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

	stop := make(chan struct{})
	go p.recvProbe(handle, stop)
	defer close(stop)

	// TODO: Ensure that interProbeDelay*20 > probe timeout to avoid
	// duplicate probes (0-19).
	var probeTimes [20][60]time.Time

	for i := uint(0); i < p.numProbes; i++ {
		// Probe number is 0-indexed, so we add 1 before logging
		log.Debugf("Sending probe %d", i+1)
		for j := uint8(1); j <= p.maxTTL; j++ {

			probeTimes[i][j-1] = time.Now()
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
