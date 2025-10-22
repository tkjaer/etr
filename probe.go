package main

import (
	"encoding/binary"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tkjaer/etr/pkg/route"
)

// ProbeConfig holds configuration common to all probes
type ProbeConfig struct {
	destination     string
	numProbes       uint
	protocolConfig  ProtocolConfig
	route           route.Route
	srcPort         uint16
	dstPort         uint16
	dstMAC          net.HardwareAddr
	maxTTL          uint8
	interProbeDelay time.Duration
	interTTLDelay   time.Duration
	timeout         time.Duration
}

type TransmitEvent struct {
	Buffer  gopacket.SerializeBuffer
	ProbeID uint16
	TTL     uint8
}

// calculateMSS calculates the Maximum Segment Size based on interface MTU and IP version
func calculateMSS(iface *net.Interface, isIPv6 bool) uint16 {
	mtu := iface.MTU
	if mtu <= 0 {
		// Default to Ethernet MTU if not available
		mtu = 1500
	}

	// MSS = MTU - IP header - TCP header
	// IPv4 header: 20 bytes (without options)
	// IPv6 header: 40 bytes
	// TCP header: 20 bytes (without options)
	var mss int
	if isIPv6 {
		mss = mtu - 40 - 20
	} else {
		mss = mtu - 20 - 20
	}

	// Ensure MSS is reasonable
	if mss < 536 {
		mss = 536 // Minimum MSS per RFC 879
	}
	if mss > 65495 {
		mss = 65495 // Maximum possible
	}

	return uint16(mss)
}

// createTCPOptions creates realistic TCP options based on interface settings
func createTCPOptions(iface *net.Interface, isIPv6 bool) []layers.TCPOption {
	mss := calculateMSS(iface, isIPv6)
	mssBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(mssBytes, mss)

	return []layers.TCPOption{
		// MSS option (calculated from interface MTU)
		{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   mssBytes,
		},
		// NOP for alignment
		{
			OptionType:   layers.TCPOptionKindNop,
			OptionLength: 1,
		},
		// Window Scale
		{
			OptionType:   layers.TCPOptionKindWindowScale,
			OptionLength: 3,
			OptionData:   []byte{0x07}, // Scale factor 7
		},
		// NOP for alignment
		{
			OptionType:   layers.TCPOptionKindNop,
			OptionLength: 1,
		},
		// NOP for alignment
		{
			OptionType:   layers.TCPOptionKindNop,
			OptionLength: 1,
		},
		// Timestamp
		{
			OptionType:   layers.TCPOptionKindTimestamps,
			OptionLength: 10,
			OptionData:   generateTimestampOption(),
		},
		// SACK Permitted
		{
			OptionType:   layers.TCPOptionKindSACKPermitted,
			OptionLength: 2,
		},
		// End of options
		{
			OptionType:   layers.TCPOptionKindEndList,
			OptionLength: 1,
		},
	}
}

// generateTimestampOption creates timestamp option data
func generateTimestampOption() []byte {
	timestamp := uint32(time.Now().Unix())
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], timestamp)
	// Echo reply timestamp (0 for SYN)
	binary.BigEndian.PutUint32(data[4:8], 0)
	return data
}

// newProbe holds configuration for a single probe instance
type Probe struct {
	probeID      uint16
	config       *ProbeConfig
	transmitChan chan TransmitEvent
	responseChan chan uint
	stop         chan struct{}
	wg           *sync.WaitGroup
}

func (p *Probe) Run() {
	probeConfig := p.config
	protocolConfig := probeConfig.protocolConfig

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	eth := layers.Ethernet{
		SrcMAC:       probeConfig.route.Interface.HardwareAddr,
		DstMAC:       probeConfig.dstMAC,
		EthernetType: protocolConfig.etherType,
	}

	var lastProbeStart time.Time

	for n := range p.config.numProbes {
		select {
		case <-p.stop:
			slog.Debug("Probe received stop signal", "probe_id", p.probeID)
			return
		default:
		}

		slog.Debug("Starting probe", "probe_num", n)
		lastProbeStart = time.Now()
		ttl := uint8(0)

	TTLLoop:
		for ttl < p.config.maxTTL {
			select {
			case <-p.stop:
				slog.Debug("Probe received stop signal during TTL loop", "probe_id", p.probeID)
				return
			case response := <-p.responseChan:
				// Stop sending TTL increments if we've received a response from the
				// final destination for this probe.
				if response == uint(n) {
					break TTLLoop
				} else {
					slog.Debug("Received response for wrong probe", "expected", n, "received", response)
				}
			default:
				ttl++
				switch protocolConfig.inet {
				case layers.IPProtocolIPv4:
					ip := layers.IPv4{
						Version:  4,
						TTL:      ttl,
						Protocol: protocolConfig.transport,
						SrcIP:    probeConfig.route.Source.AsSlice(),
						DstIP:    probeConfig.route.Destination.AsSlice(),
						Flags:    layers.IPv4DontFragment,
					}
					switch protocolConfig.transport {
					case layers.IPProtocolTCP:
						tcp := layers.TCP{
							Seq:     encodeTTLAndProbe(ttl, uint(n)),
							SrcPort: layers.TCPPort(probeConfig.srcPort + p.probeID),
							DstPort: layers.TCPPort(probeConfig.dstPort),
							SYN:     true,
							Window:  65535,
							Options: createTCPOptions(probeConfig.route.Interface, false),
						}
						tcp.SetNetworkLayerForChecksum(&ip)
						err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp)
						if err != nil {
							slog.Error("Failed to serialize layers", "error", err)
						}
						p.transmitChan <- TransmitEvent{
							Buffer:  buf,
							ProbeID: p.probeID,
							TTL:     ttl,
						}
					case layers.IPProtocolUDP:
						udp := layers.UDP{
							SrcPort: layers.UDPPort(probeConfig.srcPort + p.probeID),
							DstPort: layers.UDPPort(probeConfig.dstPort),
							Length:  uint16(8 + encodeTTLAndProbe(ttl, uint(n))),
						}
						udp.SetNetworkLayerForChecksum(&ip)
						err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp)
						if err != nil {
							slog.Error("Failed to serialize layers", "error", err)
						}
						p.transmitChan <- TransmitEvent{
							Buffer:  buf,
							ProbeID: p.probeID,
							TTL:     ttl,
						}
					}
				case layers.IPProtocolIPv6:
					ip := layers.IPv6{
						Version:    6,
						HopLimit:   ttl,
						NextHeader: protocolConfig.transport,
						SrcIP:      probeConfig.route.Source.AsSlice(),
						DstIP:      probeConfig.route.Destination.AsSlice(),
					}
					switch protocolConfig.transport {
					case layers.IPProtocolTCP:
						tcp := layers.TCP{
							Seq:     encodeTTLAndProbe(ttl, uint(n)),
							SrcPort: layers.TCPPort(probeConfig.srcPort + p.probeID),
							DstPort: layers.TCPPort(probeConfig.dstPort),
							SYN:     true,
							Window:  65535,
							Options: createTCPOptions(probeConfig.route.Interface, true),
						}
						tcp.SetNetworkLayerForChecksum(&ip)
						err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp)
						if err != nil {
							slog.Error("Failed to serialize layers", "error", err)
						}
						p.transmitChan <- TransmitEvent{
							Buffer:  buf,
							ProbeID: p.probeID,
							TTL:     ttl,
						}
					case layers.IPProtocolUDP:
						udp := layers.UDP{
							SrcPort: layers.UDPPort(probeConfig.srcPort + p.probeID),
							DstPort: layers.UDPPort(probeConfig.dstPort),
							Length:  uint16(8 + encodeTTLAndProbe(ttl, uint(n))),
						}
						udp.SetNetworkLayerForChecksum(&ip)
						err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp)
						if err != nil {
							slog.Error("Failed to serialize layers", "error", err)
						}
						p.transmitChan <- TransmitEvent{
							Buffer:  buf,
							ProbeID: p.probeID,
							TTL:     ttl,
						}
					}
				}
				// Wait inter-TTL delay before sending the next TTL increment
				delay := probeConfig.interTTLDelay * time.Duration(ttl)
				if time.Since(lastProbeStart) < delay {
					time.Sleep(delay - time.Since(lastProbeStart))
				}
			}
		}
		// Sleep for interProbeDelay if we haven't already spent that much time
		// sending the probe.
		if time.Since(lastProbeStart) < probeConfig.interProbeDelay {
			time.Sleep(probeConfig.interProbeDelay - time.Since(lastProbeStart))
		}
	}
	// Wait for any remaining responses before exiting
	time.Sleep(probeConfig.timeout)
	slog.Debug("Probe finished sending all probes", "probe_id", p.probeID)
}
