package probe

import (
	"encoding/binary"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/tkjaer/etr/pkg/iface"
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
	Buffer   gopacket.SerializeBuffer
	ProbeID  uint16
	ProbeNum uint
	TTL      uint8
}

type ResponseEvent struct {
	ProbeNum uint
	TTL      uint8
	Flag     string
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

// serializeLayers serializes network layers, optionally including Ethernet layer
func serializeLayers(buf gopacket.SerializeBuffer, opts gopacket.SerializeOptions, eth *layers.Ethernet, otherLayers ...gopacket.SerializableLayer) error {
	if eth != nil {
		// Ethernet interface - include Ethernet layer
		allLayers := append([]gopacket.SerializableLayer{eth}, otherLayers...)
		return gopacket.SerializeLayers(buf, opts, allLayers...)
	}
	// Non-Ethernet interface (e.g., VPN/tunnel) - just IP and above
	return gopacket.SerializeLayers(buf, opts, otherLayers...)
}

// newProbe holds configuration for a single probe instance
type Probe struct {
	probeID      uint16
	config       *ProbeConfig
	transmitChan chan TransmitEvent
	responseChan chan ResponseEvent
	statsChan    chan ProbeEvent
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

	// Check if this is an Ethernet interface
	isEthernet := iface.IsEthernetInterface(probeConfig.route.Interface)

	// Only create Ethernet layer for Ethernet interfaces
	var eth *layers.Ethernet
	if isEthernet {
		eth = &layers.Ethernet{
			SrcMAC:       probeConfig.route.Interface.HardwareAddr,
			DstMAC:       probeConfig.dstMAC,
			EthernetType: protocolConfig.etherType,
		}
	}

	var lastProbeStart time.Time
	maxTTL := probeConfig.maxTTL

	// Handle infinite probes (numProbes == 0)
	probeCount := p.config.numProbes
	if probeCount == 0 {
		probeCount = 1<<63 - 1 // effectively infinite
	}

	for n := range probeCount {
		select {
		case <-p.stop:
			slog.Debug("Probe received stop signal", "probe_id", p.probeID)
			return
		default:
		}

		// Drain any old responses from the channel before starting this probe
		draining := true
		for draining {
			select {
			case oldResponse := <-p.responseChan:
				slog.Debug("Drained old response before starting probe", "probe_num", n, "old_response", oldResponse)
			default:
				draining = false
			}
		}

		slog.Debug("Starting probe", "probe_num", n)
		lastProbeStart = time.Now()
		ttl := uint8(0)

	TTLLoop:
		for ttl < maxTTL {
			select {
			case <-p.stop:
				slog.Debug("Probe received stop signal during TTL loop", "probe_id", p.probeID)
				return
			case response := <-p.responseChan:
				if response.ProbeNum == n%20 {
					// Update maxTTL to original value if we got a TTL exceeded at current maxTTL
					// This allows continuing probing if the path has changed.
					if response.Flag == "TTL" && response.TTL == maxTTL {
						maxTTL = probeConfig.maxTTL
					}
					// Stop sending TTL increments if we've received a response from the
					// final destination for this probe.
					if response.Flag != "TTL" {
						// Update maxTTL to the TTL of the received response
						if response.TTL < maxTTL {
							maxTTL = response.TTL
						}
						break TTLLoop
					}
				} else {
					slog.Debug("Received response for wrong probe", "expected", n%20, "received", response)
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
						if err := tcp.SetNetworkLayerForChecksum(&ip); err != nil {
							slog.Error("Failed to set network layer for checksum", "error", err)
						}
						err := serializeLayers(buf, opts, eth, &ip, &tcp)
						if err != nil {
							slog.Error("Failed to serialize layers", "error", err)
						}
						p.transmitChan <- TransmitEvent{
							Buffer:   buf,
							ProbeID:  p.probeID,
							ProbeNum: uint(n % 20),
							TTL:      ttl,
						}
					case layers.IPProtocolUDP:
						length := uint16(8 + encodeTTLAndProbe(ttl, uint(n)))
						payload := gopacket.Payload(make([]byte, length-8))
						udp := layers.UDP{
							SrcPort: layers.UDPPort(probeConfig.srcPort + p.probeID),
							DstPort: layers.UDPPort(probeConfig.dstPort),
							Length:  uint16(length),
						}
						if err := udp.SetNetworkLayerForChecksum(&ip); err != nil {
							slog.Error("Failed to set network layer for checksum", "error", err)
						}
						err := serializeLayers(buf, opts, eth, &ip, &udp, &payload)
						if err != nil {
							slog.Error("Failed to serialize layers", "error", err)
						}
						p.transmitChan <- TransmitEvent{
							Buffer:   buf,
							ProbeID:  p.probeID,
							ProbeNum: uint(n % 20),
							TTL:      ttl,
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
						if err := tcp.SetNetworkLayerForChecksum(&ip); err != nil {
							slog.Error("Failed to set network layer for checksum", "error", err)
						}
						err := serializeLayers(buf, opts, eth, &ip, &tcp)
						if err != nil {
							slog.Error("Failed to serialize layers", "error", err)
						}
						p.transmitChan <- TransmitEvent{
							Buffer:   buf,
							ProbeID:  p.probeID,
							ProbeNum: uint(n % 20),
							TTL:      ttl,
						}
					case layers.IPProtocolUDP:
						length := uint16(8 + encodeTTLAndProbe(ttl, uint(n)))
						payload := gopacket.Payload(make([]byte, length-8))
						udp := layers.UDP{
							SrcPort: layers.UDPPort(probeConfig.srcPort + p.probeID),
							DstPort: layers.UDPPort(probeConfig.dstPort),
							Length:  uint16(length),
						}
						if err := udp.SetNetworkLayerForChecksum(&ip); err != nil {
							slog.Error("Failed to set network layer for checksum", "error", err)
						}
						err := serializeLayers(buf, opts, eth, &ip, &udp, &payload)
						if err != nil {
							slog.Error("Failed to serialize layers", "error", err)
						}
						p.transmitChan <- TransmitEvent{
							Buffer:   buf,
							ProbeID:  p.probeID,
							ProbeNum: uint(n % 20),
							TTL:      ttl,
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
		// If this is the first probe run, we'll sleep for timeout to allow responses to arrive
		if n == 0 {
			time.Sleep(probeConfig.timeout)
		} else {
			// Sleep for interProbeDelay if we haven't already spent that much time
			// sending the probe.
			if time.Since(lastProbeStart) < probeConfig.interProbeDelay {
				time.Sleep(probeConfig.interProbeDelay - time.Since(lastProbeStart))
			}
		}

		// Notify that this iteration is complete
		p.statsChan <- ProbeEvent{
			ProbeID:   p.probeID,
			EventType: "iteration_complete",
			Data: &ProbeEventDataIterationComplete{
				ProbeNum:  uint(n),
				Timestamp: time.Now(),
			},
		}
	}
	// Wait for any remaining responses before exiting
	time.Sleep(probeConfig.timeout)
	slog.Debug("Probe finished sending all probes", "probe_id", p.probeID)

	// Notify stats processor that this probe is complete
	p.statsChan <- ProbeEvent{
		ProbeID:   p.probeID,
		EventType: "complete",
		Data:      nil,
	}
}
