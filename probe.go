package main

import (
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
			log.Debugf("Probe %d received stop signal", p.probeID)
			return
		default:
		}
		
		log.Debugf("Starting probe %d", n)
		lastProbeStart = time.Now()
		ttl := uint8(0)

	TTLLoop:
		for ttl < p.config.maxTTL {
			select {
			case <-p.stop:
				log.Debugf("Probe %d received stop signal during TTL loop", p.probeID)
				return
			case response := <-p.responseChan:
				// Stop sending TTL increments if we've received a response from the
				// final destination for this probe.
				if response == uint(n) {
					break TTLLoop
				} else {
					log.Debugf("Received response for probe %d, but currently sending %d", response, n)
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
						}
						tcp.SetNetworkLayerForChecksum(&ip)
						err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp)
						if err != nil {
							log.Errorf("Failed to serialize layers: %v", err)
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
							log.Errorf("Failed to serialize layers: %v", err)
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
						}
						tcp.SetNetworkLayerForChecksum(&ip)
						err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp)
						if err != nil {
							log.Errorf("Failed to serialize layers: %v", err)
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
							log.Errorf("Failed to serialize layers: %v", err)
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
	log.Debugf("Probe %d finished sending all probes", p.probeID)
}
