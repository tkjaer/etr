package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// transmitProbes sends probes to the destination using the specified pcap handle.
// It serializes the packets and writes them to the handle, while also managing
// the timing of the probes and handling responses.
// It sends sent messages to the sentChan channel and listens for responses on
// the responseReceivedChan channel. The stop channel is used to signal when
// the transmission should stop, and the wait group is used to synchronize
// the completion of the transmission goroutine.
func (p *probe) transmitProbes(handle *pcap.Handle, sentChan chan sentMsg, responseReceivedChan chan uint, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	eth := layers.Ethernet{
		SrcMAC:       p.route.Interface.HardwareAddr,
		DstMAC:       p.dstMAC,
		EthernetType: p.etherType,
	}

	// TODO: Maybe keep a single start time and use the offset from that for all probes?
	var lastProbeStart time.Time

	// FIXME: rewrite to `for n := range p.numProbes`
	for n := uint(0); n < p.numProbes; n++ {
		// FIXME
		// Probe number is 0-indexed, so we add 1 before logging
		log.Debugf("Sending probe %d", n)

		lastProbeStart = time.Now()

		t := uint8(0)

	TTLLoop:
		for t < p.maxTTL {

			select {
			// Stop sending TTL increments if we've received a response from the
			// final destination for this probe.
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
						SrcIP:    p.route.Source.AsSlice(),
						DstIP:    p.route.Destination.AsSlice(),
						Flags:    layers.IPv4DontFragment,
					}
					switch p.proto {
					case layers.IPProtocolTCP:
						tcp := layers.TCP{
							Seq:     encodeTTLAndProbe(t, n),
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
							Length:  uint16(8 + encodeTTLAndProbe(t, n)),
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
						SrcIP:      p.route.Source.AsSlice(),
						DstIP:      p.route.Destination.AsSlice(),
					}
					switch p.proto {
					case layers.IPProtocolTCP:
						tcp := layers.TCP{
							Seq:     encodeTTLAndProbe(t, n),
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
							Length:  uint16(8 + encodeTTLAndProbe(t, n)),
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
