//go:build linux || darwin || freebsd

package arp

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestCreateARPRequest(t *testing.T) {
	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	srcIP := net.ParseIP("192.0.2.1").To4()
	dstIP := net.ParseIP("192.0.2.2").To4()

	data, err := CreateARPRequest(srcMAC, srcIP, dstIP)
	if err != nil {
		t.Fatalf("CreateARPRequest() error = %v", err)
	}

	if len(data) == 0 {
		t.Fatal("CreateARPRequest() returned empty packet")
	}

	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	// Verify Ethernet layer
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		t.Fatal("Packet missing Ethernet layer")
	}
	eth := ethLayer.(*layers.Ethernet)

	if eth.EthernetType != layers.EthernetTypeARP {
		t.Errorf("EthernetType = %v, want ARP", eth.EthernetType)
	}
	if eth.SrcMAC.String() != srcMAC.String() {
		t.Errorf("SrcMAC = %v, want %v", eth.SrcMAC, srcMAC)
	}
	if eth.DstMAC.String() != "ff:ff:ff:ff:ff:ff" {
		t.Errorf("DstMAC = %v, want broadcast", eth.DstMAC)
	}

	// Verify ARP layer
	arpLayer := pkt.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		t.Fatal("Packet missing ARP layer")
	}
	arp := arpLayer.(*layers.ARP)

	if arp.Operation != layers.ARPRequest {
		t.Errorf("Operation = %v, want ARPRequest", arp.Operation)
	}
	if !net.IP(arp.SourceProtAddress).Equal(srcIP) {
		t.Errorf("SourceProtAddress = %v, want %v", net.IP(arp.SourceProtAddress), srcIP)
	}
	if !net.IP(arp.DstProtAddress).Equal(dstIP) {
		t.Errorf("DstProtAddress = %v, want %v", net.IP(arp.DstProtAddress), dstIP)
	}
}

func TestIsARPReplyFor(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
		mac  net.IP
		op   uint16
		want bool
	}{
		{"match", net.ParseIP("192.0.2.1").To4(), net.ParseIP("192.0.2.1").To4(), layers.ARPReply, true},
		{"wrong ip", net.ParseIP("192.0.2.2").To4(), net.ParseIP("192.0.2.1").To4(), layers.ARPReply, false},
		{"request not reply", net.ParseIP("192.0.2.1").To4(), net.ParseIP("192.0.2.1").To4(), layers.ARPRequest, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
			eth := layers.Ethernet{SrcMAC: mac, DstMAC: mac, EthernetType: layers.EthernetTypeARP}
			arp := layers.ARP{
				AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
				HwAddressSize: 6, ProtAddressSize: 4, Operation: tt.op,
				SourceHwAddress: []byte(mac), SourceProtAddress: []byte(tt.ip),
				DstHwAddress: []byte{0, 0, 0, 0, 0, 0}, DstProtAddress: []byte{0, 0, 0, 0},
			}

			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &eth, &arp); err != nil {
				t.Fatalf("Failed to create packet: %v", err)
			}

			pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
			gotMAC, gotMatch := IsARPReplyFor(pkt, tt.mac)

			if gotMatch != tt.want {
				t.Errorf("IsARPReplyFor() match = %v, want %v", gotMatch, tt.want)
			}
			if tt.want && (gotMAC == nil || gotMAC.String() != mac.String()) {
				t.Errorf("IsARPReplyFor() MAC = %v, want %v", gotMAC, mac)
			}
		})
	}
}

func TestIsARPReplyFor_NonARPPacket(t *testing.T) {
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, &eth); err != nil {
		t.Fatalf("Failed to create packet: %v", err)
	}

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	mac, match := IsARPReplyFor(pkt, net.ParseIP("192.0.2.1").To4())

	if match || mac != nil {
		t.Errorf("IsARPReplyFor() = (%v, %v), want (nil, false)", mac, match)
	}
}
