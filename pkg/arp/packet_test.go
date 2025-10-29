//go:build linux || darwin
// +build linux darwin

// Package arp tests for pure functions
//
// This file tests the pure, easily-testable functions in packet.go.
// These functions have zero external dependencies and can be tested without
// network privileges, pcap handles, or actual network interfaces.
//
// Tests in this file:
// - TestCreateARPRequest: Tests ARP request packet creation
// - TestIsARPReplyFor: Tests ARP reply packet matching
// - TestIsARPReplyFor_NonARPPacket: Edge case testing
// - BenchmarkCreateARPRequest: Performance measurement
// - BenchmarkIsARPReplyFor: Performance measurement
//
// These pure functions are used internally by the pcap-dependent functions
// tested in arp_test.go (SendARPRequest and RecvARPRequest).

package arp

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestCreateARPRequest(t *testing.T) {
	tests := []struct {
		name    string
		srcMAC  net.HardwareAddr
		srcIP   net.IP
		dstIP   net.IP
		wantErr bool
	}{
		{
			name:    "valid request",
			srcMAC:  net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			srcIP:   net.ParseIP("192.0.2.1").To4(),
			dstIP:   net.ParseIP("192.0.2.2").To4(),
			wantErr: false,
		},
		{
			name:    "broadcast destination",
			srcMAC:  net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			srcIP:   net.ParseIP("198.51.100.1").To4(),
			dstIP:   net.ParseIP("198.51.100.255").To4(),
			wantErr: false,
		},
		{
			name:    "gateway IP",
			srcMAC:  net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			srcIP:   net.ParseIP("203.0.113.10").To4(),
			dstIP:   net.ParseIP("203.0.113.1").To4(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packetData, err := CreateARPRequest(tt.srcMAC, tt.srcIP, tt.dstIP)

			if (err != nil) != tt.wantErr {
				t.Errorf("CreateARPRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			// Verify we got some data
			if len(packetData) == 0 {
				t.Error("CreateARPRequest() returned empty packet")
				return
			}

			// Parse the packet back
			packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)

			// Verify Ethernet layer
			ethLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethLayer == nil {
				t.Error("Packet missing Ethernet layer")
				return
			}
			eth := ethLayer.(*layers.Ethernet)

			if eth.EthernetType != layers.EthernetTypeARP {
				t.Errorf("Wrong EthernetType: got %v, want %v", eth.EthernetType, layers.EthernetTypeARP)
			}

			if eth.SrcMAC.String() != tt.srcMAC.String() {
				t.Errorf("Wrong source MAC: got %v, want %v", eth.SrcMAC, tt.srcMAC)
			}

			expectedDstMAC := "ff:ff:ff:ff:ff:ff"
			if eth.DstMAC.String() != expectedDstMAC {
				t.Errorf("Wrong dest MAC: got %v, want %v", eth.DstMAC, expectedDstMAC)
			}

			// Verify ARP layer
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				t.Error("Packet missing ARP layer")
				return
			}
			arp := arpLayer.(*layers.ARP)

			if arp.Operation != layers.ARPRequest {
				t.Errorf("Wrong operation: got %v, want %v", arp.Operation, layers.ARPRequest)
			}

			if !net.IP(arp.SourceProtAddress).Equal(tt.srcIP) {
				t.Errorf("Wrong source IP: got %v, want %v", net.IP(arp.SourceProtAddress), tt.srcIP)
			}

			if !net.IP(arp.DstProtAddress).Equal(tt.dstIP) {
				t.Errorf("Wrong dest IP: got %v, want %v", net.IP(arp.DstProtAddress), tt.dstIP)
			}

			if net.HardwareAddr(arp.SourceHwAddress).String() != tt.srcMAC.String() {
				t.Errorf("Wrong ARP source MAC: got %v, want %v",
					net.HardwareAddr(arp.SourceHwAddress), tt.srcMAC)
			}
		})
	}
}

func TestIsARPReplyFor(t *testing.T) {
	tests := []struct {
		name      string
		replyIP   net.IP
		replyMAC  net.HardwareAddr
		targetIP  net.IP
		operation uint16
		wantMAC   net.HardwareAddr
		wantMatch bool
	}{
		{
			name:      "matching reply",
			replyIP:   net.ParseIP("192.0.2.1").To4(),
			replyMAC:  net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			targetIP:  net.ParseIP("192.0.2.1").To4(),
			operation: layers.ARPReply,
			wantMAC:   net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			wantMatch: true,
		},
		{
			name:      "non-matching IP",
			replyIP:   net.ParseIP("192.0.2.2").To4(),
			replyMAC:  net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			targetIP:  net.ParseIP("192.0.2.1").To4(),
			operation: layers.ARPReply,
			wantMAC:   nil,
			wantMatch: false,
		},
		{
			name:      "ARP request instead of reply",
			replyIP:   net.ParseIP("192.0.2.1").To4(),
			replyMAC:  net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			targetIP:  net.ParseIP("192.0.2.1").To4(),
			operation: layers.ARPRequest,
			wantMAC:   nil,
			wantMatch: false,
		},
		{
			name:      "different subnet",
			replyIP:   net.ParseIP("198.51.100.1").To4(),
			replyMAC:  net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			targetIP:  net.ParseIP("192.0.2.1").To4(),
			operation: layers.ARPReply,
			wantMAC:   nil,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test ARP packet
			eth := layers.Ethernet{
				SrcMAC:       tt.replyMAC,
				DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				EthernetType: layers.EthernetTypeARP,
			}

			arp := layers.ARP{
				AddrType:          layers.LinkTypeEthernet,
				Protocol:          layers.EthernetTypeIPv4,
				HwAddressSize:     6,
				ProtAddressSize:   4,
				Operation:         tt.operation,
				SourceHwAddress:   []byte(tt.replyMAC),
				SourceProtAddress: []byte(tt.replyIP),
				DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
				DstProtAddress:    []byte{0, 0, 0, 0},
			}

			buffer := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{}
			err := gopacket.SerializeLayers(buffer, opts, &eth, &arp)
			if err != nil {
				t.Fatalf("Failed to create test packet: %v", err)
			}

			packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

			// Test the function
			gotMAC, gotMatch := IsARPReplyFor(packet, tt.targetIP)

			if gotMatch != tt.wantMatch {
				t.Errorf("IsARPReplyFor() match = %v, want %v", gotMatch, tt.wantMatch)
			}

			if tt.wantMatch {
				if gotMAC.String() != tt.wantMAC.String() {
					t.Errorf("IsARPReplyFor() MAC = %v, want %v", gotMAC, tt.wantMAC)
				}
			} else {
				if gotMAC != nil {
					t.Errorf("IsARPReplyFor() should return nil MAC for non-match, got %v", gotMAC)
				}
			}
		})
	}
}

func TestIsARPReplyFor_NonARPPacket(t *testing.T) {
	// Create a non-ARP packet (just Ethernet)
	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4, // Not ARP
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buffer, opts, &eth)
	if err != nil {
		t.Fatalf("Failed to create test packet: %v", err)
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	targetIP := net.ParseIP("192.0.2.1").To4()
	gotMAC, gotMatch := IsARPReplyFor(packet, targetIP)

	if gotMatch {
		t.Error("IsARPReplyFor() should not match non-ARP packet")
	}

	if gotMAC != nil {
		t.Errorf("IsARPReplyFor() should return nil MAC for non-ARP packet, got %v", gotMAC)
	}
}

func BenchmarkCreateARPRequest(b *testing.B) {
	srcMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	srcIP := net.ParseIP("192.0.2.1").To4()
	dstIP := net.ParseIP("192.0.2.2").To4()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CreateARPRequest(srcMAC, srcIP, dstIP)
	}
}

func BenchmarkIsARPReplyFor(b *testing.B) {
	// Create a test ARP reply packet
	replyMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	replyIP := net.ParseIP("192.0.2.1").To4()

	eth := layers.Ethernet{
		SrcMAC:       replyMAC,
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(replyMAC),
		SourceProtAddress: []byte(replyIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte{0, 0, 0, 0},
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	_ = gopacket.SerializeLayers(buffer, opts, &eth, &arp)

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	targetIP := net.ParseIP("192.0.2.1").To4()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = IsARPReplyFor(packet, targetIP)
	}
}
