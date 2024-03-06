package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jsimonetti/rtnetlink/rtnl"
)

func RecvARPRequest(handle *pcap.Handle, ARPChan chan net.HardwareAddr, senderIP net.IP, stop chan struct{}) error {
	if err := handle.SetBPFFilter("arp"); err != nil {
		log.Fatal(err)
	}
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return nil
		case packet = <-in:
			// ttl, probeNum, timestamp, ip, flag := p.decodeRecvProbe(packet)
			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
				arp := arpLayer.(*layers.ARP)
				// Return the MAC address if sender IP address matches
				// if arp.Operation == layers.ARPReply && bytes.Equal(arp.SourceProtAddress, senderIP[12:]) {
				if arp.Operation == layers.ARPReply && bytes.Equal(arp.SourceProtAddress, senderIP) {
					ARPChan <- arp.SourceHwAddress
					return nil
				}
			}
		}
	}
}

// SendARPRequest sends an ARP request to the network using the provided handle
func SendARPRequest(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP, dstIP net.IP) error {

	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:        layers.LinkTypeEthernet,
		Protocol:        layers.EthernetTypeIPv4,
		HwAddressSize:   6,
		ProtAddressSize: 4,
		Operation:       layers.ARPRequest,
		SourceHwAddress: []byte(srcMAC),
		// SourceProtAddress: []byte(srcIP[12:]),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP),
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	if err := gopacket.SerializeLayers(buffer, opts, &eth, &arp); err != nil {
		return err
	}

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		return err
	}

	return nil
}

// Check if IP is in the kernel ARP table for the provided interface
func CheckARPTable(ip net.IP, ifc *net.Interface) (net.HardwareAddr, error) {
	conn, err := rtnl.Dial(nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	r, err := conn.Neighbours(ifc, 0)
	if err != nil {
		return nil, err
	}

	for _, n := range r {
		if n.IP.Equal(ip) {
			return n.HwAddr, nil
		}
	}
	return nil, errors.New("MAC not found")
}

func GetMACForIP(ip net.IP, ifc *net.Interface) (net.HardwareAddr, error) {

	// Check if we already have an ARP entry
	mac, err := CheckARPTable(ip, ifc)

	// If not, send an ARP request and listen for response
	if err != nil {
		// Get source IP address for the ARP request
		srcIP, err := GetInterfaceIP(ifc, ip)
		if err != nil {
			fmt.Println(err)
		}
		handle, err := pcap.OpenLive(ifc.Name, 65536, false, pcap.BlockForever)
		if err != nil {
			return nil, err
		}
		defer handle.Close()

		stop := make(chan struct{})
		ARPChan := make(chan net.HardwareAddr)

		// Listen for ARP response in a goroutine
		go RecvARPRequest(handle, ARPChan, ip, stop)

		// Short wait before start sending ARP requests
		time.Sleep(1 * time.Millisecond)

		// Send ARP requests in a goroutine
		go func(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP, dstIP net.IP, stop chan struct{}) {
			select {
			case <-stop:
				return
			default:
				SendARPRequest(handle, srcMAC, srcIP, dstIP)
				time.Sleep(100 * time.Millisecond)
			}
		}(handle, ifc.HardwareAddr, srcIP, ip, stop)

		for {
			select {
			case mac = <-ARPChan:
				close(stop)
				return mac, nil
			case <-time.After(1 * time.Second):
				return nil, fmt.Errorf("ARP request timeout")
			}
		}
	}

	return mac, nil
}
