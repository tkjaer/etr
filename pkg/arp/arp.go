//go:build linux || darwin

// This should work on freebsd, netbsd and openbsd as well (but not tested).

package arp

import (
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// Get retrieves the MAC address for a given IP address.
// It first checks the kernel ARP table and if not found, sends an ARP request.
func Get(ip net.IP, iface *net.Interface, src net.IP) (net.HardwareAddr, error) {
	// Check if the IP is in the kernel ARP table
	mac, err := CheckARPTable(ip, iface)

	// If the IP is not in the ARP table, send an ARP request and wait for a response
	if err != nil {
		handle, err := pcap.OpenLive(iface.Name, 65536, false, pcap.BlockForever)
		if err != nil {
			return nil, err
		}
		defer handle.Close()

		stop := make(chan struct{})
		arpChan := make(chan net.HardwareAddr)

		// Listen for ARP response in a goroutine
		go func() {
			if err := RecvARPRequest(handle, arpChan, ip, stop); err != nil {
				slog.Error("ARP receiver error", "error", err)
			}
		}()

		// Wait for a short time to allow the receiver to start
		time.Sleep(1 * time.Millisecond)

		// Send ARP request in a separate goroutine
		go func(handle *pcap.Handle, srcMAC net.HardwareAddr, src, dstIP net.IP, stop chan struct{}) {
			select {
			case <-stop:
				return
			default:
				if err := SendARPRequest(handle, srcMAC, src, dstIP); err != nil {
					slog.Error("ARP send error", "error", err)
				}
				// Use a short 0.1s retry interval
				time.Sleep(100 * time.Millisecond)
			}
		}(handle, iface.HardwareAddr, src, ip, stop)

		// Wait for the ARP response or timeout
		for {
			select {
			case mac = <-arpChan:
				// Stop the receiver goroutine and return the MAC address
				close(stop)
				return mac, nil
			case <-time.After(2 * time.Second):
				return nil, fmt.Errorf("timeout waiting for ARP response for %s", ip)
			}
		}
	}

	return mac, nil
}

// CheckARPTable checks if IP is in the kernel ARP table for the provided interface
// and returns the corresponding MAC address if found.
// It supports Linux and Darwin (macOS) platforms.
func CheckARPTable(ip net.IP, iface *net.Interface) (net.HardwareAddr, error) {
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		return checkARPTable(ip, iface)
	}
	return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
}

// RecvARPRequest listens for ARP requests on the provided handle and sends the MAC address to the channel
// if the sender IP matches the provided ip
func RecvARPRequest(handle *pcap.Handle, arpChan chan net.HardwareAddr, ip net.IP, stop chan struct{}) error {
	if err := handle.SetBPFFilter("arp"); err != nil {
		return err
	}
	in := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	for {
		select {
		case packet := <-in:
			if mac, ok := IsARPReplyFor(packet, ip); ok {
				arpChan <- mac
				return nil
			}
		case <-stop:
			return nil
		}
	}
}

// SendARPRequest sends an ARP request to the network using the provided handle
func SendARPRequest(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP, dstIP net.IP) error {
	r, err := CreateARPRequest(srcMAC, srcIP, dstIP)
	if err != nil {
		return err
	}
	if err := handle.WritePacketData(r); err != nil {
		return err
	}
	return nil
}
