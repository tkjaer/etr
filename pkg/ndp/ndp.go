package ndp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"time"

	"github.com/mdlayher/ndp"
)

// PerformNeighborDiscovery performs an active IPv6 Neighbor Discovery
// for the given target IP on the specified interface.
// Returns the MAC address if found, or an error if not found or on failure.
func PerformNeighborDiscovery(targetIP net.IP, iface *net.Interface, timeout time.Duration) (net.HardwareAddr, error) {
	// Convert to netip.Addr for ndp package
	addr, ok := netip.AddrFromSlice(targetIP)
	if !ok {
		return nil, errors.New("invalid IP address")
	}

	// Only works for IPv6
	if !addr.Is6() {
		return nil, errors.New("NDP only works for IPv6 addresses")
	}

	// Create NDP connection on the interface
	conn, _, err := ndp.Listen(iface, ndp.LinkLocal)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			slog.Error("Failed to close NDP connection", "error", err)
		}
	}()

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Send Neighbor Solicitation
	msg := &ndp.NeighborSolicitation{
		TargetAddress: addr,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Source,
				Addr:      iface.HardwareAddr,
			},
		},
	}

	// Determine destination (solicited-node multicast address)
	dst, err := ndp.SolicitedNodeMulticast(addr)
	if err != nil {
		return nil, err
	}

	if err := conn.WriteTo(msg, nil, dst); err != nil {
		return nil, err
	}

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		slog.Error("Failed to set read deadline", "error", err)
	}

	// Wait for Neighbor Advertisement response
	for {
		select {
		case <-ctx.Done():
			return nil, errors.New("neighbor discovery timeout")
		default:
			msg, _, _, err := conn.ReadFrom()
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					return nil, errors.New("neighbor discovery timeout")
				}
				return nil, err
			}

			// Check if it's a Neighbor Advertisement for our target
			if na, ok := msg.(*ndp.NeighborAdvertisement); ok {
				if na.TargetAddress == addr {
					// Extract MAC address from target link-layer address option
					for _, opt := range na.Options {
						if lla, ok := opt.(*ndp.LinkLayerAddress); ok {
							if lla.Direction == ndp.Target {
								return lla.Addr, nil
							}
						}
					}
				}
			}
		}
	}
}

func CheckNeighbourTable(ip net.IP, iface *net.Interface) (net.HardwareAddr, error) {
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		return checkNeighbourTable(ip, iface)
	}
	return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
}

// Get checks both the kernel neighbor cache and performs active discovery if
// not found in cache (IPv6 only).
func Get(ip net.IP, iface *net.Interface) (net.HardwareAddr, error) {
	// Check that IP is IPv6
	if ip.To4() != nil {
		return nil, errors.New("only IPv6 addresses are supported")
	}

	// First, try to get from kernel neighbor table
	mac, err := CheckNeighbourTable(ip, iface)
	if err == nil {
		return mac, nil
	}

	// If not in cache and it's IPv6, try active NDP
	mac, err = PerformNeighborDiscovery(ip, iface, 1*time.Second)
	if err == nil {
		return mac, nil
	}

	return nil, errors.New("neighbor not found in cache or via discovery")
}
