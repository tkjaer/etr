package etr

import (
	"net/netip"
	"runtime"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/tkjaer/etr/pkg/route"
)

func TestBuildBPFFilter_TCPIPv4(t *testing.T) {
	if runtime.GOOS == "openbsd" {
		t.Skip("OpenBSD uses a port list instead of portrange")
	}
	cfg := Config{SrcPort: 50000, DstPort: 443, ParallelProbes: 3}
	tgt := target{
		route: route.Route{
			Source:      netip.MustParseAddr("192.0.2.1"),
			Destination: netip.MustParseAddr("198.51.100.1"),
		},
		inet:      layers.IPProtocolIPv4,
		transport: layers.IPProtocolTCP,
	}

	got, err := buildBPFFilter(cfg, tgt, false)
	if err != nil {
		t.Fatalf("buildBPFFilter() error = %v", err)
	}
	want := "(tcp and src host 198.51.100.1 and dst host 192.0.2.1 and src port 443 and dst portrange 50000-50002) or " +
		"(dst host 192.0.2.1 and icmp and icmp[0] == 11 and icmp[1] == 0) or " +
		"(dst host 192.0.2.1 and icmp and icmp[0] == 3 and icmp[1] == 3)"
	if got != want {
		t.Errorf("buildBPFFilter() =\n%s\nwant\n%s", got, want)
	}
}

func TestBuildBPFFilter_UDPIPv6IncludeProbes(t *testing.T) {
	if runtime.GOOS == "openbsd" {
		t.Skip("OpenBSD uses a port list instead of portrange")
	}
	cfg := Config{SrcPort: 40000, DstPort: 33434, ParallelProbes: 2}
	tgt := target{
		route: route.Route{
			Source:      netip.MustParseAddr("2001:db8::1"),
			Destination: netip.MustParseAddr("2001:db8::2"),
		},
		inet:      layers.IPProtocolIPv6,
		transport: layers.IPProtocolUDP,
	}

	got, err := buildBPFFilter(cfg, tgt, true)
	if err != nil {
		t.Fatalf("buildBPFFilter() error = %v", err)
	}
	want := "(udp and src host 2001:db8::2 and dst host 2001:db8::1 and src port 33434 and dst portrange 40000-40001) or " +
		"(dst host 2001:db8::1 and icmp6 and icmp6[0] == 3 and icmp6[1] == 0) or " +
		"(dst host 2001:db8::1 and icmp6 and icmp6[0] == 1 and icmp6[1] == 4) or " +
		"(udp and src host 2001:db8::1 and dst host 2001:db8::2 and src portrange 40000-40001 and dst port 33434)"
	if got != want {
		t.Errorf("buildBPFFilter() =\n%s\nwant\n%s", got, want)
	}
}

func TestBuildBPFFilter_DiscoveryMaxFlows(t *testing.T) {
	if runtime.GOOS == "openbsd" {
		t.Skip("OpenBSD uses a port list instead of portrange")
	}
	cfg := Config{SrcPort: 50000, DstPort: 443, ParallelProbes: 2, Discovery: &DiscoveryConfig{MaxFlows: 20}}
	tgt := target{
		route: route.Route{
			Source:      netip.MustParseAddr("192.0.2.1"),
			Destination: netip.MustParseAddr("198.51.100.1"),
		},
		inet:      layers.IPProtocolIPv4,
		transport: layers.IPProtocolTCP,
	}

	got, err := buildBPFFilter(cfg, tgt, false)
	if err != nil {
		t.Fatalf("buildBPFFilter() error = %v", err)
	}
	want := "(tcp and src host 198.51.100.1 and dst host 192.0.2.1 and src port 443 and dst portrange 50000-50021) or " +
		"(dst host 192.0.2.1 and icmp and icmp[0] == 11 and icmp[1] == 0) or " +
		"(dst host 192.0.2.1 and icmp and icmp[0] == 3 and icmp[1] == 3)"
	if got != want {
		t.Errorf("buildBPFFilter() =\n%s\nwant\n%s", got, want)
	}
}

func TestBuildBPFFilter_DiscoveryUnlimitedCapsAt65535(t *testing.T) {
	if runtime.GOOS == "openbsd" {
		t.Skip("OpenBSD uses a port list instead of portrange")
	}
	cfg := Config{SrcPort: 65530, DstPort: 443, ParallelProbes: 2, Discovery: &DiscoveryConfig{}}
	tgt := target{
		route: route.Route{
			Source:      netip.MustParseAddr("192.0.2.1"),
			Destination: netip.MustParseAddr("198.51.100.1"),
		},
		inet:      layers.IPProtocolIPv4,
		transport: layers.IPProtocolTCP,
	}

	got, err := buildBPFFilter(cfg, tgt, false)
	if err != nil {
		t.Fatalf("buildBPFFilter() error = %v", err)
	}
	want := "(tcp and src host 198.51.100.1 and dst host 192.0.2.1 and src port 443 and dst portrange 65530-65535) or " +
		"(dst host 192.0.2.1 and icmp and icmp[0] == 11 and icmp[1] == 0) or " +
		"(dst host 192.0.2.1 and icmp and icmp[0] == 3 and icmp[1] == 3)"
	if got != want {
		t.Errorf("buildBPFFilter() =\n%s\nwant\n%s", got, want)
	}
}
