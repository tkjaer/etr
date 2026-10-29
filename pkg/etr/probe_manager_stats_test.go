package etr

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jellydator/ttlcache/v3"

	"github.com/tkjaer/etr/pkg/ptr"
	"github.com/tkjaer/etr/pkg/route"
)

func TestCopyProbeStatsIsIndependent(t *testing.T) {
	orig := &ProbeStats{
		ProbeID: 1,
		Hops: map[uint8]*HopStats{
			1: {
				IPs:       map[string]*HopIPStats{"10.0.0.1": {Responses: 1, PTR: "gw"}},
				CurrentIP: "10.0.0.1",
				Sent:      1,
			},
		},
	}

	c := copyProbeStats(orig)

	// Change everything the stats processor might change after the copy.
	orig.Hops[1].Sent = 2
	orig.Hops[1].CurrentIP = "10.0.0.2"
	orig.Hops[1].IPs["10.0.0.1"].Responses = 2
	orig.Hops[1].IPs["10.0.0.2"] = &HopIPStats{}
	orig.Hops[2] = &HopStats{}

	hop := c.Hops[1]
	if len(c.Hops) != 1 || hop.Sent != 1 || hop.CurrentIP != "10.0.0.1" {
		t.Errorf("hop copy changed: %d hops, %+v", len(c.Hops), hop)
	}
	if len(hop.IPs) != 1 || hop.IPs["10.0.0.1"].Responses != 1 || hop.IPs["10.0.0.1"].PTR != "gw" {
		t.Errorf("IP stats copy changed: %+v", hop.IPs)
	}
}

func TestCopyStatsKeepsNilMaps(t *testing.T) {
	if c := copyHopStats(&HopStats{}); c.IPs != nil {
		t.Errorf("copyHopStats: IPs = %v, want nil", c.IPs)
	}
	if c := copyProbeStats(&ProbeStats{}); c.Hops != nil {
		t.Errorf("copyProbeStats: Hops = %v, want nil", c.Hops)
	}
}

func TestGetProbeStatsReturnsCopies(t *testing.T) {
	pm := &probeManager{
		stats: probeManagerStats{
			Probes: map[uint16]*ProbeStats{
				1: {ProbeID: 1, Hops: map[uint8]*HopStats{
					3: {IPs: map[string]*HopIPStats{"10.0.0.1": {Responses: 1}}},
				}},
			},
		},
	}
	orig := pm.stats.Probes[1].Hops[3].IPs["10.0.0.1"]

	hop, ok := pm.getProbeHopStats(1, 3)
	if !ok || hop.IPs["10.0.0.1"] == orig {
		t.Errorf("getProbeHopStats shares IP stats with the stats processor (ok=%v)", ok)
	}
	probe, ok := pm.getProbeStats(1)
	if !ok || probe.Hops[3].IPs["10.0.0.1"] == orig {
		t.Errorf("getProbeStats shares IP stats with the stats processor (ok=%v)", ok)
	}
	if _, ok := pm.getProbeHopStats(1, 4); ok {
		t.Error("getProbeHopStats found a hop that doesn't exist")
	}
	if _, ok := pm.getProbeStats(2); ok {
		t.Error("getProbeStats found a probe that doesn't exist")
	}
}

// newReplyTestProbeManager returns a probe manager with just enough state to
// record sent and received stats for probes to dest.
func newReplyTestProbeManager(dest string) *probeManager {
	return &probeManager{
		outputChan:  make(chan outputMsg, 10),
		ptrManager:  ptr.NewPtrManager(),
		probeTarget: target{route: route.Route{Destination: netip.MustParseAddr(dest)}},
		stats: probeManagerStats{
			Probes:      make(map[uint16]*ProbeStats),
			CurrentRuns: make(map[uint16]*probeRunBuilder),
			TTLCache:    ttlcache.New[ttlCacheKey, ttlCacheValue](),
		},
	}
}

func TestReceivedStatsRecordReplyAndForwarding(t *testing.T) {
	// A destination that forwards port 80 to a container one hop behind it,
	// as in #127: TTL 6 expires on the destination, TTL 7 reaches the service.
	const dest = "192.0.2.50"
	pm := newReplyTestProbeManager(dest)
	sent := time.Now()
	replies := []struct {
		ttl  uint8
		ip   string
		flag string
	}{
		{5, "198.51.100.1", "TTL"},
		{6, dest, "TTL"},
		{7, dest, "SYN-ACK"},
	}
	for _, r := range replies {
		pm.updateSentStats(0, &probeEventDataSent{ProbeNum: 0, TTL: r.ttl, Timestamp: sent})
		pm.updateReceivedStats(0, &probeEventDataReceived{
			ProbeNum: 0, TTL: r.ttl, IP: r.ip, Flag: r.flag, Timestamp: sent.Add(time.Millisecond),
		})
	}

	want := map[uint8]struct {
		reply     Reply
		forwarded bool
	}{
		5: {ReplyTimeExceeded, false},
		6: {ReplyTimeExceeded, true},
		7: {ReplySYNACK, false},
	}
	for _, r := range replies {
		got := pm.stats.Probes[0].Hops[r.ttl].IPs[r.ip]
		if got.Reply != want[r.ttl].reply || got.Forwarded != want[r.ttl].forwarded {
			t.Errorf("TTL %d: reply = %q, forwarded = %v, want %q, %v",
				r.ttl, got.Reply, got.Forwarded, want[r.ttl].reply, want[r.ttl].forwarded)
		}
	}

	pm.outputProbeRun(0, &probeEventDataIterationComplete{ProbeNum: 0, Timestamp: sent})
	msg := <-pm.outputChan
	if msg.run == nil {
		t.Fatalf("output message = %+v, want a probe run", msg)
	}
	for _, hop := range msg.run.Hops {
		if hop.Reply != want[hop.TTL].reply || hop.Forwarded != want[hop.TTL].forwarded {
			t.Errorf("probe run TTL %d: reply = %q, forwarded = %v, want %q, %v",
				hop.TTL, hop.Reply, hop.Forwarded, want[hop.TTL].reply, want[hop.TTL].forwarded)
		}
	}

	// The JSON output only marks forwarded hops and leaves the reply out
	for _, hop := range msg.run.Hops {
		b, err := json.Marshal(hop)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `"reply"`) {
			t.Errorf("TTL %d JSON has a reply field: %s", hop.TTL, b)
		}
		if got := strings.Contains(string(b), `"forwarded":true`); got != want[hop.TTL].forwarded {
			t.Errorf("TTL %d JSON forwarded = %v, want %v: %s", hop.TTL, got, want[hop.TTL].forwarded, b)
		}
	}
}
