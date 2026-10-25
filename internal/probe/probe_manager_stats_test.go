package probe

import (
	"testing"
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
	pm := &ProbeManager{
		stats: ProbeManagerStats{
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
