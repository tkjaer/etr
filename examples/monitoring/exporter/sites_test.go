package main

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSitesLongestPrefixWins(t *testing.T) {
	s, err := ParseSites(strings.NewReader(`
# prefix        site   class
10.0.0.0/8      wan    internal
10.1.0.0/16     fra    internal   # more specific
192.0.2.100     www    public
2001:db8::/32   v6     internal
`))
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]Site{
		"10.1.2.3":         {"fra", "internal"},
		"10.9.9.9":         {"wan", "internal"},
		"192.0.2.100":      {"www", "public"},
		"2001:db8::1":      {"v6", "internal"},
		"198.51.100.7":     {"198.51.100.7", unknownClass},
		"::ffff:10.1.0.1":  {"fra", "internal"},
		"not-an-ip-at-all": {"not-an-ip-at-all", unknownClass},
	} {
		if got := s.Lookup(ip); got != want {
			t.Errorf("Lookup(%s) = %+v, want %+v", ip, got, want)
		}
	}
}

func TestSitesRejectsBadLines(t *testing.T) {
	for _, in := range []string{"10.0.0.0/8", "10.0.0.0/33 x", "10.0.0.1 a b c", "nope site"} {
		if _, err := ParseSites(strings.NewReader(in)); err == nil {
			t.Errorf("ParseSites(%q) succeeded, want an error", in)
		}
	}
}

// Transit metrics attribute each probe's end-to-end result to every hop on
// its path, per source site, so a hop shared by failing targets stands out.
func TestFleetMetrics(t *testing.T) {
	s := newTestStore(t)
	sites, _ := ParseSites(strings.NewReader("10.0.0.0/24 fra internal\n192.0.2.0/24 ams internal\n"))
	s.SetSites(sites)
	const other = "192.0.2.200"
	for sec := range 10 {
		s.Process(run(50000, sec, "10.0.0.1", "198.51.100.1", dst))
		pr := run(50001, sec, "10.0.0.1", "198.51.100.1", "")
		pr.DestinationIP = other
		s.Process(pr)
	}
	tl := []string{src, "fra", dst, "ams", "internal"}
	if got := testutil.ToFloat64(s.m.targetProbes.WithLabelValues(tl...)); got != 10 {
		t.Errorf("target probes = %v, want 10", got)
	}
	if got := testutil.ToFloat64(s.m.targetReached.WithLabelValues(tl...)); got != 10 {
		t.Errorf("target reached = %v, want 10", got)
	}
	if got := testutil.ToFloat64(s.m.targetPaths.WithLabelValues(tl...)); got != 1 {
		t.Errorf("target paths = %v, want 1", got)
	}
	// Both targets cross 198.51.100.1; only one of them gets through.
	if got := testutil.ToFloat64(s.m.transitProbes.WithLabelValues("fra", "198.51.100.1")); got != 20 {
		t.Errorf("transit probes = %v, want 20", got)
	}
	if got := testutil.ToFloat64(s.m.transitReached.WithLabelValues("fra", "198.51.100.1")); got != 10 {
		t.Errorf("transit reached = %v, want 10", got)
	}
	if n := testutil.CollectAndCount(s.m.transitProbes); n != 2 {
		t.Errorf("transit series = %d, want 2 (the destination itself is not a transit hop)", n)
	}

	s.now = func() time.Time { return t0.Add(20 * time.Second) }
	s.Expire()
	if got := testutil.ToFloat64(s.m.transitTargets.WithLabelValues("fra", "198.51.100.1")); got != 2 {
		t.Errorf("transit targets = %v, want 2", got)
	}
	s.now = func() time.Time { return t0.Add(time.Hour) }
	s.Expire()
	if n := testutil.CollectAndCount(s.m.transitTargets); n != 0 {
		t.Errorf("transit target gauges after the flows stopped = %d, want 0", n)
	}
}

func TestFleetDemo(t *testing.T) {
	s := newTestStore(t)
	sites, err := LoadSites("../sites.txt")
	if err != nil {
		t.Fatal(err)
	}
	s.SetSites(sites)
	targets := fleetTargets(4)
	for i, p := range fleetPhases {
		for _, tg := range targets {
			for port := uint16(50000); port < 50000+uint16(tg.flows); port++ {
				if pr := demoRun(tg, 0, uint(i), port, p, t0.Add(time.Duration(i)*time.Second)); !s.Process(pr) {
					t.Fatalf("demo run rejected: %+v", pr)
				}
			}
		}
	}
	if len(s.targets) != 6*5+6*2 {
		t.Fatalf("fleet demo produced %d targets, want 42", len(s.targets))
	}
	fraNYC := s.targets[Target{"10.1.0.10", "10.4.0.10"}]
	if want := []string{"10.1.0.10", "fra", "10.4.0.10", "nyc", "wan"}; !slices.Equal(fraNYC.labels, want) {
		t.Errorf("fra→nyc labels = %v, want %v", fraNYC.labels, want)
	}
	if len(fraNYC.paths) < 2 {
		t.Errorf("fra→nyc has %d paths, want both transatlantic links", len(fraNYC.paths))
	}
	if got := s.targets[Target{"10.5.0.10", "198.18.1.80"}].labels[3:]; !slices.Equal(got, []string{"saas-api", "public"}) {
		t.Errorf("sin→saas-api labels = %v", got)
	}
	// Every EU site's traffic to nyc crosses one of the transatlantic links.
	for _, site := range []string{"fra", "ams", "lon"} {
		if got := testutil.ToFloat64(s.m.transitProbes.WithLabelValues(site, "172.17.2.1")); got == 0 {
			t.Errorf("no %s probes crossed tat2", site)
		}
	}
}
