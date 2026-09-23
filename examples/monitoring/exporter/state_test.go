package main

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s := NewStore(NewMetrics(prometheus.NewRegistry()), time.Hour, 2*time.Minute)
	s.now = func() time.Time { return t0.Add(time.Hour) }
	s.liveAfter = 24 * time.Hour
	return s
}

// run builds a probe run for src port `port` at second `sec`. Each hop is an
// IP, or "" for a timeout. The last hop is the destination.
func run(port uint16, sec int, hops ...string) *ProbeRun {
	pr := &ProbeRun{
		SourceIP:        "10.0.0.2",
		SourcePort:      port,
		DestinationIP:   "192.0.2.100",
		DestinationPort: 443,
		Protocol:        "TCP",
		Timestamp:       t0.Add(time.Duration(sec) * time.Second),
	}
	for i, ip := range hops {
		h := &HopRun{TTL: uint8(i + 1), IP: ip, RTT: int64(1000 * (i + 1)), Timeout: ip == ""}
		if ip == "" {
			h.RTT = 0
		}
		pr.Hops = append(pr.Hops, h)
	}
	pr.ReachedDest = len(hops) > 0 && hops[len(hops)-1] == pr.DestinationIP
	return pr
}

const dst = "192.0.2.100"

func flowLabelsFor(port string) []string { return []string{dst, "TCP", "443", port} }

func TestParallelFlowsOnDifferentPathsAreNotPathChanges(t *testing.T) {
	s := newTestStore(t)
	for sec := range 10 {
		s.Process(run(50000, sec, "10.0.0.1", "198.51.100.1", dst))
		s.Process(run(50001, sec, "10.0.0.1", "198.51.100.2", dst))
	}
	for _, p := range []string{"50000", "50001"} {
		if got := testutil.ToFloat64(s.m.pathChanges.WithLabelValues(flowLabelsFor(p)...)); got != 0 {
			t.Errorf("flow %s: path changes = %v, want 0", p, got)
		}
	}
	if len(s.events) != 0 {
		t.Errorf("events = %d, want 0", len(s.events))
	}
	if got := testutil.ToFloat64(s.m.distinctPaths.WithLabelValues(dst)); got != 2 {
		t.Errorf("active paths = %v, want 2", got)
	}
	if a, b := testutil.ToFloat64(s.m.pathIndex.WithLabelValues(flowLabelsFor("50000")...)),
		testutil.ToFloat64(s.m.pathIndex.WithLabelValues(flowLabelsFor("50001")...)); a == b {
		t.Errorf("both flows got path index %v", a)
	}
}

func TestTimeoutIsNotAPathChange(t *testing.T) {
	s := newTestStore(t)
	s.Process(run(50000, 0, "10.0.0.1", "198.51.100.1", dst))
	s.Process(run(50000, 1, "10.0.0.1", "", dst))
	s.Process(run(50000, 2, "10.0.0.1", "198.51.100.1", dst))
	if len(s.events) != 0 {
		t.Fatalf("got %d path change events for a lost reply", len(s.events))
	}
	// The timeout is attributed to the hop we know is there.
	hl := append(flowLabelsFor("50000"), "2", "198.51.100.1")
	if sent, recv := testutil.ToFloat64(s.m.hopSent.WithLabelValues(hl...)), testutil.ToFloat64(s.m.hopRecv.WithLabelValues(hl...)); sent != 3 || recv != 2 {
		t.Errorf("hop 2 sent/received = %v/%v, want 3/2", sent, recv)
	}
}

func TestPathChangeRecordsEvent(t *testing.T) {
	s := newTestStore(t)
	s.Process(run(50000, 0, "10.0.0.1", "198.51.100.1", "203.0.113.1", dst))
	s.Process(run(50000, 1, "10.0.0.1", "198.51.100.2", "203.0.113.1", dst))
	s.Process(run(50000, 2, "10.0.0.1", "198.51.100.2", "203.0.113.1", dst))
	s.Process(run(50000, 3, "10.0.0.1", "198.51.100.1", "203.0.113.1", dst))

	if got := testutil.ToFloat64(s.m.pathChanges.WithLabelValues(flowLabelsFor("50000")...)); got != 2 {
		t.Fatalf("path changes = %v, want 2", got)
	}
	e := s.events[0]
	if e.FromPath != 1 || e.ToPath != 2 || e.TTL != 2 || e.OldHop != "198.51.100.1" || e.NewHop != "198.51.100.2" {
		t.Errorf("unexpected first event %+v", e)
	}
	// Returning to a known path reuses its number.
	if e := s.events[1]; e.FromPath != 2 || e.ToPath != 1 {
		t.Errorf("unexpected second event %+v", e)
	}
	if got := testutil.ToFloat64(s.m.pathIndex.WithLabelValues(flowLabelsFor("50000")...)); got != 1 {
		t.Errorf("path index = %v, want 1", got)
	}
}

func TestShorterPathIsAPathChange(t *testing.T) {
	s := newTestStore(t)
	s.Process(run(50000, 0, "10.0.0.1", "198.51.100.1", "198.51.100.9", dst))
	s.Process(run(50000, 1, "10.0.0.1", "198.51.100.1", dst))
	if len(s.events) != 1 || s.events[0].TTL != 3 {
		t.Fatalf("events = %+v, want one change at TTL 3", s.events)
	}
	if got := testutil.ToFloat64(s.m.hopCount.WithLabelValues(flowLabelsFor("50000")...)); got != 3 {
		t.Errorf("hops = %v, want 3", got)
	}
}

func TestRerouteForgetsHopsCarriedIntoSilentTTLs(t *testing.T) {
	const detour, silent, edge = "198.51.100.41", "", "203.0.113.9"
	s := newTestStore(t)
	s.Process(run(50000, 0, "10.0.0.1", silent, edge, dst))
	// Detour: one extra (answering) hop in front of the silent one.
	s.Process(run(50000, 1, "10.0.0.1", detour, silent, edge, dst))
	// Back to the original route: TTL 2 is silent again.
	for sec := 2; sec < 5; sec++ {
		s.Process(run(50000, sec, "10.0.0.1", silent, edge, dst))
	}
	if len(s.events) != 2 {
		t.Fatalf("events = %+v, want detour and return", s.events)
	}
	if e := s.events[0]; e.TTL != 2 || e.OldHop != unknownHop || e.NewHop != detour {
		t.Errorf("detour event %+v, want divergence at TTL 2 (* -> %s)", e, detour)
	}
	if e := s.events[1]; e.ToPath != 1 {
		t.Errorf("return event %+v, want back to path 1", e)
	}
	// The silent TTL must not be blamed on the detour hop after the return.
	dl := append(flowLabelsFor("50000"), "2", detour)
	if sent := testutil.ToFloat64(s.m.hopSent.WithLabelValues(dl...)); sent != 1 {
		t.Errorf("detour hop sent = %v, want 1", sent)
	}
	last := s.records[len(s.records)-1]
	if ip := last.Hops[1].IP; ip != "" {
		t.Errorf("TTL 2 attributed to %q after the reroute, want unknown", ip)
	}
}

func TestFirstReplyBackfillsEarlierTimeouts(t *testing.T) {
	s := newTestStore(t)
	s.Process(run(50000, 0, "10.0.0.1", "", dst))
	s.Process(run(50000, 1, "10.0.0.1", "198.51.100.1", dst))

	if len(s.events) != 0 {
		t.Fatalf("learning a hop was reported as a path change: %+v", s.events)
	}
	if n := len(s.dests[dst].paths); n != 1 {
		t.Errorf("registered %d paths, want 1", n)
	}
	for _, n := range s.graphNodes(query{from: t0, to: t0.Add(time.Minute)}) {
		if strings.HasPrefix(n.ID, "*") {
			t.Errorf("phantom placeholder node %q", n.ID)
		}
	}
}

func TestSilentHopBecomesPlaceholder(t *testing.T) {
	s := newTestStore(t)
	for sec := range 3 {
		s.Process(run(50000, sec, "10.0.0.1", "", dst))
		s.Process(run(50001, sec, "10.0.0.9", "", dst))
	}
	var placeholders []graphNode
	for _, n := range s.graphNodes(query{from: t0, to: t0.Add(time.Minute)}) {
		if n.Title == unknownHop {
			placeholders = append(placeholders, n)
		}
	}
	// One per branch, not merged into a single fake node.
	if len(placeholders) != 2 {
		t.Fatalf("placeholders = %+v, want 2", placeholders)
	}
	if placeholders[0].ArcSilent != 1 {
		t.Errorf("placeholder arcs = %+v", placeholders[0])
	}
}

func TestForwardingLossIgnoresICMPRateLimiting(t *testing.T) {
	s := newTestStore(t)
	// Hop 2 drops half its replies, but nothing behind it loses packets.
	for sec := range 20 {
		hop2 := "198.51.100.1"
		if sec%2 == 0 {
			hop2 = ""
		}
		s.Process(run(50000, sec, "10.0.0.1", hop2, "203.0.113.1", dst))
	}
	// Flow 50001 has real loss from hop 2 (198.51.100.2) onwards.
	for sec := range 20 {
		if sec%4 == 0 {
			s.Process(run(50001, sec, "10.0.0.1", "", "", ""))
			continue
		}
		s.Process(run(50001, sec, "10.0.0.1", "198.51.100.2", "203.0.113.1", dst))
	}

	g := s.buildGraph(query{from: t0, to: t0.Add(time.Minute)})
	rl := g.nodes["198.51.100.1"]
	if rl.loss() != 0.5 || rl.fwdLoss != 0 {
		t.Errorf("rate-limiting hop: loss %.2f fwd %.2f, want 0.50 / 0", rl.loss(), rl.fwdLoss)
	}
	lossy := g.nodes["198.51.100.2"]
	if lossy.fwdLoss < 0.2 {
		t.Errorf("lossy hop fwd loss = %.2f, want 0.25", lossy.fwdLoss)
	}
	var edgeColor string
	for _, e := range s.graphEdges(query{from: t0, to: t0.Add(time.Minute)}) {
		if e.Target == "198.51.100.1" {
			edgeColor = e.Color
		}
	}
	if edgeColor != colorOK {
		t.Errorf("edge into rate-limiting hop colored %s, want %s", edgeColor, colorOK)
	}
}

func TestReplacedPathEdgesAreDashed(t *testing.T) {
	s := newTestStore(t)
	s.Process(run(50000, 0, "10.0.0.1", "198.51.100.1", dst))
	s.Process(run(50000, 1, "10.0.0.1", "198.51.100.2", dst))
	edges := map[string]graphEdge{}
	for _, e := range s.graphEdges(query{from: t0, to: t0.Add(2 * time.Second)}) {
		edges[e.ID] = e
	}
	if e := edges["10.0.0.1->198.51.100.1"]; e.StrokeDasharray == "" || e.InUse == "yes" {
		t.Errorf("old edge not marked stale: %+v", e)
	}
	if e := edges["10.0.0.1->198.51.100.2"]; e.StrokeDasharray != "" || e.InUse != "yes" {
		t.Errorf("current edge marked stale: %+v", e)
	}
}

func TestNonProbeLinesIgnored(t *testing.T) {
	s := newTestStore(t)
	w := NewWatcher("", s)
	w.handleLine([]byte(`{"distinct_paths":2,"flows_used":4,"paths":[]}`))
	w.handleLine([]byte(`not json`))
	if len(s.flows) != 0 {
		t.Errorf("discovery summary created flows")
	}
	if got := testutil.ToFloat64(s.m.parseError); got != 1 {
		t.Errorf("parse errors = %v, want 1", got)
	}
}

func TestOldLinesDoNotBumpCounters(t *testing.T) {
	s := newTestStore(t)
	s.liveAfter = time.Minute
	s.Process(run(50000, 0, "10.0.0.1", dst)) // an hour before "now"
	if got := testutil.CollectAndCount(s.m.runs); got != 0 {
		t.Errorf("replayed line incremented counters")
	}
	if got := testutil.ToFloat64(s.m.pathIndex.WithLabelValues(flowLabelsFor("50000")...)); got != 1 {
		t.Errorf("path index = %v, want 1", got)
	}
}

func TestExpireDropsFlowGauges(t *testing.T) {
	s := newTestStore(t)
	s.Process(run(50000, 0, "10.0.0.1", dst))
	s.Process(run(50000, 1, "10.0.0.1", dst))
	if testutil.CollectAndCount(s.m.pathIndex) != 1 || testutil.CollectAndCount(s.m.hopJitter) == 0 {
		t.Fatal("expected gauges before expiry")
	}
	s.Expire()
	if n := testutil.CollectAndCount(s.m.pathIndex); n != 0 {
		t.Errorf("path index series after expiry = %d", n)
	}
	if n := testutil.CollectAndCount(s.m.hopJitter); n != 0 {
		t.Errorf("jitter series after expiry = %d", n)
	}
	if got := testutil.ToFloat64(s.m.distinctPaths.WithLabelValues(dst)); got != 0 {
		t.Errorf("active paths after expiry = %v", got)
	}
}

func TestParseSet(t *testing.T) {
	for _, in := range []string{"", "All", "$__all", ".*"} {
		if got := parseSet(in, func(s string) (string, bool) { return s, true }); got != nil {
			t.Errorf("parseSet(%q) = %v, want nil", in, got)
		}
	}
	got := parseSet("{192.0.2.1,192.0.2.2}", func(s string) (string, bool) { return s, true })
	if len(got) != 2 || !got["192.0.2.1"] || !got["192.0.2.2"] {
		t.Errorf("parseSet = %v", got)
	}
}

func TestDemoOutputIsIngestible(t *testing.T) {
	s := newTestStore(t)
	for i, p := range demoPhases {
		for port := uint16(50000); port < 50008; port++ {
			pr := demoRun(0, uint(i), port, p, t0.Add(time.Duration(i)*time.Second))
			if !s.Process(pr) {
				t.Fatalf("demo run rejected: %+v", pr)
			}
		}
	}
	if n := len(s.dests[demoDest].paths); n < 4 {
		t.Errorf("demo produced %d distinct paths, want at least 4", n)
	}
}
