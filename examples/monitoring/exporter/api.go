package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The JSON API is shaped for Grafana's Infinity datasource: every endpoint
// returns a flat array of objects. /api/graph/{nodes,edges} use the field
// names the Node Graph panel expects.

type query struct {
	from, to time.Time
	sources  map[string]bool
	dests    map[string]bool
	ports    map[uint16]bool
}

func parseQuery(r *http.Request, now time.Time) query {
	q := query{to: now, from: now.Add(-15 * time.Minute)}
	v := r.URL.Query()
	if t, ok := parseMillis(v.Get("to")); ok {
		q.to = t
	}
	if t, ok := parseMillis(v.Get("from")); ok {
		q.from = t
	}
	str := func(s string) (string, bool) { return s, true }
	q.sources = parseSet(v.Get("source"), str)
	q.dests = parseSet(v.Get("destination"), str)
	q.ports = parseSet(v.Get("src_port"), func(s string) (uint16, bool) {
		n, err := strconv.ParseUint(s, 10, 16)
		return uint16(n), err == nil
	})
	return q
}

func parseMillis(s string) (time.Time, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.UnixMilli(n), true
}

// parseSet parses a comma separated filter. Empty values and Grafana's
// "All" placeholders mean "no filter".
func parseSet[T comparable](s string, conv func(string) (T, bool)) map[T]bool {
	out := map[T]bool{}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '|' || r == ' ' }) {
		part = strings.Trim(part, "{}()")
		switch part {
		case "", "All", "$__all", ".*", "*":
			return nil
		}
		if v, ok := conv(part); ok {
			out[v] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (q query) matchFlow(k FlowKey) bool {
	return (q.sources == nil || q.sources[k.Source]) && (q.dests == nil || q.dests[k.Destination]) &&
		(q.ports == nil || q.ports[k.SrcPort])
}

// window returns the records in the query window, in arrival order.
func (s *Store) window(q query) []*record {
	var out []*record
	for i := range s.records {
		r := &s.records[i]
		if r.TS.Before(q.from) || r.TS.After(q.to) || !q.matchFlow(r.Flow) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// lastPerFlow returns the latest record of each flow that was still active
// at the end of the window. Those records define what is "in use".
func (s *Store) lastPerFlow(recs []*record, q query) map[FlowKey]*record {
	last := map[FlowKey]*record{}
	for _, r := range recs {
		if cur, ok := last[r.Flow]; !ok || !r.TS.Before(cur.TS) {
			last[r.Flow] = r
		}
	}
	for k, r := range last {
		if q.to.Sub(r.TS) > s.stale {
			delete(last, k)
		}
	}
	return last
}

type stats struct {
	sent, recv int
	rtts       []float64 // ms
	jSum       float64
	jN         int
}

func (st *stats) add(o *hopObs) {
	st.sent++
	if !o.Lost {
		st.recv++
		st.rtts = append(st.rtts, float64(o.RTT)/1000)
	}
}

func (st *stats) loss() float64 {
	if st.sent == 0 {
		return 0
	}
	return 1 - float64(st.recv)/float64(st.sent)
}

func (st *stats) avg() float64 {
	if len(st.rtts) == 0 {
		return math.NaN()
	}
	var sum float64
	for _, v := range st.rtts {
		sum += v
	}
	return sum / float64(len(st.rtts))
}

func (st *stats) quantile(p float64) float64 {
	if len(st.rtts) == 0 {
		return math.NaN()
	}
	s := slices.Clone(st.rtts)
	slices.Sort(s)
	return s[int(math.Round(p*float64(len(s)-1)))]
}

func (st *stats) best() float64  { return st.quantile(0) }
func (st *stats) worst() float64 { return st.quantile(1) }

func (st *stats) jitter() float64 {
	if st.jN == 0 {
		return math.NaN()
	}
	return st.jSum / float64(st.jN)
}

// jitterTracker accumulates mean absolute RTT deltas between consecutive
// replies of the same flow at the same TTL.
type jitterTracker map[string]float64

func (j jitterTracker) observe(st *stats, key string, o *hopObs) {
	if o.Lost {
		return
	}
	rtt := float64(o.RTT) / 1000
	if prev, ok := j[key]; ok {
		st.jSum += math.Abs(rtt - prev)
		st.jN++
	}
	j[key] = rtt
}

type nodeAgg struct {
	stats
	id          string
	ip          string
	ttl         int
	flows       map[FlowKey]bool
	paths       map[string]bool
	dests       map[string]bool
	source      bool
	placeholder bool
	destination bool
	inUse       bool
	lastSeen    time.Time
	fwdLoss     float64
}

type edgeAgg struct {
	source, target string
	flows          map[FlowKey]bool
	paths          map[string]bool
	inUse          bool
	lastSeen       time.Time
}

type graph struct {
	nodes map[string]*nodeAgg
	edges map[string]*edgeAgg
	succ  map[string][]string
	multi bool
}

func pathLabel(multi bool, t Target, idx int) string {
	if multi {
		return fmt.Sprintf("%s #%d", t, idx)
	}
	return fmt.Sprintf("#%d", idx)
}

func (s *Store) buildGraph(q query) *graph {
	recs := s.window(q)
	last := s.lastPerFlow(recs, q)
	g := &graph{nodes: map[string]*nodeAgg{}, edges: map[string]*edgeAgg{}, succ: map[string][]string{}}
	targets := map[Target]bool{}
	for _, r := range recs {
		targets[r.Flow.target()] = true
	}
	g.multi = len(targets) > 1

	node := func(id string, ttl int) *nodeAgg {
		n := g.nodes[id]
		if n == nil {
			n = &nodeAgg{id: id, ttl: ttl, flows: map[FlowKey]bool{}, paths: map[string]bool{}, dests: map[string]bool{}}
			g.nodes[id] = n
		}
		n.ttl = min(n.ttl, ttl)
		return n
	}
	jt := jitterTracker{}
	for _, r := range recs {
		inUse := last[r.Flow] == r
		pl := pathLabel(g.multi, r.Flow.target(), r.PathIdx)
		src := node(sourceNodeID(r.Flow.Source), 0)
		src.source, src.ip = true, r.Flow.Source
		src.flows[r.Flow] = true
		src.inUse = src.inUse || inUse
		src.lastSeen = maxTime(src.lastSeen, r.TS)
		prev := src.id
		for i := range r.Hops {
			o := &r.Hops[i]
			n := node(o.Node, int(o.TTL))
			n.ip = o.IP
			n.placeholder = o.IP == ""
			n.destination = n.destination || o.IP == r.Flow.Destination
			n.add(o)
			jt.observe(&n.stats, fmt.Sprintf("%v|%d|%s", r.Flow, o.TTL, o.Node), o)
			n.flows[r.Flow] = true
			n.paths[pl] = true
			n.dests[r.Flow.Destination] = true
			n.inUse = n.inUse || inUse
			n.lastSeen = maxTime(n.lastSeen, r.TS)

			eid := prev + "->" + n.id
			e := g.edges[eid]
			if e == nil {
				e = &edgeAgg{source: prev, target: n.id, flows: map[FlowKey]bool{}, paths: map[string]bool{}}
				g.edges[eid] = e
				g.succ[prev] = append(g.succ[prev], n.id)
			}
			e.flows[r.Flow] = true
			e.paths[pl] = true
			e.inUse = e.inUse || inUse
			e.lastSeen = maxTime(e.lastSeen, r.TS)
			prev = n.id
		}
	}
	g.computeForwardingLoss(recs)
	return g
}

// computeForwardingLoss estimates the loss a hop actually forwards, as opposed
// to a router rate-limiting its own ICMP replies. Loss on a link shows up at
// every hop behind it, so for the flows crossing a node, forwarding loss is
// the lowest loss seen at that node or any later TTL. Silent hops are skipped.
func (g *graph) computeForwardingLoss(recs []*record) {
	type key struct {
		node string
		ttl  uint8
	}
	down := map[key]*stats{}
	for _, r := range recs {
		for i := range r.Hops {
			n := &r.Hops[i]
			for j := i; j < len(r.Hops); j++ {
				o := &r.Hops[j]
				if o.IP == "" {
					continue
				}
				k := key{n.Node, o.TTL}
				if down[k] == nil {
					down[k] = &stats{}
				}
				down[k].sent++
				if !o.Lost {
					down[k].recv++
				}
			}
		}
	}
	for _, n := range g.nodes {
		n.fwdLoss = math.NaN()
	}
	for k, st := range down {
		if n := g.nodes[k.node]; n != nil {
			l := st.loss()
			if math.IsNaN(n.fwdLoss) || l < n.fwdLoss {
				n.fwdLoss = l
			}
		}
	}
	for _, n := range g.nodes {
		if math.IsNaN(n.fwdLoss) {
			n.fwdLoss = 0
		}
	}
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

type graphNode struct {
	ID            string  `json:"id"`
	Title         string  `json:"title"`
	Subtitle      string  `json:"subtitle"`
	MainStat      string  `json:"mainstat"`
	SecondaryStat string  `json:"secondarystat"`
	ArcOK         float64 `json:"arc__ok"`
	ArcLoss       float64 `json:"arc__loss"`
	ArcSilent     float64 `json:"arc__silent"`
	ArcIdle       float64 `json:"arc__idle"`
	Highlighted   bool    `json:"highlighted"`
	FixedX        float64 `json:"fixedx"`
	FixedY        float64 `json:"fixedy"`
	IP            string  `json:"detail__ip"`
	PTR           string  `json:"detail__ptr"`
	ASN           string  `json:"detail__asn"`
	TTL           int     `json:"detail__ttl"`
	Avg           string  `json:"detail__avg"`
	P95           string  `json:"detail__p95"`
	Jitter        string  `json:"detail__jitter"`
	Loss          string  `json:"detail__loss"`
	FwdLoss       string  `json:"detail__fwd_loss"`
	Sent          int     `json:"detail__sent"`
	Flows         string  `json:"detail__flows"`
	Paths         string  `json:"detail__paths"`
	InUse         string  `json:"detail__in_use"`
}

type graphEdge struct {
	ID              string  `json:"id"`
	Source          string  `json:"source"`
	Target          string  `json:"target"`
	MainStat        string  `json:"mainstat"`
	SecondaryStat   string  `json:"secondarystat"`
	Thickness       float64 `json:"thickness"`
	Color           string  `json:"color"`
	StrokeDasharray string  `json:"strokedasharray"`
	Flows           string  `json:"detail__flows"`
	Paths           string  `json:"detail__paths"`
	InUse           string  `json:"detail__in_use"`
	LastSeen        string  `json:"detail__last_seen"`
}

const (
	colorOK    = "#73BF69"
	colorWarn  = "#FF9830"
	colorBad   = "#F2495C"
	colorStale = "#8E8E8E"

	// Loss above these thresholds colors edges / highlights nodes.
	warnLoss = 0.01
	badLoss  = 0.05

	nodeSpacingX = 180
	nodeSpacingY = 130
)

func lossColor(l float64) string {
	switch {
	case l >= badLoss:
		return colorBad
	case l >= warnLoss:
		return colorWarn
	default:
		return colorOK
	}
}

func (s *Store) graphNodes(q query) []graphNode {
	g := s.buildGraph(q)

	// Lay nodes out left to right by TTL; order each column by path number
	// so the ECMP branches stay in stable rows.
	// The graph is centered on (0,0), which is where the panel's view starts.
	cols := map[int][]*nodeAgg{}
	maxTTL := 0
	for _, n := range g.nodes {
		cols[n.ttl] = append(cols[n.ttl], n)
		maxTTL = max(maxTTL, n.ttl)
	}
	pos := map[string][2]float64{}
	for ttl, col := range cols {
		slices.SortFunc(col, func(a, b *nodeAgg) int {
			return cmp.Or(cmp.Compare(firstPath(a.paths), firstPath(b.paths)), cmp.Compare(a.id, b.id))
		})
		for i, n := range col {
			pos[n.id] = [2]float64{
				(float64(ttl) - float64(maxTTL)/2) * nodeSpacingX,
				(float64(i) - float64(len(col)-1)/2) * nodeSpacingY,
			}
		}
	}

	out := make([]graphNode, 0, len(g.nodes))
	for _, n := range g.nodes {
		meta := s.hopMeta[n.ip]
		gn := graphNode{
			ID:     n.id,
			Title:  n.ip,
			FixedX: pos[n.id][0],
			FixedY: pos[n.id][1],
			IP:     n.ip,
			PTR:    meta.ptr,
			ASN:    meta.asn,
			TTL:    n.ttl,
			Sent:   n.sent,
			Flows:  flowList(n.flows),
			Paths:  setList(n.paths),
			InUse:  inUseText(n.inUse, n.lastSeen),
		}
		switch {
		case n.source:
			gn.Title, gn.Subtitle, gn.MainStat = n.ip, "source", "source"
			gn.ArcOK = 1
		case n.placeholder:
			gn.Title, gn.Subtitle = unknownHop, fmt.Sprintf("TTL %d · no reply", n.ttl)
			gn.MainStat = "no reply"
			gn.ArcSilent = 1
			gn.FwdLoss = pct(n.fwdLoss)
		default:
			gn.Subtitle = shorten(cmp.Or(meta.ptr, meta.asn), 28)
			if n.destination {
				if d := s.dests[n.ip]; d != nil && d.ptr != "" {
					gn.Subtitle = shorten(d.ptr, 28)
				}
			}
			gn.MainStat = ms(n.avg())
			gn.SecondaryStat = pct(n.loss()) + " loss"
			gn.ArcLoss = n.loss()
			gn.ArcOK = 1 - gn.ArcLoss
			gn.Highlighted = n.inUse && n.fwdLoss >= warnLoss
			gn.Avg, gn.P95, gn.Jitter = ms(n.avg()), ms(n.quantile(0.95)), ms(n.jitter())
			gn.Loss, gn.FwdLoss = pct(n.loss()), pct(n.fwdLoss)
		}
		if !n.inUse && !n.source {
			// Hops only seen on paths no longer in use are drawn hollow.
			gn.ArcIdle, gn.ArcOK, gn.ArcLoss, gn.ArcSilent = 1, 0, 0, 0
		}
		out = append(out, gn)
	}
	slices.SortFunc(out, func(a, b graphNode) int {
		return cmp.Or(cmp.Compare(a.FixedX, b.FixedX), cmp.Compare(a.FixedY, b.FixedY))
	})
	return out
}

func (s *Store) graphEdges(q query) []graphEdge {
	g := s.buildGraph(q)
	out := make([]graphEdge, 0, len(g.edges))
	for id, e := range g.edges {
		src, dst := g.nodes[e.source], g.nodes[e.target]
		ge := graphEdge{
			ID:            id,
			Source:        e.source,
			Target:        e.target,
			SecondaryStat: plural(len(e.flows), "flow"),
			Thickness:     math.Min(1+float64(len(e.flows)), 8),
			Color:         lossColor(dst.fwdLoss),
			Flows:         flowList(e.flows),
			Paths:         setList(e.paths),
			InUse:         inUseText(e.inUse, e.lastSeen),
			LastSeen:      e.lastSeen.Format(time.RFC3339),
		}
		srcRTT := 0.0
		if !src.source {
			srcRTT = src.avg()
		}
		if d := dst.avg() - srcRTT; !math.IsNaN(d) {
			ge.MainStat = fmt.Sprintf("%+.1f ms", d)
		}
		if !e.inUse {
			ge.Color, ge.StrokeDasharray, ge.Thickness = colorStale, "6 4", 1
		}
		out = append(out, ge)
	}
	slices.SortFunc(out, func(a, b graphEdge) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

type flowRow struct {
	Source      string  `json:"source"`
	Destination string  `json:"destination"`
	Protocol    string  `json:"protocol"`
	SrcPort     uint16  `json:"src_port"`
	DstPort     uint16  `json:"dst_port"`
	Path        string  `json:"path"`
	Hops        int     `json:"hops"`
	Route       string  `json:"route"`
	Loss        float64 `json:"loss_pct"`
	Avg         optNum  `json:"avg_ms"`
	P95         optNum  `json:"p95_ms"`
	Jitter      optNum  `json:"jitter_ms"`
	Last        optNum  `json:"last_ms"`
	Changes     int     `json:"path_changes"`
	LastSeen    int64   `json:"last_seen"`
	Active      bool    `json:"active"`
}

func (s *Store) flowRows(q query) []flowRow {
	recs := s.window(q)
	last := s.lastPerFlow(recs, q)
	type acc struct {
		stats
		last *record
	}
	byFlow := map[FlowKey]*acc{}
	jt := jitterTracker{}
	for _, r := range recs {
		a := byFlow[r.Flow]
		if a == nil {
			a = &acc{}
			byFlow[r.Flow] = a
		}
		a.last = r
		if len(r.Hops) == 0 {
			a.sent++
			continue
		}
		o := r.Hops[len(r.Hops)-1]
		o.Lost = !r.Reached
		a.add(&o)
		jt.observe(&a.stats, fmt.Sprint(r.Flow), &o)
	}
	changes := map[FlowKey]int{}
	for _, e := range s.events {
		if !e.Time.Before(q.from) && !e.Time.After(q.to) {
			changes[e.Flow]++
		}
	}
	out := make([]flowRow, 0, len(byFlow))
	for k, a := range byFlow {
		row := flowRow{
			Source:      k.Source,
			Destination: k.Destination,
			Protocol:    k.Protocol,
			SrcPort:     k.SrcPort,
			DstPort:     k.DstPort,
			Path:        fmt.Sprintf("#%d", a.last.PathIdx),
			Hops:        len(a.last.Hops),
			Route:       s.route(recordHops(a.last)),
			Loss:        round(a.loss() * 100),
			Avg:         optNum(a.avg()),
			P95:         optNum(a.quantile(0.95)),
			Jitter:      optNum(a.jitter()),
			Changes:     changes[k],
			LastSeen:    a.last.TS.UnixMilli(),
			Active:      last[k] != nil,
		}
		row.Last = optNum(math.NaN())
		if n := len(a.last.Hops); a.last.Reached && n > 0 {
			row.Last = optNum(float64(a.last.Hops[n-1].RTT) / 1000)
		}
		out = append(out, row)
	}
	slices.SortFunc(out, func(a, b flowRow) int {
		return cmp.Or(cmp.Compare(a.Source, b.Source), cmp.Compare(a.Destination, b.Destination),
			cmp.Compare(a.Protocol, b.Protocol), cmp.Compare(a.DstPort, b.DstPort), cmp.Compare(a.SrcPort, b.SrcPort))
	})
	return out
}

func recordHops(r *record) []string {
	out := make([]string, len(r.Hops))
	for i, o := range r.Hops {
		out[i] = cmp.Or(o.IP, unknownHop)
	}
	return out
}

type pathRow struct {
	Source      string  `json:"source"`
	Destination string  `json:"destination"`
	Path        string  `json:"path"`
	Index       int     `json:"index"`
	Hops        int     `json:"hops"`
	Route       string  `json:"route"`
	FlowsNow    int     `json:"flows_now"`
	Flows       string  `json:"flows"`
	Share       float64 `json:"share_pct"`
	Loss        float64 `json:"loss_pct"`
	Avg         optNum  `json:"avg_ms"`
	P95         optNum  `json:"p95_ms"`
	FirstSeen   int64   `json:"first_seen"`
	LastSeen    int64   `json:"last_seen"`
}

func (s *Store) pathRows(q query) []pathRow {
	recs := s.window(q)
	last := s.lastPerFlow(recs, q)
	type key struct {
		t   Target
		idx int
	}
	st := map[key]*stats{}
	total := map[Target]int{}
	for _, r := range recs {
		k := key{r.Flow.target(), r.PathIdx}
		a := st[k]
		if a == nil {
			a = &stats{}
			st[k] = a
		}
		total[r.Flow.target()]++
		if len(r.Hops) == 0 {
			a.sent++
			continue
		}
		o := r.Hops[len(r.Hops)-1]
		o.Lost = !r.Reached
		a.add(&o)
	}
	now := map[key]map[FlowKey]bool{}
	for fk, r := range last {
		k := key{fk.target(), r.PathIdx}
		if now[k] == nil {
			now[k] = map[FlowKey]bool{}
		}
		now[k][fk] = true
	}
	var out []pathRow
	for t, ts := range s.targets {
		for _, p := range ts.paths {
			a := st[key{t, p.Index}]
			if a == nil {
				continue
			}
			flows := now[key{t, p.Index}]
			out = append(out, pathRow{
				Source:      t.Source,
				Destination: t.Destination,
				Path:        fmt.Sprintf("#%d", p.Index),
				Index:       p.Index,
				Hops:        len(p.Hops),
				Route:       s.route(p.Hops),
				FlowsNow:    len(flows),
				Flows:       flowList(flows),
				Share:       round(100 * float64(a.sent) / float64(max(total[t], 1))),
				Loss:        round(a.loss() * 100),
				Avg:         optNum(a.avg()),
				P95:         optNum(a.quantile(0.95)),
				FirstSeen:   p.FirstSeen.UnixMilli(),
				LastSeen:    p.LastSeen.UnixMilli(),
			})
		}
	}
	slices.SortFunc(out, func(a, b pathRow) int {
		return cmp.Or(cmp.Compare(a.Source, b.Source), cmp.Compare(a.Destination, b.Destination),
			cmp.Compare(a.Index, b.Index))
	})
	return out
}

type eventRow struct {
	Time        int64  `json:"time"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	SrcPort     uint16 `json:"src_port"`
	Change      string `json:"change"`
	TTL         int    `json:"ttl"`
	OldHop      string `json:"old_hop"`
	NewHop      string `json:"new_hop"`
	OldRoute    string `json:"old_route"`
	NewRoute    string `json:"new_route"`
}

func (s *Store) eventRows(q query) []eventRow {
	out := []eventRow{}
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		if e.Time.Before(q.from) || e.Time.After(q.to) || !q.matchFlow(e.Flow) {
			continue
		}
		out = append(out, eventRow{
			Time:        e.Time.UnixMilli(),
			Source:      e.Flow.Source,
			Destination: e.Flow.Destination,
			Protocol:    e.Flow.Protocol,
			SrcPort:     e.Flow.SrcPort,
			Change:      fmt.Sprintf("#%d → #%d", e.FromPath, e.ToPath),
			TTL:         int(e.TTL),
			OldHop:      s.hopName(e.OldHop),
			NewHop:      s.hopName(e.NewHop),
			OldRoute:    s.route(e.OldHops),
			NewRoute:    s.route(e.NewHops),
		})
	}
	return out
}

type hopRow struct {
	Source      string  `json:"source"`
	Destination string  `json:"destination"`
	TTL         int     `json:"ttl"`
	IP          string  `json:"ip"`
	PTR         string  `json:"ptr"`
	ASN         string  `json:"asn"`
	Sent        int     `json:"sent"`
	Loss        float64 `json:"loss_pct"`
	FwdLoss     float64 `json:"fwd_loss_pct"`
	Avg         optNum  `json:"avg_ms"`
	Best        optNum  `json:"best_ms"`
	Worst       optNum  `json:"worst_ms"`
	P95         optNum  `json:"p95_ms"`
	Jitter      optNum  `json:"jitter_ms"`
	Flows       int     `json:"flows"`
	Paths       string  `json:"paths"`
	InUse       bool    `json:"in_use"`
}

func (s *Store) hopRows(q query) []hopRow {
	g := s.buildGraph(q)
	recs := s.window(q)
	last := s.lastPerFlow(recs, q)
	type key struct {
		t    Target
		ttl  uint8
		node string
	}
	type acc struct {
		stats
		ip    string
		flows map[FlowKey]bool
		paths map[int]bool
		inUse bool
	}
	byHop := map[key]*acc{}
	jt := jitterTracker{}
	for _, r := range recs {
		for i := range r.Hops {
			o := &r.Hops[i]
			k := key{r.Flow.target(), o.TTL, o.Node}
			a := byHop[k]
			if a == nil {
				a = &acc{ip: o.IP, flows: map[FlowKey]bool{}, paths: map[int]bool{}}
				byHop[k] = a
			}
			a.add(o)
			jt.observe(&a.stats, fmt.Sprintf("%v|%d|%s", r.Flow, o.TTL, o.Node), o)
			a.flows[r.Flow] = true
			a.paths[r.PathIdx] = true
			a.inUse = a.inUse || last[r.Flow] == r
		}
	}
	out := make([]hopRow, 0, len(byHop))
	for k, a := range byHop {
		meta := s.hopMeta[a.ip]
		row := hopRow{
			Source:      k.t.Source,
			Destination: k.t.Destination,
			TTL:         int(k.ttl),
			IP:          cmp.Or(a.ip, unknownHop),
			PTR:         meta.ptr,
			ASN:         meta.asn,
			Sent:        a.sent,
			Loss:        round(a.loss() * 100),
			Avg:         optNum(a.avg()),
			Best:        optNum(a.best()),
			Worst:       optNum(a.worst()),
			P95:         optNum(a.quantile(0.95)),
			Jitter:      optNum(a.jitter()),
			Flows:       len(a.flows),
			InUse:       a.inUse,
		}
		if n := g.nodes[k.node]; n != nil {
			row.FwdLoss = round(n.fwdLoss * 100)
		}
		paths := make([]string, 0, len(a.paths))
		for _, idx := range slices.Sorted(maps.Keys(a.paths)) {
			paths = append(paths, fmt.Sprintf("#%d", idx))
		}
		row.Paths = strings.Join(paths, " ")
		out = append(out, row)
	}
	slices.SortFunc(out, func(a, b hopRow) int {
		return cmp.Or(cmp.Compare(a.Source, b.Source), cmp.Compare(a.Destination, b.Destination), cmp.Compare(a.TTL, b.TTL),
			-cmp.Compare(a.Sent, b.Sent), cmp.Compare(a.IP, b.IP))
	})
	return out
}

func (s *Store) route(hops []string) string {
	return strings.Join(hops, " → ")
}

func (s *Store) hopName(ip string) string {
	if m := s.hopMeta[ip]; m.ptr != "" {
		return ip + " (" + m.ptr + ")"
	}
	return ip
}

func firstPath(paths map[string]bool) string {
	return slices.Min(append(slices.Collect(maps.Keys(paths)), "~"))
}

func setList(m map[string]bool) string {
	return strings.Join(slices.Sorted(maps.Keys(m)), " ")
}

func flowList(m map[FlowKey]bool) string {
	keys := slices.SortedFunc(maps.Keys(m), func(a, b FlowKey) int {
		return cmp.Or(cmp.Compare(a.Source, b.Source), cmp.Compare(a.Destination, b.Destination),
			cmp.Compare(a.Protocol, b.Protocol), cmp.Compare(a.SrcPort, b.SrcPort))
	})
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s:%d", k.Protocol, k.SrcPort)
	}
	return strings.Join(parts, " ")
}

func inUseText(inUse bool, last time.Time) string {
	if inUse {
		return "yes"
	}
	return "no, last seen " + last.Format("15:04:05")
}

func ms(v float64) string {
	if math.IsNaN(v) {
		return ""
	}
	return fmt.Sprintf("%.1f ms", v)
}

func pct(v float64) string { return fmt.Sprintf("%.1f%%", v*100) }

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// round keeps two decimals and maps NaN to 0 (JSON has no NaN).
// optNum is a number that is encoded as null when it is undefined (NaN), so
// tables show an empty cell instead of a misleading 0.
type optNum float64

func (n optNum) MarshalJSON() ([]byte, error) {
	v := float64(n)
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return []byte("null"), nil
	}
	return strconv.AppendFloat(nil, math.Round(v*100)/100, 'f', -1, 64), nil
}

func round(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return math.Round(v*100) / 100
}

func (s *Store) Handler() http.Handler {
	mux := http.NewServeMux()
	endpoint := func(path string, fn func(query) any) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			s.mu.RLock()
			v := fn(parseQuery(r, s.now()))
			s.mu.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		})
	}
	endpoint("/api/graph/nodes", func(q query) any { return s.graphNodes(q) })
	endpoint("/api/graph/edges", func(q query) any { return s.graphEdges(q) })
	endpoint("/api/flows", func(q query) any { return s.flowRows(q) })
	endpoint("/api/paths", func(q query) any { return nonNil(s.pathRows(q)) })
	endpoint("/api/events", func(q query) any { return s.eventRows(q) })
	endpoint("/api/hops", func(q query) any { return s.hopRows(q) })
	endpoint("/api/targets", func(q query) any { return s.targetRows(q) })
	return mux
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
