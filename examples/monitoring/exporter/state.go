package main

import (
	"slices"
	"strconv"
	"sync"
	"time"
)

const unknownHop = "*"

// FlowKey identifies one ECMP flow (a 5-tuple).
type FlowKey struct {
	Source      string
	Destination string
	Protocol    string
	DstPort     uint16
	SrcPort     uint16
}

func (k FlowKey) labels() []string {
	return []string{k.Source, k.Destination, k.Protocol, strconv.Itoa(int(k.DstPort)), strconv.Itoa(int(k.SrcPort))}
}

// Target is what etr traces: a destination as seen from one source. Paths
// are numbered per target.
type Target struct {
	Source      string
	Destination string
}

func (k FlowKey) target() Target { return Target{k.Source, k.Destination} }

func (t Target) String() string { return t.Source + " → " + t.Destination }

func (k FlowKey) hopLabels(ttl uint8, ip string) []string {
	return append(k.labels(), strconv.Itoa(int(ttl)), ip)
}

// hopObs is one TTL of one probe iteration. Node is the graph node the
// observation is attributed to: the responding IP, the last IP seen at that
// TTL for the flow (for timeouts), or a placeholder for silent hops.
type hopObs struct {
	TTL  uint8
	Node string
	IP   string
	RTT  int64 // microseconds
	Lost bool
}

type record struct {
	TS      time.Time
	Flow    FlowKey
	PathIdx int
	Reached bool
	Hops    []hopObs
}

type pathEntry struct {
	Index     int
	Hops      []string
	FirstSeen time.Time
	LastSeen  time.Time
}

type destState struct {
	ip      string
	ptr     string
	asn     string
	infoSet bool
}

type targetState struct {
	paths  []*pathEntry
	labels []string // fleet metric labels
}

type transitKey struct {
	site string
	hop  string
}

type flowState struct {
	key        FlowKey
	lastIP     map[uint8]string
	jitterIP   map[uint8]string
	prevRTT    map[uint8]float64
	jitter     map[uint8]float64
	destPrev   float64
	destJitter float64
	hasDest    bool
	path       *pathEntry
	hops       []string
	lastNodes  []string
	lastSeen   time.Time
	expired    bool
}

// PathEvent records a flow moving from one path to another.
type PathEvent struct {
	Time     time.Time
	Flow     FlowKey
	FromPath int
	ToPath   int
	TTL      uint8
	OldHop   string
	NewHop   string
	OldHops  []string
	NewHops  []string
}

type hopMeta struct {
	ptr string
	asn string
}

// Store turns etr probe runs into path state, Prometheus metrics and a
// short in-memory history used by the JSON API.
type Store struct {
	mu        sync.RWMutex
	m         *Metrics
	retention time.Duration
	stale     time.Duration
	liveAfter time.Duration
	now       func() time.Time

	flows   map[FlowKey]*flowState
	dests   map[string]*destState
	targets map[Target]*targetState
	sites   *Sites
	transit map[transitKey]map[Target]time.Time
	hopMeta map[string]hopMeta
	records []record
	events  []PathEvent
}

const maxEvents = 5000

func NewStore(m *Metrics, retention, stale time.Duration) *Store {
	return &Store{
		m:         m,
		retention: retention,
		stale:     stale,
		liveAfter: 2 * time.Minute,
		now:       time.Now,
		flows:     make(map[FlowKey]*flowState),
		dests:     make(map[string]*destState),
		targets:   make(map[Target]*targetState),
		transit:   make(map[transitKey]map[Target]time.Time),
		hopMeta:   make(map[string]hopMeta),
	}
}

// Process ingests one probe run. It returns false if the input is not a
// probe run (for example an etr --discover summary line).
func (s *Store) Process(pr *ProbeRun) bool {
	if pr == nil || pr.DestinationIP == "" || pr.Timestamp.IsZero() {
		return false
	}
	if pr.Protocol == "" {
		pr.Protocol = "TCP"
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	// Lines older than liveAfter (e.g. when the exporter starts on an existing
	// file) update path state and history, but not counters/histograms, so a
	// restart does not produce a burst in rate() graphs.
	live := pr.Timestamp.After(now.Add(-s.liveAfter))

	key := FlowKey{pr.SourceIP, pr.DestinationIP, pr.Protocol, pr.DestinationPort, pr.SourcePort}
	f := s.flows[key]
	if f == nil {
		f = &flowState{
			key:      key,
			lastIP:   make(map[uint8]string),
			jitterIP: make(map[uint8]string),
			prevRTT:  make(map[uint8]float64),
			jitter:   make(map[uint8]float64),
		}
		s.flows[key] = f
	}
	if pr.Timestamp.Before(f.lastSeen) {
		// Out of order (e.g. file rewound). Ignore to keep path state sane.
		return true
	}
	f.lastSeen = pr.Timestamp
	f.expired = false

	s.dest(pr)
	t := s.target(key.target())

	hops := slices.Clone(pr.Hops)
	hops = slices.DeleteFunc(hops, func(h *HopRun) bool { return h == nil || h.TTL == 0 })
	slices.SortFunc(hops, func(a, b *HopRun) int { return int(a.TTL) - int(b.TTL) })

	// A responding hop that differs from what this flow saw before means the
	// route changed. IPs carried forward into silent TTLs belong to the old
	// route then, so forget them rather than blame a hop that is not there.
	var maxTTL uint8
	rerouted := false
	for _, h := range hops {
		maxTTL = max(maxTTL, h.TTL)
		if old, ok := f.lastIP[h.TTL]; ok && !h.Timeout && h.IP != "" && h.IP != old {
			rerouted = true
		}
	}
	for _, h := range hops {
		if !h.Timeout && h.IP != "" {
			if _, known := f.lastIP[h.TTL]; !known && !rerouted && f.path != nil {
				s.backfill(key, f.path.Index, h.TTL, h.IP)
			}
			f.lastIP[h.TTL] = h.IP
			s.setHopMeta(h.IP, h.PTR, h.ASN)
		} else if rerouted {
			delete(f.lastIP, h.TTL)
		}
	}
	if pr.ReachedDest {
		for ttl := range f.lastIP {
			if ttl > maxTTL {
				delete(f.lastIP, ttl)
			}
		}
	}

	obs := make([]hopObs, 0, len(hops))
	for _, h := range hops {
		o := hopObs{TTL: h.TTL, RTT: h.RTT}
		if !h.Timeout && h.IP != "" {
			o.IP = h.IP
		} else {
			o.Lost = true
			o.IP = f.lastIP[h.TTL]
		}
		obs = append(obs, o)
	}
	assignNodes(pr.SourceIP, obs)

	vec := f.pathVector(maxTTL, pr.ReachedDest)
	s.updatePath(f, t, vec, pr.Timestamp)

	f.lastNodes = f.lastNodes[:0]
	for _, o := range obs {
		f.lastNodes = append(f.lastNodes, o.Node)
	}

	s.records = append(s.records, record{
		TS:      pr.Timestamp,
		Flow:    key,
		PathIdx: f.path.Index,
		Reached: pr.ReachedDest,
		Hops:    obs,
	})

	s.updateMetrics(f, pr, obs, len(vec), live)
	s.updateFleetMetrics(t, key, pr, obs, live)
	s.updateActivePaths(key.target())
	s.prune(now)
	return true
}

// SetSites sets the IP → site mapping used for the fleet metrics. Call it
// before processing any input.
func (s *Store) SetSites(sites *Sites) { s.sites = sites }

func (s *Store) target(t Target) *targetState {
	ts := s.targets[t]
	if ts == nil {
		src, dst := s.sites.Lookup(t.Source), s.sites.Lookup(t.Destination)
		ts = &targetState{labels: []string{t.Source, src.Name, t.Destination, dst.Name, dst.Class}}
		s.targets[t] = ts
	}
	return ts
}

func (s *Store) dest(pr *ProbeRun) *destState {
	d := s.dests[pr.DestinationIP]
	if d == nil {
		d = &destState{ip: pr.DestinationIP}
		s.dests[pr.DestinationIP] = d
	}
	ptr, asn := d.ptr, d.asn
	if pr.DestinationPTR != "" {
		ptr = pr.DestinationPTR
	}
	if pr.DestinationASN != "" {
		asn = pr.DestinationASN
	}
	if d.infoSet && ptr == d.ptr && asn == d.asn {
		return d
	}
	if s.m != nil {
		if d.infoSet {
			s.m.destInfo.DeleteLabelValues(d.ip, d.ptr, d.asn)
		}
		s.m.destInfo.WithLabelValues(d.ip, ptr, asn).Set(1)
	}
	d.ptr, d.asn, d.infoSet = ptr, asn, true
	return d
}

func (s *Store) setHopMeta(ip, ptr, asn string) {
	old, ok := s.hopMeta[ip]
	nm := old
	if ptr != "" {
		nm.ptr = ptr
	}
	if asn != "" {
		nm.asn = asn
	}
	if ok && nm == old {
		return
	}
	s.hopMeta[ip] = nm
	if s.m != nil {
		if ok {
			s.m.hopInfo.DeleteLabelValues(ip, old.ptr, old.asn)
		}
		s.m.hopInfo.WithLabelValues(ip, nm.ptr, nm.asn).Set(1)
	}
}

// pathVector returns the flow's current path, one entry per TTL starting at
// 1. Timeouts are filled in with the last IP seen at that TTL, so a single
// lost reply is not mistaken for a path change. Trailing unknowns are dropped.
func (f *flowState) pathVector(maxTTL uint8, reached bool) []string {
	n := int(maxTTL)
	if !reached {
		for ttl := range f.lastIP {
			n = max(n, int(ttl))
		}
	}
	vec := make([]string, n)
	for i := range vec {
		if ip, ok := f.lastIP[uint8(i+1)]; ok {
			vec[i] = ip
		} else {
			vec[i] = unknownHop
		}
	}
	for len(vec) > 0 && vec[len(vec)-1] == unknownHop {
		vec = vec[:len(vec)-1]
	}
	return vec
}

func (s *Store) updatePath(f *flowState, d *targetState, vec []string, ts time.Time) {
	switch {
	case f.path == nil:
		f.path = d.match(vec, ts)
	case slices.Equal(f.hops, vec):
	case compatible(f.hops, vec):
		// Only unknown hops were filled in (or dropped): same path.
		f.path = d.match(vec, ts)
	default:
		old := f.path
		f.path = d.match(vec, ts)
		if old != f.path {
			ttl, oldHop, newHop := divergence(f.hops, vec)
			s.events = append(s.events, PathEvent{
				Time:     ts,
				Flow:     f.key,
				FromPath: old.Index,
				ToPath:   f.path.Index,
				TTL:      ttl,
				OldHop:   oldHop,
				NewHop:   newHop,
				OldHops:  slices.Clone(f.hops),
				NewHops:  slices.Clone(vec),
			})
			if s.m != nil {
				s.m.pathChanges.WithLabelValues(f.key.labels()...).Inc()
				s.m.targetPathChanges.WithLabelValues(d.labels...).Inc()
			}
		}
	}
	f.path.LastSeen = ts
	f.hops = vec
}

// match returns the target's path entry for vec, registering a new one
// if needed. An existing entry that only differs in unknown hops is refined
// in place instead of creating a near-duplicate.
func (d *targetState) match(vec []string, ts time.Time) *pathEntry {
	for _, p := range d.paths {
		if slices.Equal(p.Hops, vec) {
			return p
		}
	}
	for _, p := range d.paths {
		if compatible(p.Hops, vec) {
			p.Hops = merge(p.Hops, vec)
			return p
		}
	}
	p := &pathEntry{Index: len(d.paths) + 1, Hops: slices.Clone(vec), FirstSeen: ts, LastSeen: ts}
	d.paths = append(d.paths, p)
	return p
}

func hopAt(v []string, i int) string {
	if i < len(v) {
		return v[i]
	}
	return unknownHop
}

// compatible reports whether a and b never disagree on a hop both know.
func compatible(a, b []string) bool {
	for i := range max(len(a), len(b)) {
		x, y := hopAt(a, i), hopAt(b, i)
		if x != unknownHop && y != unknownHop && x != y {
			return false
		}
	}
	return true
}

func merge(a, b []string) []string {
	out := make([]string, max(len(a), len(b)))
	for i := range out {
		if y := hopAt(b, i); y != unknownHop {
			out[i] = y
		} else {
			out[i] = hopAt(a, i)
		}
	}
	return out
}

// divergence returns the first TTL at which two paths disagree: the first
// conflicting pair of known hops, moved back over any unknown hops in front
// of it to the point where the paths were last identical. A hop inserted in
// front of a silent one thus diverges at the inserted hop.
func divergence(a, b []string) (uint8, string, string) {
	n := max(len(a), len(b))
	for i := range n {
		x, y := hopAt(a, i), hopAt(b, i)
		if x != unknownHop && y != unknownHop && x != y {
			for i > 0 && hopAt(a, i-1) != hopAt(b, i-1) {
				i--
			}
			return uint8(i + 1), hopAt(a, i), hopAt(b, i)
		}
	}
	for i := range n {
		if x, y := hopAt(a, i), hopAt(b, i); x != y {
			return uint8(i + 1), x, y
		}
	}
	return 0, "", ""
}

func (s *Store) updateMetrics(f *flowState, pr *ProbeRun, obs []hopObs, hopCount int, live bool) {
	if s.m == nil {
		return
	}
	fl := f.key.labels()
	s.m.pathIndex.WithLabelValues(fl...).Set(float64(f.path.Index))
	s.m.hopCount.WithLabelValues(fl...).Set(float64(hopCount))
	s.m.lastProbe.WithLabelValues(fl...).Set(float64(pr.Timestamp.UnixMilli()) / 1000)

	if live {
		s.m.runs.WithLabelValues(fl...).Inc()
		s.m.reached.WithLabelValues(fl...).Add(0)
		s.m.pathChanges.WithLabelValues(fl...).Add(0)
	}
	if pr.ReachedDest && len(obs) > 0 {
		rtt := float64(obs[len(obs)-1].RTT) / 1e6
		if live {
			s.m.reached.WithLabelValues(fl...).Inc()
			s.m.destRTT.WithLabelValues(fl...).Observe(rtt)
		}
		if f.hasDest {
			f.destJitter += (abs(rtt-f.destPrev) - f.destJitter) / 16
			s.m.destJitter.WithLabelValues(fl...).Set(f.destJitter)
		}
		f.destPrev, f.hasDest = rtt, true
	}

	for _, o := range obs {
		ip := o.IP
		if ip == "" {
			ip = unknownHop
		}
		hl := f.key.hopLabels(o.TTL, ip)
		if live {
			s.m.hopSent.WithLabelValues(hl...).Inc()
			s.m.hopRecv.WithLabelValues(hl...).Add(0)
		}
		if o.Lost {
			continue
		}
		rtt := float64(o.RTT) / 1e6
		if live {
			s.m.hopRecv.WithLabelValues(hl...).Inc()
			s.m.hopRTT.WithLabelValues(hl...).Observe(rtt)
		}
		if prevIP, ok := f.jitterIP[o.TTL]; ok && prevIP != ip {
			s.m.hopJitter.DeleteLabelValues(f.key.hopLabels(o.TTL, prevIP)...)
			delete(f.prevRTT, o.TTL)
			f.jitter[o.TTL] = 0
		}
		f.jitterIP[o.TTL] = ip
		if prev, ok := f.prevRTT[o.TTL]; ok {
			f.jitter[o.TTL] += (abs(rtt-prev) - f.jitter[o.TTL]) / 16
			s.m.hopJitter.WithLabelValues(hl...).Set(f.jitter[o.TTL])
		}
		f.prevRTT[o.TTL] = rtt
	}
}

func (s *Store) updateActivePaths(t Target) {
	if s.m == nil {
		return
	}
	seen := map[int]bool{}
	for _, f := range s.flows {
		if f.key.target() == t && !f.expired && f.path != nil {
			seen[f.path.Index] = true
		}
	}
	s.m.distinctPaths.WithLabelValues(t.Source, t.Destination).Set(float64(len(seen)))
	s.m.targetPaths.WithLabelValues(s.target(t).labels...).Set(float64(len(seen)))
}

// updateFleetMetrics feeds the per-target and per-transit-hop aggregates.
func (s *Store) updateFleetMetrics(t *targetState, key FlowKey, pr *ProbeRun, obs []hopObs, live bool) {
	site := t.labels[1]
	seen := map[string]bool{}
	for _, o := range obs {
		if o.IP == "" || o.IP == key.Destination || seen[o.IP] {
			continue
		}
		seen[o.IP] = true
		tk := transitKey{site, o.IP}
		if s.transit[tk] == nil {
			s.transit[tk] = map[Target]time.Time{}
		}
		s.transit[tk][key.target()] = pr.Timestamp
	}
	if s.m == nil || !live {
		return
	}
	s.m.targetProbes.WithLabelValues(t.labels...).Inc()
	s.m.targetReached.WithLabelValues(t.labels...).Add(0)
	s.m.targetPathChanges.WithLabelValues(t.labels...).Add(0)
	if pr.ReachedDest && len(obs) > 0 {
		s.m.targetReached.WithLabelValues(t.labels...).Inc()
		s.m.targetRTT.WithLabelValues(t.labels...).Observe(float64(obs[len(obs)-1].RTT) / 1e6)
	}
	for ip := range seen {
		s.m.transitProbes.WithLabelValues(site, ip).Inc()
		s.m.transitReached.WithLabelValues(site, ip).Add(0)
		if pr.ReachedDest {
			s.m.transitReached.WithLabelValues(site, ip).Inc()
		}
	}
}

// updateTransitTargets counts, per site and hop, the targets whose paths
// crossed the hop recently.
func (s *Store) updateTransitTargets(now time.Time) {
	for tk, targets := range s.transit {
		for t, ts := range targets {
			if now.Sub(ts) >= s.stale {
				delete(targets, t)
			}
		}
		if len(targets) == 0 {
			delete(s.transit, tk)
			if s.m != nil {
				s.m.transitTargets.DeleteLabelValues(tk.site, tk.hop)
			}
			continue
		}
		if s.m != nil {
			s.m.transitTargets.WithLabelValues(tk.site, tk.hop).Set(float64(len(targets)))
		}
	}
}

// Expire drops gauges for flows that have gone quiet, so stopped etr runs do
// not leave stale "current path" series behind. Counters are kept.
func (s *Store) Expire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	targets := map[Target]bool{}
	for _, f := range s.flows {
		if f.expired || now.Sub(f.lastSeen) < s.stale {
			continue
		}
		f.expired = true
		targets[f.key.target()] = true
		if s.m == nil {
			continue
		}
		fl := f.key.labels()
		s.m.pathIndex.DeleteLabelValues(fl...)
		s.m.hopCount.DeleteLabelValues(fl...)
		s.m.lastProbe.DeleteLabelValues(fl...)
		s.m.destJitter.DeleteLabelValues(fl...)
		for ttl, ip := range f.jitterIP {
			s.m.hopJitter.DeleteLabelValues(f.key.hopLabels(ttl, ip)...)
		}
		f.jitterIP = make(map[uint8]string)
		f.prevRTT = make(map[uint8]float64)
		f.hasDest = false
	}
	for t := range targets {
		s.updateActivePaths(t)
	}
	s.updateTransitTargets(now)
	s.prune(now)
}

func (s *Store) prune(now time.Time) {
	cutoff := now.Add(-s.retention)
	i := 0
	for i < len(s.records) && s.records[i].TS.Before(cutoff) {
		i++
	}
	// Reslice rather than copy: append reallocates (and drops the pruned
	// prefix) once capacity runs out, keeping this amortized O(1).
	s.records = s.records[i:]
	j := 0
	for j < len(s.events) && (s.events[j].Time.Before(cutoff) || len(s.events)-j > maxEvents) {
		j++
	}
	s.events = s.events[j:]
}

// assignNodes sets the graph node of each observation. Hops with no known
// IP become placeholders keyed by their predecessor, so silent hops on
// different branches stay separate.
func assignNodes(source string, obs []hopObs) {
	prev := sourceNodeID(source)
	for i := range obs {
		if obs[i].IP != "" {
			obs[i].Node = obs[i].IP
		} else {
			obs[i].Node = placeholderID(obs[i].TTL, prev)
		}
		prev = obs[i].Node
	}
}

// backfill attributes earlier timeouts of a flow at ttl to ip, the first IP
// that answered there. Otherwise a reply lost before the flow ever heard from
// a hop would leave a phantom "*" node in the graph.
func (s *Store) backfill(flow FlowKey, pathIdx int, ttl uint8, ip string) {
	for i := len(s.records) - 1; i >= 0; i-- {
		r := &s.records[i]
		if r.Flow != flow {
			continue
		}
		if r.PathIdx != pathIdx {
			return
		}
		changed := false
		for j := range r.Hops {
			if o := &r.Hops[j]; o.TTL == ttl {
				if o.IP != "" {
					return
				}
				o.IP = ip
				changed = true
			}
		}
		if changed {
			assignNodes(r.Flow.Source, r.Hops)
		}
	}
}

func sourceNodeID(ip string) string { return "src:" + ip }

func placeholderID(ttl uint8, prev string) string {
	return "*:" + strconv.Itoa(int(ttl)) + ":" + prev
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
