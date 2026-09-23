package main

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"time"
)

// recentWindow is the span the target status (and the "now" columns) is
// based on, so an incident an hour ago does not mark a target as degraded.
const recentWindow = time.Minute

type targetRow struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Name        string `json:"name"`
	ASN         string `json:"asn"`
	Status      string `json:"status"`
	Flows       int    `json:"flows"`
	PathsNow    int    `json:"paths_now"`
	PathsSeen   int    `json:"paths_seen"`
	Changes     int    `json:"path_changes"`
	LastChange  *int64 `json:"last_change"`
	LossNow     optNum `json:"loss_now_pct"`
	RTTNow      optNum `json:"rtt_now_ms"`
	Loss        optNum `json:"loss_pct"`
	Avg         optNum `json:"avg_ms"`
	P95         optNum `json:"p95_ms"`
	Jitter      optNum `json:"jitter_ms"`
	LastSeen    int64  `json:"last_seen"`
}

// targetRows summarizes every target (source → destination) for the
// overview dashboard.
func (s *Store) targetRows(q query) []targetRow {
	recs := s.window(q)
	last := s.lastPerFlow(recs, q)
	recentFrom := q.to.Add(-recentWindow)

	type acc struct {
		all, recent stats
		paths       map[int]bool
		lastSeen    time.Time
	}
	byTarget := map[Target]*acc{}
	jt := jitterTracker{}
	for _, r := range recs {
		t := r.Flow.target()
		a := byTarget[t]
		if a == nil {
			a = &acc{paths: map[int]bool{}}
			byTarget[t] = a
		}
		a.paths[r.PathIdx] = true
		a.lastSeen = maxTime(a.lastSeen, r.TS)
		o := hopObs{Lost: true}
		if n := len(r.Hops); n > 0 {
			o = r.Hops[n-1]
			o.Lost = !r.Reached
		}
		a.all.add(&o)
		jt.observe(&a.all, fmt.Sprint(r.Flow), &o)
		if !r.TS.Before(recentFrom) {
			a.recent.add(&o)
		}
	}

	flowsNow := map[Target]int{}
	pathsNow := map[Target]map[int]bool{}
	for fk, r := range last {
		t := fk.target()
		flowsNow[t]++
		if pathsNow[t] == nil {
			pathsNow[t] = map[int]bool{}
		}
		pathsNow[t][r.PathIdx] = true
	}
	changes := map[Target]int{}
	lastChange := map[Target]int64{}
	for _, e := range s.events {
		if e.Time.Before(q.from) || e.Time.After(q.to) || !q.matchFlow(e.Flow) {
			continue
		}
		t := e.Flow.target()
		changes[t]++
		lastChange[t] = max(lastChange[t], e.Time.UnixMilli())
	}

	out := make([]targetRow, 0, len(byTarget))
	for t, a := range byTarget {
		row := targetRow{
			Source:      t.Source,
			Destination: t.Destination,
			Status:      targetStatus(flowsNow[t], &a.recent),
			Flows:       flowsNow[t],
			PathsNow:    len(pathsNow[t]),
			PathsSeen:   len(a.paths),
			Changes:     changes[t],
			LossNow:     lossPct(&a.recent),
			RTTNow:      optNum(a.recent.avg()),
			Loss:        lossPct(&a.all),
			Avg:         optNum(a.all.avg()),
			P95:         optNum(a.all.quantile(0.95)),
			Jitter:      optNum(a.all.jitter()),
			LastSeen:    a.lastSeen.UnixMilli(),
		}
		if d := s.dests[t.Destination]; d != nil {
			row.Name, row.ASN = d.ptr, d.asn
		}
		if lc, ok := lastChange[t]; ok {
			row.LastChange = &lc
		}
		out = append(out, row)
	}
	slices.SortFunc(out, func(a, b targetRow) int {
		return cmp.Or(cmp.Compare(a.Source, b.Source), cmp.Compare(a.Destination, b.Destination))
	})
	return out
}

func targetStatus(activeFlows int, recent *stats) string {
	switch {
	case activeFlows == 0 || recent.sent == 0:
		return "stopped"
	case recent.loss() >= 0.5:
		return "down"
	case recent.loss() >= warnLoss:
		return "degraded"
	default:
		return "ok"
	}
}

func lossPct(st *stats) optNum {
	if st.sent == 0 {
		return optNum(math.NaN())
	}
	return optNum(st.loss() * 100)
}
