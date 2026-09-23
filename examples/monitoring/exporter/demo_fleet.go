package main

import "fmt"

// The fleet scenario simulates a company WAN: six sites probe each other in
// a full mesh, and each site also probes two public SaaS destinations
// through its local internet breakout.
//
//	fra ─┐                    ┌─ tat1 ─┐
//	ams ─┼─ core.eu ──────────┤        ├─ core.us ─ nyc
//	lon ─┘      │             └─ tat2 ─┘     │
//	            └── sea1 ── core.ap ── tpc1 ──┘
//	                          ├─ sin
//	                          └─ syd (long backhaul)
//
// Traceroute shows the ingress interface of each router, so every WAN link
// appears as a different hop per direction. EU↔US flows are hashed over the
// two transatlantic links. The incident cycle degrades tat2, cuts tat1
// (reroute = path changes), adds loss on one site's internet breakout and
// congests another site's backhaul.

type fleetSite struct {
	n        int
	name     string
	region   string
	backhaul float64 // RTT between the site's PE and its region core
}

var fleetSites = []fleetSite{
	{1, "fra", "eu", 1}, {2, "ams", "eu", 3}, {3, "lon", "eu", 5},
	{4, "nyc", "us", 1}, {5, "sin", "ap", 1}, {6, "syd", "ap", 46},
}

func (s fleetSite) host() string { return fmt.Sprintf("10.%d.0.10", s.n) }
func (s fleetSite) ce() demoHop {
	return demoHop{ip: fmt.Sprintf("10.%d.0.1", s.n), ptr: "ce1." + s.name + ".corp.example", delay: 0.5}
}
func (s fleetSite) pe(ph demoPhase) demoHop {
	h := demoHop{ip: fmt.Sprintf("172.16.%d.1", s.n), ptr: "pe1." + s.name + ".wan.example", asn: "AS64600", delay: s.backhaul}
	if ph.sydCongestion && s.name == "syd" {
		h.delay += 60
		h.fwdLoss = 0.02
	}
	return h
}
func (s fleetSite) isp(ph demoPhase) demoHop {
	h := demoHop{ip: fmt.Sprintf("100.64.%d.1", s.n), ptr: "br1." + s.name + ".isp.example", asn: fmt.Sprintf("AS%d", 64510+s.n), delay: 2}
	if ph.sinISPLoss && s.name == "sin" {
		h.fwdLoss = 0.12
	}
	return h
}

var fleetRegions = map[string]int{"eu": 0, "us": 1, "ap": 2}

func fleetCore(region string) demoHop {
	return demoHop{ip: fmt.Sprintf("172.16.%d.1", 100+fleetRegions[region]), ptr: "core1." + region + ".wan.example", asn: "AS64600", delay: 1}
}

// fleetLink is the far-end interface of an inter-region link: the hop seen
// when crossing from region `from` to region `to`.
func fleetLink(name string, id int, delay float64, from, to string, ph demoPhase) demoHop {
	side := 1
	if fleetRegions[from] > fleetRegions[to] {
		side = 2
	}
	h := demoHop{ip: fmt.Sprintf("172.17.%d.%d", id, side), ptr: name + ".core1." + to + ".wan.example", asn: "AS64600", delay: delay}
	if ph.tat2Loss && name == "tat2" {
		h.delay += 20
		h.fwdLoss = 0.06
	}
	return h
}

func fleetWAN(a, b fleetSite, port uint16, ph demoPhase) []demoHop {
	path := []demoHop{a.ce(), a.pe(ph), fleetCore(a.region)}
	pair := map[string]bool{a.region: true, b.region: true}
	switch {
	case a.region == b.region:
	case pair["eu"] && pair["us"]:
		tat1 := fleetLink("tat1", 1, 72, a.region, b.region, ph)
		tat2 := fleetLink("tat2", 2, 75, a.region, b.region, ph)
		if ph.tat1Down {
			path = append(path, tat2)
		} else {
			path = append(path, pick(port, "tat", tat1, tat2))
		}
	case pair["eu"] && pair["ap"]:
		path = append(path, fleetLink("sea1", 3, 150, a.region, b.region, ph))
	default:
		path = append(path, fleetLink("tpc1", 4, 170, a.region, b.region, ph))
	}
	bce := b.ce()
	bce.delay = 0.5
	return append(path, b.pe(ph), bce, demoHop{ip: b.host(), ptr: "probe." + b.name + ".corp.example", delay: 0.3})
}

var (
	fleetWWW = demoHop{ip: demoDest, ptr: "www.example.com", asn: "AS64496", delay: 0.4}
	fleetAPI = demoHop{ip: "198.18.1.80", ptr: "api.saas.example", asn: "AS64497", delay: 0.6}
)

// Public targets: an anycast CDN served from a regional edge, and an API
// hosted in a single US region (far away for APAC sites).
func fleetPublic(a fleetSite, dest demoHop, port uint16, ph demoPhase) []demoHop {
	transit := demoHop{ip: fmt.Sprintf("198.51.100.%d", 129+4*fleetRegions[a.region]), ptr: "ae1." + a.region + ".tier1.example", asn: "AS64502", delay: 1.5}
	path := []demoHop{a.ce(), a.isp(ph), transit}
	if dest.ip == fleetWWW.ip {
		edge := demoHop{ip: fmt.Sprintf("203.0.113.%d", 9+8*fleetRegions[a.region]), ptr: "edge1." + a.region + ".cdn.example", asn: "AS64496", delay: 2}
		return append(path, edge, dest)
	}
	far := map[string]float64{"eu": 78, "us": 4, "ap": 175}[a.region]
	origin := demoHop{ip: "198.18.1.1", ptr: "gw.us-east.saas.example", asn: "AS64497", delay: far}
	lb := pick(port, "lb",
		demoHop{ip: "198.18.1.5", ptr: "lb1.us-east.saas.example", asn: "AS64497", delay: 0.5},
		demoHop{ip: "198.18.1.9", ptr: "lb2.us-east.saas.example", asn: "AS64497", delay: 0.5})
	return append(path, origin, lb, dest)
}

var fleetPhases = []demoPhase{
	{name: "normal", until: 2.0 / 12},
	{name: "tat2 degraded (+20 ms, 6% loss on EU↔US flows hashed onto it)", until: 5.0 / 12, tat2Loss: true},
	{name: "normal", until: 6.0 / 12},
	{name: "tat1 cut (EU↔US flows reroute via tat2)", until: 8.0 / 12, tat1Down: true},
	{name: "sin internet breakout loss (12%, public targets only)", until: 10.0 / 12, sinISPLoss: true},
	{name: "syd backhaul congestion (+60 ms, 2% loss)", until: 1, sydCongestion: true},
}

func fleetTargets(flows int) []demoTarget {
	var targets []demoTarget
	for _, a := range fleetSites {
		for _, b := range fleetSites {
			if a == b {
				continue
			}
			targets = append(targets, demoTarget{
				source: a.host(), dest: demoHop{ip: b.host(), ptr: "probe." + b.name + ".corp.example"}, flows: flows,
				path: func(port uint16, ph demoPhase) []demoHop { return fleetWAN(a, b, port, ph) },
			})
		}
		for _, d := range []demoHop{fleetWWW, fleetAPI} {
			targets = append(targets, demoTarget{
				source: a.host(), dest: d, flows: flows,
				path: func(port uint16, ph demoPhase) []demoHop { return fleetPublic(a, d, port, ph) },
			})
		}
	}
	return targets
}
