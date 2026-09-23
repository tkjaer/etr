package main

import (
	"cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"log"
	"math"
	"math/rand/v2"
	"os"
	"strings"
	"time"
)

// The demo writes synthetic etr output so the dashboards can be explored
// without root privileges or a real target. The "small" scenario traces three
// targets from two sources (the "fleet" scenario is in demo_fleet.go):
//
//	home → www:     gw ─ bras ─┬ core1 ┬─┬ border1 ┬─ * (silent IX) ─ edge1 ─ www
//	                           └ core2 ┘ └ border2 ┘
//	home → ns1:     gw ─ bras ─┬ core1 ┬─ transit1 ─ ns-edge ─ ns1
//	                           └ core2 ┘
//	office → www:   gw ─ pe1 ─┬ cr1 ┬─ edge2 ─ www
//	                          └ cr2 ┘
//
// Flows are spread over the ECMP branches by hashing the source port. A
// scripted cycle of incidents exercises every panel: congestion (latency +
// loss on one branch), a link outage shared by two targets (flows reroute =
// path changes), loss on another source's uplink, a detour (extra hop), and a
// router that constantly rate-limits ICMP (loss that is not real).

type demoHop struct {
	ip, ptr, asn string
	delay        float64 // one-way-ish latency added by this hop, in ms of RTT
	icmpLoss     float64 // reply suppression at this hop only
	fwdLoss      float64 // loss added to this hop and everything behind it
	silent       bool
}

var (
	demoHome   = "192.168.1.10"
	demoOffice = "10.20.0.5"
	demoDest   = "203.0.113.50"
	demoNSDest = "198.18.0.53"

	hGW      = demoHop{ip: "192.168.1.1", ptr: "gw.home.lan", delay: 0.6}
	hBRAS    = demoHop{ip: "100.64.0.1", ptr: "bras1.isp.example", asn: "AS64500", delay: 4.4}
	hCore1   = demoHop{ip: "198.51.100.1", ptr: "core1.fra.isp.example", asn: "AS64500", delay: 3, icmpLoss: 0.15}
	hCore2   = demoHop{ip: "198.51.100.5", ptr: "core2.fra.isp.example", asn: "AS64500", delay: 3.6}
	hBorder1 = demoHop{ip: "198.51.100.33", ptr: "border1.ams.isp.example", asn: "AS64500", delay: 5}
	hBorder2 = demoHop{ip: "198.51.100.37", ptr: "border2.ams.isp.example", asn: "AS64500", delay: 5.2}
	hDetour  = demoHop{ip: "198.51.100.41", ptr: "detour1.ams.isp.example", asn: "AS64500", delay: 3}
	hIX      = demoHop{ip: "203.0.113.1", delay: 2, silent: true}
	hEdge    = demoHop{ip: "203.0.113.9", ptr: "edge1.cdn.example", asn: "AS64496", delay: 2}
	hDest    = demoHop{ip: demoDest, ptr: "www.example.com", asn: "AS64496", delay: 0.4}

	hTransit = demoHop{ip: "198.51.100.65", ptr: "transit1.fra.isp.example", asn: "AS64500", delay: 1.2}
	hNSEdge  = demoHop{ip: "198.18.0.1", ptr: "edge.ns.example.net", asn: "AS64499", delay: 1.5}
	hNSDest  = demoHop{ip: demoNSDest, ptr: "ns1.example.net", asn: "AS64499", delay: 0.3}

	hOfficeGW = demoHop{ip: "10.20.0.1", ptr: "gw.office.lan", delay: 0.4}
	hPE1      = demoHop{ip: "192.0.2.1", ptr: "pe1.isp2.example", asn: "AS64511", delay: 2.1}
	hCR1      = demoHop{ip: "192.0.2.5", ptr: "cr1.isp2.example", asn: "AS64511", delay: 6.5}
	hCR2      = demoHop{ip: "192.0.2.9", ptr: "cr2.isp2.example", asn: "AS64511", delay: 7.4}
	hEdge2    = demoHop{ip: "203.0.113.13", ptr: "edge2.cdn.example", asn: "AS64496", delay: 1.8}
)

type demoPhase struct {
	name       string
	until      float64 // fraction of the cycle
	congestion bool    // border2: +30 ms, 4% loss
	coreDown   bool    // core2 down: everything via core1
	officeLoss bool    // office uplink: 8% loss from pe1 on
	detour     bool    // border1 maintenance: extra hop

	// fleet scenario
	tat2Loss, tat1Down, sinISPLoss, sydCongestion bool
}

var demoPhases = []demoPhase{
	{name: "normal", until: 2.0 / 12},
	{name: "congestion on border2 (+30 ms, 4% loss)", until: 4.5 / 12, congestion: true},
	{name: "normal", until: 6.0 / 12},
	{name: "core2 outage (home flows reroute via core1)", until: 8.5 / 12, coreDown: true},
	{name: "office uplink loss (8% from pe1 on)", until: 10.0 / 12, officeLoss: true},
	{name: "border1 maintenance (detour, +1 hop)", until: 1, detour: true},
}

type demoTarget struct {
	source string
	dest   demoHop
	flows  int
	path   func(port uint16, ph demoPhase) []demoHop
}

func pick(port uint16, salt string, hops ...demoHop) demoHop {
	return hops[ecmp(port, salt, len(hops))]
}

func demoTargets(flows int) []demoTarget {
	homeCore := func(port uint16, ph demoPhase) demoHop {
		if ph.coreDown {
			return hCore1
		}
		return pick(port, "core", hCore1, hCore2)
	}
	return []demoTarget{
		{source: demoHome, dest: hDest, flows: flows, path: func(port uint16, ph demoPhase) []demoHop {
			border := pick(port, "border", hBorder1, hBorder2)
			if ph.congestion && border.ip == hBorder2.ip {
				border.delay += 30
				border.fwdLoss = 0.04
			}
			path := []demoHop{hGW, hBRAS, homeCore(port, ph), border}
			if ph.detour && border.ip == hBorder1.ip {
				path = append(path, hDetour)
			}
			return append(path, hIX, hEdge, hDest)
		}},
		{source: demoHome, dest: hNSDest, flows: 4, path: func(port uint16, ph demoPhase) []demoHop {
			return []demoHop{hGW, hBRAS, homeCore(port, ph), hTransit, hNSEdge, hNSDest}
		}},
		{source: demoOffice, dest: hDest, flows: 4, path: func(port uint16, ph demoPhase) []demoHop {
			pe := hPE1
			if ph.officeLoss {
				pe.fwdLoss = 0.08
			}
			return []demoHop{hOfficeGW, pe, pick(port, "cr", hCR1, hCR2), hEdge2, hDest}
		}},
	}
}

func runDemo(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	out := fs.String("out", "/data/demo.json", "file to write (truncated on start, like etr -j)")
	scenario := fs.String("scenario", "small", `"small" (3 targets, 2 sources) or "fleet" (6-site WAN mesh + public targets)`)
	interval := fs.Duration("interval", 0, "delay between probe iterations (default 1s small, 5s fleet)")
	flows := fs.Int("flows", 0, "parallel flows (etr -P) per target (default 8 towards the main small target, 2 fleet)")
	basePort := fs.Int("src-port", 50000, "base source port (etr -s)")
	cycle := fs.Duration("cycle", 12*time.Minute, "length of the scripted incident cycle")
	_ = fs.Parse(args)

	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	defer f.Close()

	var targets []demoTarget
	phases := demoPhases
	switch *scenario {
	case "small":
		targets = demoTargets(cmp.Or(*flows, 8))
		*interval = cmp.Or(*interval, time.Second)
	case "fleet":
		targets = fleetTargets(cmp.Or(*flows, 2))
		phases = fleetPhases
		*interval = cmp.Or(*interval, 5*time.Second)
	default:
		return fmt.Errorf("unknown scenario %q", *scenario)
	}
	start := time.Now()
	lastPhase := ""
	var num uint
	t := time.NewTicker(*interval)
	defer t.Stop()
	log.Printf("demo: writing %d targets to %s every %s (incident cycle %s)", len(targets), *out, *interval, *cycle)
	for {
		now := time.Now()
		pos := math.Mod(now.Sub(start).Seconds(), cycle.Seconds()) / cycle.Seconds()
		phase := phases[len(phases)-1]
		for _, p := range phases {
			if pos < p.until {
				phase = p
				break
			}
		}
		if phase.name != lastPhase {
			log.Printf("demo: %s", phase.name)
			lastPhase = phase.name
		}

		var buf strings.Builder
		var id uint16
		for _, tg := range targets {
			for i := range tg.flows {
				run := demoRun(tg, id, num, uint16(*basePort+i), phase, now)
				id++
				b, _ := json.Marshal(run)
				buf.Write(b)
				buf.WriteByte('\n')
			}
		}
		num++
		if _, err := f.WriteString(buf.String()); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// ecmp mimics a router's flow hash: stable per source port, spread across links.
func ecmp(port uint16, salt string, n int) int {
	h := fnv.New32a()
	fmt.Fprintf(h, "%d/%s", port, salt)
	v := h.Sum32()
	v ^= v >> 16
	v *= 0x45d9f3b
	v ^= v >> 16
	return int(v % uint32(n))
}

func demoRun(tg demoTarget, id uint16, num uint, port uint16, phase demoPhase, now time.Time) *ProbeRun {
	path := tg.path(port, phase)
	run := &ProbeRun{
		ProbeID:         id,
		ProbeNum:        num,
		SourceIP:        tg.source,
		SourcePort:      port,
		DestinationIP:   tg.dest.ip,
		DestinationPort: 443,
		DestinationPTR:  tg.dest.ptr,
		DestinationASN:  tg.dest.asn,
		Protocol:        "TCP",
		Timestamp:       now,
	}

	var ips []string
	cum, deliver := 0.0, 1.0
	for i, h := range path {
		cum += h.delay
		deliver *= 1 - h.fwdLoss
		hop := &HopRun{TTL: uint8(i + 1)}
		if h.silent || rand.Float64() > deliver*(1-h.icmpLoss) {
			hop.Timeout = true
		} else {
			rtt := cum*(1+rand.NormFloat64()*0.04) + rand.ExpFloat64()*0.3*math.Sqrt(cum)
			hop.IP, hop.PTR, hop.ASN = h.ip, h.ptr, h.asn
			hop.RTT = int64(math.Max(rtt, 0.05) * 1000)
			hop.RecvTime = now.Add(time.Duration(hop.RTT) * time.Microsecond)
			ips = append(ips, h.ip)
		}
		run.Hops = append(run.Hops, hop)
	}
	last := run.Hops[len(run.Hops)-1]
	run.ReachedDest = !last.Timeout && last.IP == tg.dest.ip
	run.PathHash = fmt.Sprintf("%08x", crc32.ChecksumIEEE([]byte(strings.Join(ips, "|")+"|")))
	return run
}
