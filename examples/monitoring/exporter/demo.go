package main

import (
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

// The demo writes synthetic etr output for a small ECMP network so the
// dashboard can be explored without root privileges or a real target:
//
//	              ┌ core1 ┐   ┌ border1 ┐
//	gw ─ bras ────┤       ├───┤         ├── * (silent IX) ── edge ── www
//	              └ core2 ┘   └ border2 ┘
//
// Flows are spread over the four paths by hashing the source port. A scripted
// cycle of incidents exercises every panel: congestion (latency + loss on one
// branch), a link outage (flows reroute = path changes), a detour (extra hop),
// and a router that constantly rate-limits ICMP (loss that is not real).

type demoHop struct {
	ip, ptr, asn string
	delay        float64 // one-way-ish latency added by this hop, in ms of RTT
	icmpLoss     float64 // reply suppression at this hop only
	fwdLoss      float64 // loss added to this hop and everything behind it
	silent       bool
}

var (
	demoSource = "192.168.1.10"
	demoDest   = "203.0.113.50"

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
)

type demoPhase struct {
	name     string
	until    float64 // fraction of the cycle
	apply    func(core, border *demoHop, detour *bool)
	coreDown bool
}

var demoPhases = []demoPhase{
	{name: "normal", until: 2.0 / 12},
	{name: "congestion on border2 (+30 ms, 4% loss)", until: 4.5 / 12, apply: func(_, border *demoHop, _ *bool) {
		if border.ip == hBorder2.ip {
			border.delay += 30
			border.fwdLoss = 0.04
		}
	}},
	{name: "normal", until: 6.0 / 12},
	{name: "core2 outage (flows reroute via core1)", until: 8.5 / 12, coreDown: true},
	{name: "normal", until: 10.0 / 12},
	{name: "border1 maintenance (detour, +1 hop)", until: 1, apply: func(_, border *demoHop, detour *bool) {
		if border.ip == hBorder1.ip {
			*detour = true
		}
	}},
}

func runDemo(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	out := fs.String("out", "/data/demo.json", "file to write (truncated on start, like etr -j)")
	interval := fs.Duration("interval", time.Second, "delay between probe iterations")
	flows := fs.Int("flows", 8, "number of parallel flows (etr -P)")
	basePort := fs.Int("src-port", 50000, "base source port (etr -s)")
	cycle := fs.Duration("cycle", 12*time.Minute, "length of the scripted incident cycle")
	_ = fs.Parse(args)

	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	defer f.Close()

	start := time.Now()
	lastPhase := ""
	nums := make([]uint, *flows)
	t := time.NewTicker(*interval)
	defer t.Stop()
	log.Printf("demo: writing %d flows to %s every %s (incident cycle %s)", *flows, *out, *interval, *cycle)
	for {
		now := time.Now()
		pos := math.Mod(now.Sub(start).Seconds(), cycle.Seconds()) / cycle.Seconds()
		phase := demoPhases[len(demoPhases)-1]
		for _, p := range demoPhases {
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
		for i := range *flows {
			port := uint16(*basePort + i)
			run := demoRun(uint16(i), nums[i], port, phase, now)
			nums[i]++
			b, _ := json.Marshal(run)
			buf.Write(b)
			buf.WriteByte('\n')
		}
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

func demoRun(id uint16, num uint, port uint16, phase demoPhase, now time.Time) *ProbeRun {
	cores := []demoHop{hCore1, hCore2}
	borders := []demoHop{hBorder1, hBorder2}
	core := cores[ecmp(port, "core", 2)]
	if phase.coreDown {
		core = hCore1
	}
	border := borders[ecmp(port, "border", 2)]
	detour := false
	if phase.apply != nil {
		phase.apply(&core, &border, &detour)
	}

	path := []demoHop{hGW, hBRAS, core, border}
	if detour {
		path = append(path, hDetour)
	}
	path = append(path, hIX, hEdge, hDest)

	run := &ProbeRun{
		ProbeID:         id,
		ProbeNum:        num,
		SourceIP:        demoSource,
		SourcePort:      port,
		DestinationIP:   demoDest,
		DestinationPort: 443,
		DestinationPTR:  hDest.ptr,
		DestinationASN:  hDest.asn,
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
	run.ReachedDest = !last.Timeout && last.IP == demoDest
	run.PathHash = fmt.Sprintf("%08x", crc32.ChecksumIEEE([]byte(strings.Join(ips, "|")+"|")))
	return run
}
