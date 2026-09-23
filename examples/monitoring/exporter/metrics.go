package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

var (
	flowLabels = []string{"source", "destination", "protocol", "dst_port", "src_port"}
	hopLabels  = append(append([]string{}, flowLabels...), "ttl", "hop_ip")

	// 0.25ms .. ~8s
	rttBuckets = prometheus.ExponentialBuckets(0.00025, 2, 16)
)

// Metrics holds every Prometheus collector exposed by the exporter.
type Metrics struct {
	runs          *prometheus.CounterVec
	reached       *prometheus.CounterVec
	destRTT       *prometheus.HistogramVec
	destJitter    *prometheus.GaugeVec
	pathIndex     *prometheus.GaugeVec
	pathChanges   *prometheus.CounterVec
	hopCount      *prometheus.GaugeVec
	lastProbe     *prometheus.GaugeVec
	distinctPaths *prometheus.GaugeVec
	destInfo      *prometheus.GaugeVec

	hopSent    *prometheus.CounterVec
	hopRecv    *prometheus.CounterVec
	hopRTT     *prometheus.HistogramVec
	hopJitter  *prometheus.GaugeVec
	hopInfo    *prometheus.GaugeVec
	parseError prometheus.Counter
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		runs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "etr_probe_runs_total",
			Help: "Completed probe iterations per flow.",
		}, flowLabels),
		reached: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "etr_destination_reached_total",
			Help: "Probe iterations per flow that got a reply from the destination.",
		}, flowLabels),
		destRTT: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "etr_destination_rtt_seconds",
			Help:    "End-to-end round-trip time per flow.",
			Buckets: rttBuckets,
		}, flowLabels),
		destJitter: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "etr_destination_jitter_seconds",
			Help: "Smoothed end-to-end RTT variation per flow (RFC 3550 style).",
		}, flowLabels),
		pathIndex: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "etr_flow_path_index",
			Help: "Index (#N) of the path currently used by the flow. Paths are numbered per target (source → destination) in order of discovery.",
		}, flowLabels),
		pathChanges: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "etr_flow_path_changes_total",
			Help: "Number of times the flow moved to a different path.",
		}, flowLabels),
		hopCount: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "etr_flow_hops",
			Help: "Number of hops in the flow's current path.",
		}, flowLabels),
		lastProbe: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "etr_flow_last_probe_timestamp_seconds",
			Help: "Unix timestamp of the flow's most recent probe iteration.",
		}, flowLabels),
		distinctPaths: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "etr_destination_active_paths",
			Help: "Number of distinct paths currently used by the flows of a target (source → destination).",
		}, []string{"source", "destination"}),
		destInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "etr_destination_info",
			Help: "Destination metadata (always 1).",
		}, []string{"destination", "destination_ptr", "destination_asn"}),

		hopSent: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "etr_hop_sent_total",
			Help: "Probes sent per flow and TTL. Timeouts are attributed to the last hop IP seen at that TTL for the flow (or \"*\").",
		}, hopLabels),
		hopRecv: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "etr_hop_received_total",
			Help: "Replies received per flow, TTL and hop IP.",
		}, hopLabels),
		hopRTT: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "etr_hop_rtt_seconds",
			Help:    "Round-trip time to each hop per flow.",
			Buckets: rttBuckets,
		}, hopLabels),
		hopJitter: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "etr_hop_jitter_seconds",
			Help: "Smoothed RTT variation per flow and hop (RFC 3550 style).",
		}, hopLabels),
		hopInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "etr_hop_info",
			Help: "Hop metadata (always 1).",
		}, []string{"hop_ip", "hop_ptr", "hop_asn"}),
		parseError: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "etr_exporter_parse_errors_total",
			Help: "Input lines that could not be parsed.",
		}),
	}

	reg.MustRegister(
		m.runs, m.reached, m.destRTT, m.destJitter, m.pathIndex, m.pathChanges,
		m.hopCount, m.lastProbe, m.distinctPaths, m.destInfo,
		m.hopSent, m.hopRecv, m.hopRTT, m.hopJitter, m.hopInfo, m.parseError,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}
