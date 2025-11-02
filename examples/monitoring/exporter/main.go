package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type HopRun struct {
	TTL      uint8     `json:"ttl"`
	IP       string    `json:"ip"`
	RTT      int64     `json:"rtt"`       // RTT in microseconds
	Timeout  bool      `json:"timeout"`   // Whether this hop timed out
	PTR      string    `json:"ptr"`       // PTR record for this IP
	RecvTime time.Time `json:"recv_time"` // When response was received
}

type ProbeRun struct {
	ProbeID         uint16    `json:"probe_id"`
	ProbeNum        uint      `json:"probe_num"`
	PathHash        string    `json:"path_hash"`
	SourceIP        string    `json:"source_ip"`
	SourcePort      uint16    `json:"source_port"`
	DestinationIP   string    `json:"destination_ip"`
	DestinationPort uint16    `json:"destination_port"` // Destination port
	DestinationPTR  string    `json:"destination_ptr"`  // PTR record for destination
	Protocol        string    `json:"protocol"`         // Protocol (TCP/UDP)
	ReachedDest     bool      `json:"reached_dest"`
	Hops            []*HopRun `json:"hops"`
	Timestamp       time.Time `json:"timestamp"`
}

type Metrics struct {
	hopRTT             *prometheus.GaugeVec
	hopTimeout         *prometheus.GaugeVec
	pathChanges        *prometheus.CounterVec
	destinationReached *prometheus.GaugeVec
	probesTotal        *prometheus.CounterVec
	lastProbeTime      *prometheus.GaugeVec

	mu           sync.RWMutex
	lastPathHash map[string]string // destination -> path_hash
}

func NewMetrics() *Metrics {
	m := &Metrics{
		hopRTT: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "etr_hop_rtt_ms",
				Help: "Round-trip time to each hop in milliseconds",
			},
			[]string{"destination", "destination_ptr", "ttl", "hop_ip", "hop_ptr", "protocol", "path_hash"},
		),
		hopTimeout: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "etr_hop_timeout",
				Help: "Whether a hop timed out (1 = timeout, 0 = response)",
			},
			[]string{"destination", "destination_ptr", "ttl", "protocol", "path_hash"},
		),
		pathChanges: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "etr_path_changes_total",
				Help: "Total number of path changes detected",
			},
			[]string{"destination", "destination_ptr", "protocol"},
		),
		destinationReached: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "etr_destination_reached",
				Help: "Whether the destination was reached (1 = yes, 0 = no)",
			},
			[]string{"destination", "destination_ptr", "protocol", "path_hash"},
		),
		probesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "etr_probes_total",
				Help: "Total number of probes sent",
			},
			[]string{"destination", "destination_ptr", "protocol"},
		),
		lastProbeTime: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "etr_last_probe_timestamp",
				Help: "Timestamp of the last probe",
			},
			[]string{"destination", "destination_ptr", "protocol", "path_hash"},
		),
		lastPathHash: make(map[string]string),
	}

	prometheus.MustRegister(m.hopRTT)
	prometheus.MustRegister(m.hopTimeout)
	prometheus.MustRegister(m.pathChanges)
	prometheus.MustRegister(m.destinationReached)
	prometheus.MustRegister(m.probesTotal)
	prometheus.MustRegister(m.lastProbeTime)

	return m
}

func (m *Metrics) ProcessProbeRun(pr *ProbeRun) {
	destKey := pr.DestinationIP
	destPTR := pr.DestinationPTR
	protocol := pr.Protocol
	pathHash := pr.PathHash

	// Update probe counter
	m.probesTotal.WithLabelValues(pr.DestinationIP, destPTR, protocol).Inc()

	// Update last probe time
	m.lastProbeTime.WithLabelValues(pr.DestinationIP, destPTR, protocol, pathHash).Set(float64(pr.Timestamp.Unix()))

	// Update destination reached
	reachedValue := 0.0
	if pr.ReachedDest {
		reachedValue = 1.0
	}
	m.destinationReached.WithLabelValues(pr.DestinationIP, destPTR, protocol, pathHash).Set(reachedValue)

	// Check for path changes
	m.mu.Lock()
	lastHash, exists := m.lastPathHash[destKey]
	if exists && lastHash != pr.PathHash {
		m.pathChanges.WithLabelValues(pr.DestinationIP, destPTR, protocol).Inc()
	}
	m.lastPathHash[destKey] = pr.PathHash
	m.mu.Unlock()

	// Process each hop
	for _, hop := range pr.Hops {
		ttl := fmt.Sprintf("%d", hop.TTL)

		if hop.Timeout {
			m.hopTimeout.WithLabelValues(pr.DestinationIP, destPTR, ttl, protocol, pathHash).Set(1.0)
		} else {
			m.hopTimeout.WithLabelValues(pr.DestinationIP, destPTR, ttl, protocol, pathHash).Set(0.0)
			if hop.RTT > 0 {
				// Convert microseconds to milliseconds
				rttMs := float64(hop.RTT) / 1000.0
				m.hopRTT.WithLabelValues(pr.DestinationIP, destPTR, ttl, hop.IP, hop.PTR, protocol, pathHash).Set(rttMs)
			}
		}
	}
}

func watchJSONFile(filename string, metrics *Metrics) {
	for {
		file, err := os.Open(filename)
		if err != nil {
			log.Printf("Error opening file %s: %v (will retry)", filename, err)
			time.Sleep(5 * time.Second)
			continue
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var probeRun ProbeRun
			if err := json.Unmarshal(scanner.Bytes(), &probeRun); err != nil {
				log.Printf("Error parsing JSON: %v", err)
				continue
			}
			metrics.ProcessProbeRun(&probeRun)
		}

		if err := scanner.Err(); err != nil {
			log.Printf("Error reading file: %v", err)
		}

		file.Close()
		time.Sleep(1 * time.Second)
	}
}

func main() {
	metrics := NewMetrics()

	// Watch the JSON file
	jsonFile := os.Getenv("ETR_JSON_FILE")
	if jsonFile == "" {
		jsonFile = "/data/etr.json"
	}

	go watchJSONFile(jsonFile, metrics)

	// Expose metrics
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Println("ETR Exporter listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
