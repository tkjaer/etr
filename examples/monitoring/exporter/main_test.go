package main

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestProcessProbeRun_RTTConversion(t *testing.T) {
	// Test that RTT is correctly converted from microseconds to milliseconds
	tests := []struct {
		name      string
		rttMicros int64
		wantRttMs float64
	}{
		{"1ms", 1000, 1.0},
		{"10ms", 10000, 10.0},
		{"0.5ms", 500, 0.5},
		{"100ms", 100000, 100.0},
		{"zero", 0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			m := newMetricsWithRegistry(registry)

			pr := &ProbeRun{
				DestinationIP:  "192.0.2.100",
				DestinationPTR: "test.example.com",
				Protocol:       "TCP",
				Timestamp:      time.Now(),
				PathHash:       "abc123",
				Hops: []*HopRun{
					{
						TTL:     1,
						IP:      "192.0.2.1",
						RTT:     tt.rttMicros,
						Timeout: false,
						PTR:     "router.example.com",
					},
				},
			}

			m.ProcessProbeRun(pr)

			// Verify the metric value if RTT > 0
			if tt.rttMicros > 0 {
				metricValue := testutil.ToFloat64(m.hopRTT.WithLabelValues(
					"192.0.2.100", "test.example.com", "1", "192.0.2.1", "router.example.com", "TCP", "abc123",
				))
				if metricValue != tt.wantRttMs {
					t.Errorf("RTT metric = %v, want %v", metricValue, tt.wantRttMs)
				}
			}
		})
	}
}

func TestProcessProbeRun_PathChangeDetection(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetricsWithRegistry(registry)

	destination := "192.0.2.100"
	destPTR := "test.example.com"
	protocol := "TCP"

	// First probe run
	pr1 := &ProbeRun{
		DestinationIP:  destination,
		DestinationPTR: destPTR,
		Protocol:       protocol,
		PathHash:       "hash1",
		Timestamp:      time.Now(),
		Hops:           []*HopRun{},
	}
	m.ProcessProbeRun(pr1)

	// Path changes counter should be 0 (first run)
	pathChanges := testutil.ToFloat64(m.pathChanges.WithLabelValues(destination, destPTR, protocol))
	if pathChanges != 0 {
		t.Errorf("Initial path changes = %v, want 0", pathChanges)
	}

	// Second probe run with same path
	pr2 := &ProbeRun{
		DestinationIP:  destination,
		DestinationPTR: destPTR,
		Protocol:       protocol,
		PathHash:       "hash1", // Same hash
		Timestamp:      time.Now(),
		Hops:           []*HopRun{},
	}
	m.ProcessProbeRun(pr2)

	// Path changes counter should still be 0 (same path)
	pathChanges = testutil.ToFloat64(m.pathChanges.WithLabelValues(destination, destPTR, protocol))
	if pathChanges != 0 {
		t.Errorf("Path changes after same hash = %v, want 0", pathChanges)
	}

	// Third probe run with different path
	pr3 := &ProbeRun{
		DestinationIP:  destination,
		DestinationPTR: destPTR,
		Protocol:       protocol,
		PathHash:       "hash2", // Different hash
		Timestamp:      time.Now(),
		Hops:           []*HopRun{},
	}
	m.ProcessProbeRun(pr3)

	// Path changes counter should be 1 (detected change)
	pathChanges = testutil.ToFloat64(m.pathChanges.WithLabelValues(destination, destPTR, protocol))
	if pathChanges != 1 {
		t.Errorf("Path changes after different hash = %v, want 1", pathChanges)
	}

	// Fourth probe run with another different path
	pr4 := &ProbeRun{
		DestinationIP:  destination,
		DestinationPTR: destPTR,
		Protocol:       protocol,
		PathHash:       "hash3", // Another different hash
		Timestamp:      time.Now(),
		Hops:           []*HopRun{},
	}
	m.ProcessProbeRun(pr4)

	// Path changes counter should be 2
	pathChanges = testutil.ToFloat64(m.pathChanges.WithLabelValues(destination, destPTR, protocol))
	if pathChanges != 2 {
		t.Errorf("Path changes after second different hash = %v, want 2", pathChanges)
	}
}

func TestProcessProbeRun_TimeoutHandling(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetricsWithRegistry(registry)

	pr := &ProbeRun{
		DestinationIP:  "192.0.2.100",
		DestinationPTR: "test.example.com",
		Protocol:       "TCP",
		Timestamp:      time.Now(),
		PathHash:       "abc123",
		Hops: []*HopRun{
			{
				TTL:     1,
				IP:      "",
				RTT:     0,
				Timeout: true,
			},
			{
				TTL:     2,
				IP:      "192.0.2.2",
				RTT:     5000,
				Timeout: false,
				PTR:     "router2.example.com",
			},
		},
	}

	m.ProcessProbeRun(pr)

	// Check timeout metric for hop 1 (should be 1.0)
	timeoutValue := testutil.ToFloat64(m.hopTimeout.WithLabelValues("192.0.2.100", "test.example.com", "1", "TCP", "abc123"))
	if timeoutValue != 1.0 {
		t.Errorf("Timeout hop metric = %v, want 1.0", timeoutValue)
	}

	// Check timeout metric for hop 2 (should be 0.0)
	timeoutValue = testutil.ToFloat64(m.hopTimeout.WithLabelValues("192.0.2.100", "test.example.com", "2", "TCP", "abc123"))
	if timeoutValue != 0.0 {
		t.Errorf("Non-timeout hop metric = %v, want 0.0", timeoutValue)
	}
}

func TestProcessProbeRun_DestinationReached(t *testing.T) {
	tests := []struct {
		name        string
		reachedDest bool
		wantMetric  float64
	}{
		{"destination reached", true, 1.0},
		{"destination not reached", false, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			m := newMetricsWithRegistry(registry)

			pr := &ProbeRun{
				DestinationIP:  "192.0.2.100",
				DestinationPTR: "test.example.com",
				Protocol:       "TCP",
				ReachedDest:    tt.reachedDest,
				Timestamp:      time.Now(),
				PathHash:       "abc123",
				Hops:           []*HopRun{},
			}

			m.ProcessProbeRun(pr)

			metricValue := testutil.ToFloat64(m.destinationReached.WithLabelValues("192.0.2.100", "test.example.com", "TCP", "abc123"))
			if metricValue != tt.wantMetric {
				t.Errorf("destinationReached metric = %v, want %v", metricValue, tt.wantMetric)
			}
		})
	}
}

func TestProcessProbeRun_ProbeCounter(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetricsWithRegistry(registry)

	destination := "192.0.2.100"
	destPTR := "test.example.com"
	protocol := "TCP"

	// Process 3 probe runs
	for i := 0; i < 3; i++ {
		pr := &ProbeRun{
			DestinationIP:  destination,
			DestinationPTR: destPTR,
			Protocol:       protocol,
			Timestamp:      time.Now(),
			PathHash:       "abc123",
			Hops:           []*HopRun{},
		}
		m.ProcessProbeRun(pr)
	}

	// Counter should be 3
	count := testutil.ToFloat64(m.probesTotal.WithLabelValues(destination, destPTR, protocol))
	if count != 3 {
		t.Errorf("probesTotal = %v, want 3", count)
	}
}

func TestProcessProbeRun_MultipleDestinations(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetricsWithRegistry(registry)

	// Process probe runs for two different destinations
	pr1 := &ProbeRun{
		DestinationIP:  "192.0.2.100",
		DestinationPTR: "test.example.com",
		Protocol:       "TCP",
		PathHash:       "hash1",
		Timestamp:      time.Now(),
		Hops:           []*HopRun{},
	}
	m.ProcessProbeRun(pr1)

	pr2 := &ProbeRun{
		DestinationIP:  "192.0.2.200",
		DestinationPTR: "test2.example.com",
		Protocol:       "UDP",
		PathHash:       "hash2",
		Timestamp:      time.Now(),
		Hops:           []*HopRun{},
	}
	m.ProcessProbeRun(pr2)

	// Verify both destinations are tracked separately
	count1 := testutil.ToFloat64(m.probesTotal.WithLabelValues("192.0.2.100", "test.example.com", "TCP"))
	count2 := testutil.ToFloat64(m.probesTotal.WithLabelValues("192.0.2.200", "test2.example.com", "UDP"))

	if count1 != 1 {
		t.Errorf("Destination 192.0.2.100 probes = %v, want 1", count1)
	}
	if count2 != 1 {
		t.Errorf("Destination 192.0.2.200 probes = %v, want 1", count2)
	}

	// Verify path hashes are tracked separately
	m.mu.RLock()
	if m.lastPathHash["192.0.2.100"] != "hash1" {
		t.Errorf("Path hash for 192.0.2.100 = %v, want hash1", m.lastPathHash["192.0.2.100"])
	}
	if m.lastPathHash["192.0.2.200"] != "hash2" {
		t.Errorf("Path hash for 192.0.2.200 = %v, want hash2", m.lastPathHash["192.0.2.200"])
	}
	m.mu.RUnlock()
}

// Helper function to create metrics with a custom registry for testing
func newMetricsWithRegistry(registry *prometheus.Registry) *Metrics {
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

	registry.MustRegister(m.hopRTT)
	registry.MustRegister(m.hopTimeout)
	registry.MustRegister(m.pathChanges)
	registry.MustRegister(m.destinationReached)
	registry.MustRegister(m.probesTotal)
	registry.MustRegister(m.lastProbeTime)

	return m
}
