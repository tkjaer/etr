package main

import "time"

// HopRun mirrors a single hop in etr's per-iteration JSON output.
type HopRun struct {
	TTL      uint8     `json:"ttl"`
	IP       string    `json:"ip"`
	RTT      int64     `json:"rtt"` // microseconds
	Timeout  bool      `json:"timeout"`
	PTR      string    `json:"ptr"`
	ASN      string    `json:"asn"`
	RecvTime time.Time `json:"recv_time"`
}

// ProbeRun mirrors one line of etr's newline-delimited JSON output
// (one completed iteration of one parallel probe / flow).
type ProbeRun struct {
	ProbeID         uint16    `json:"probe_id"`
	ProbeNum        uint      `json:"probe_num"`
	PathHash        string    `json:"path_hash"`
	SourceIP        string    `json:"source_ip"`
	SourcePort      uint16    `json:"source_port"`
	DestinationIP   string    `json:"destination_ip"`
	DestinationPort uint16    `json:"destination_port"`
	DestinationPTR  string    `json:"destination_ptr"`
	DestinationASN  string    `json:"destination_asn"`
	Protocol        string    `json:"protocol"`
	ReachedDest     bool      `json:"reached_dest"`
	Hops            []*HopRun `json:"hops"`
	Timestamp       time.Time `json:"timestamp"`
}
