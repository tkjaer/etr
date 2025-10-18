package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
)

// JSONOutput writes probe summary to a file or stdout when complete
type JSONOutput struct {
	mu       sync.Mutex
	file     *os.File
	enc      *json.Encoder
	toStdout bool
}

func NewJSONOutput(filename string) (*JSONOutput, error) {
	if filename == "" {
		// Output to stdout
		return &JSONOutput{
			file:     os.Stdout,
			enc:      json.NewEncoder(os.Stdout),
			toStdout: true,
		}, nil
	}
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	return &JSONOutput{
		file:     f,
		enc:      json.NewEncoder(f),
		toStdout: false,
	}, nil
}

func (j *JSONOutput) UpdateHop(probeID uint16, ttl uint8, hopStats HopStats) {
	// No-op for JSON, only output on complete
}

func (j *JSONOutput) CompleteProbe(probeID uint16, stats ProbeStats) {
	j.mu.Lock()
	defer j.mu.Unlock()
	// Compute path hash
	path := getProbePath(stats)
	hash := sha256.Sum256([]byte(path))
	hashStr := hex.EncodeToString(hash[:])

	// Prepare output struct
	out := struct {
		ProbeID  uint16     `json:"probe_id"`
		PathHash string     `json:"path_hash"`
		Stats    ProbeStats `json:"stats"`
	}{
		ProbeID:  probeID,
		PathHash: hashStr,
		Stats:    stats,
	}

	_ = j.enc.Encode(out)
}

func (j *JSONOutput) Close() error {
	if j.toStdout {
		return nil
	}
	return j.file.Close()
}
