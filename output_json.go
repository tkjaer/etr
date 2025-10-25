package main

import (
	"encoding/json"
	"os"
	"sync"
)

// JSONOutput writes probe data to a file or stdout when complete
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
	// No-op for JSON, only output on complete run
}

func (j *JSONOutput) CompleteProbe(probeID uint16, stats ProbeStats) {
	// No-op for JSON, we use CompleteProbeRun instead
}

func (j *JSONOutput) CompleteProbeRun(run *ProbeRun) {
	j.mu.Lock()
	defer j.mu.Unlock()

	// Just output the run directly
	_ = j.enc.Encode(run)
}

func (j *JSONOutput) Close() error {
	if j.toStdout {
		return nil
	}
	return j.file.Close()
}
