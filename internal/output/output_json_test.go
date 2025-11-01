package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tkjaer/etr/internal/shared"
)

func TestNewJSONOutput_Stdout(t *testing.T) {
	output, err := NewJSONOutput("")
	if err != nil {
		t.Fatalf("NewJSONOutput() error = %v", err)
	}
	defer output.Close()

	if !output.toStdout {
		t.Error("NewJSONOutput(\"\") should output to stdout")
	}
	if output.file != os.Stdout {
		t.Error("NewJSONOutput(\"\") file should be os.Stdout")
	}
}

func TestNewJSONOutput_File(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "test_output.json")

	output, err := NewJSONOutput(filename)
	if err != nil {
		t.Fatalf("NewJSONOutput() error = %v", err)
	}
	defer output.Close()

	if output.toStdout {
		t.Error("NewJSONOutput() with filename should not output to stdout")
	}
	if output.file == os.Stdout {
		t.Error("NewJSONOutput() with filename should not use os.Stdout")
	}
	if output.file == nil {
		t.Error("NewJSONOutput() file should not be nil")
	}
}

func TestJSONOutput_CompleteProbeRun(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "test_run.json")

	output, err := NewJSONOutput(filename)
	if err != nil {
		t.Fatalf("NewJSONOutput() error = %v", err)
	}

	run := &shared.ProbeRun{
		ProbeID:       1,
		ProbeNum:      0,
		PathHash:      "abc123",
		SourceIP:      "198.51.100.1",
		DestinationIP: "203.0.113.1",
		Protocol:      "TCP",
		ReachedDest:   true,
	}

	output.CompleteProbeRun(run)
	output.Close()

	// Read and verify the JSON file
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var decoded shared.ProbeRun
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if decoded.ProbeID != 1 {
		t.Errorf("ProbeID = %d, want 1", decoded.ProbeID)
	}
	if decoded.PathHash != "abc123" {
		t.Errorf("PathHash = %s, want abc123", decoded.PathHash)
	}
	if decoded.SourceIP != "198.51.100.1" {
		t.Errorf("SourceIP = %s, want 198.51.100.1", decoded.SourceIP)
	}
}

func TestJSONOutput_Close_Stdout(t *testing.T) {
	output, err := NewJSONOutput("")
	if err != nil {
		t.Fatalf("NewJSONOutput() error = %v", err)
	}

	// Closing stdout output should not error
	if err := output.Close(); err != nil {
		t.Errorf("Close() for stdout error = %v, want nil", err)
	}
}

func TestJSONOutput_Close_File(t *testing.T) {
	tmpDir := t.TempDir()
	filename := filepath.Join(tmpDir, "test_close.json")

	output, err := NewJSONOutput(filename)
	if err != nil {
		t.Fatalf("NewJSONOutput() error = %v", err)
	}

	if err := output.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// File should be closed, writing should fail
	_, err = output.file.Write([]byte("test"))
	if err == nil {
		t.Error("Writing to closed file should error")
	}
}

func TestJSONOutput_NoOps(t *testing.T) {
	output, err := NewJSONOutput("")
	if err != nil {
		t.Fatalf("NewJSONOutput() error = %v", err)
	}
	defer output.Close()

	// These should all be no-ops and not panic
	output.UpdateHop(1, 1, shared.HopStats{})
	output.DeleteHops(1, []uint8{1, 2})
	output.CompleteProbe(1, shared.ProbeStats{})
}
