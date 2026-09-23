package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func line(t *testing.T, pr *ProbeRun) string {
	t.Helper()
	b, err := json.Marshal(pr)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestWatcherFollowsAppendsPartialLinesAndTruncation(t *testing.T) {
	s := newTestStore(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "etr.json")
	if err := os.WriteFile(path, []byte(line(t, run(50000, 0, "10.0.0.1", dst))), 0o644); err != nil {
		t.Fatal(err)
	}

	w := NewWatcher(filepath.Join(dir, "*.json"), s)
	w.poll, w.rescan = 10*time.Millisecond, 10*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	runs := func() float64 { return testutil.ToFloat64(s.m.runs.WithLabelValues(flowLabelsFor("50000")...)) }
	waitFor(t, "existing line", func() bool { return runs() == 1 })

	// A line written in two pieces is only processed once complete.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	l := line(t, run(50000, 1, "10.0.0.1", dst))
	_, _ = f.WriteString(l[:20])
	time.Sleep(50 * time.Millisecond)
	if runs() != 1 {
		t.Fatal("partial line was processed")
	}
	_, _ = f.WriteString(l[20:])
	f.Close()
	waitFor(t, "completed line", func() bool { return runs() == 2 })

	// etr truncates its output file when restarted.
	if err := os.WriteFile(path, []byte(line(t, run(50000, 5, "10.0.0.1", dst))), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "line after truncation", func() bool { return runs() == 3 })

	// New files matching the pattern are picked up.
	other := run(50001, 6, "10.0.0.1", dst)
	if err := os.WriteFile(filepath.Join(dir, "second.json"), []byte(line(t, other)), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "second file", func() bool {
		return testutil.ToFloat64(s.m.runs.WithLabelValues(flowLabelsFor("50001")...)) == 1
	})
}
