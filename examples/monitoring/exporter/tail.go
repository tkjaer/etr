package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Watcher follows every file matching a glob pattern, like `tail -F`: it
// picks up new files, reads appended lines, and starts over when a file is
// truncated or replaced (etr truncates its -j file on start).
type Watcher struct {
	pattern  string
	store    *Store
	poll     time.Duration
	rescan   time.Duration
	mu       sync.Mutex
	watching map[string]bool
}

func NewWatcher(pattern string, store *Store) *Watcher {
	return &Watcher{
		pattern:  pattern,
		store:    store,
		poll:     250 * time.Millisecond,
		rescan:   2 * time.Second,
		watching: make(map[string]bool),
	}
}

func (w *Watcher) Run(ctx context.Context) {
	if _, err := filepath.Match(w.pattern, ""); err != nil {
		log.Fatalf("invalid input pattern %q: %v", w.pattern, err)
	}
	warned := false
	for {
		matches, _ := filepath.Glob(w.pattern)
		if len(matches) == 0 && !warned {
			log.Printf("waiting for files matching %s", w.pattern)
			warned = true
		}
		for _, m := range matches {
			w.mu.Lock()
			if !w.watching[m] {
				w.watching[m] = true
				log.Printf("following %s", m)
				go w.follow(ctx, m)
			}
			w.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(w.rescan):
		}
	}
}

func (w *Watcher) follow(ctx context.Context, path string) {
	defer func() {
		w.mu.Lock()
		delete(w.watching, path)
		w.mu.Unlock()
	}()
	for {
		err := w.followOnce(ctx, path)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("%s removed, no longer following", path)
			return
		}
		if err != nil {
			log.Printf("%s: %v (reopening)", path, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(w.poll):
		}
	}
}

// followOnce reads path until it is truncated, replaced, or removed.
func (w *Watcher) followOnce(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}

	r := bufio.NewReaderSize(f, 64*1024)
	var partial []byte
	var offset int64
	for {
		line, err := r.ReadBytes('\n')
		offset += int64(len(line))
		if err == nil {
			if len(partial) > 0 {
				line = append(partial, line...)
				partial = nil
			}
			w.handleLine(line)
			continue
		}
		if !errors.Is(err, io.EOF) {
			return err
		}
		// Keep an incomplete trailing line until the writer finishes it.
		partial = append(partial, line...)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(w.poll):
		}

		cur, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !os.SameFile(info, cur) {
			return errors.New("file replaced")
		}
		if cur.Size() < offset {
			return errors.New("file truncated")
		}
	}
}

func (w *Watcher) handleLine(line []byte) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return
	}
	var pr ProbeRun
	if err := json.Unmarshal(line, &pr); err != nil {
		if w.store.m != nil {
			w.store.m.parseError.Inc()
		}
		return
	}
	w.store.Process(&pr)
}
