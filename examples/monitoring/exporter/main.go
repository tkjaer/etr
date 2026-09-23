// Command etr-exporter follows etr's JSON output and exposes it as
// Prometheus metrics plus a small JSON API used by the Grafana dashboard's
// topology, path and event panels.
//
//	etr-exporter [-input '/data/*.json'] [-listen :8080]
//	etr-exporter demo [-out /data/demo.json]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(os.Args) > 1 && os.Args[1] == "demo" {
		if err := runDemo(ctx, os.Args[2:]); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatal(err)
		}
		return
	}

	fs := flag.NewFlagSet("etr-exporter", flag.ExitOnError)
	input := fs.String("input", env("ETR_JSON_FILE", "/data/*.json"), "etr JSON file or glob to follow (env ETR_JSON_FILE)")
	listen := fs.String("listen", env("ETR_LISTEN", ":8080"), "HTTP listen address (env ETR_LISTEN)")
	retention := fs.Duration("retention", envDuration("ETR_RETENTION", time.Hour), "how much probe history the JSON API keeps in memory (env ETR_RETENTION)")
	stale := fs.Duration("stale", envDuration("ETR_STALE", 2*time.Minute), "flows silent for this long are considered stopped (env ETR_STALE)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  etr-exporter [flags]\n  etr-exporter demo [flags]   write synthetic etr output\n\nFlags:\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(os.Args[1:])

	reg := prometheus.NewRegistry()
	store := NewStore(NewMetrics(reg), *retention, *stale)

	go NewWatcher(*input, store).Run(ctx)
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				store.Expire()
			}
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	mux.Handle("/api/", store.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Printf("etr-exporter listening on %s, following %s", *listen, *input)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		log.Printf("ignoring invalid %s=%q", key, v)
	}
	return def
}
