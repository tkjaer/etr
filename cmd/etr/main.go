package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/tkjaer/etr/internal/config"
	"github.com/tkjaer/etr/internal/probe"
)

var errForcedExit = errors.New("second interrupt received")

func main() {
	if err := run(); err != nil {
		if errors.Is(err, config.ErrMissingDestination) {
			fmt.Fprintf(os.Stderr, "Error: destination is required\n\n")
			config.PrintShortUsage()
			os.Exit(2)
		}
		if errors.Is(err, errForcedExit) {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	args, err := config.ParseArgs()
	if err != nil {
		return err
	}

	if args.PrintBPFFilter {
		filter, err := probe.BuildBPFFilter(args)
		if err != nil {
			return err
		}
		fmt.Println(filter)
		return nil
	}

	logFile, err := config.SetupLogging(args)
	if err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}
	if logFile != nil {
		defer func() {
			if err := logFile.Close(); err != nil {
				slog.Error("Failed to close log file", "error", err)
			}
		}()
	}

	slog.Debug("Starting ECMP traceroute",
		"destination", args.Destination,
		"protocol", args.ProtocolName(),
		"parallel_probes", args.ParallelProbes,
	)

	pm, err := probe.NewProbeManager(args)
	if err != nil {
		return fmt.Errorf("failed to create probe manager: %w", err)
	}

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	done := make(chan error, 1)
	go func() {
		done <- pm.Run()
	}()

	runErr := waitForCompletion(pm, done, sigChan)

	if args.Discover {
		s := pm.GetDiscoverySummary()
		if s.Enabled {
			var flowStr string
			if s.FlowBudget == 0 {
				flowStr = fmt.Sprintf("%d/∞", s.FlowsUsed)
			} else {
				flowStr = fmt.Sprintf("%d/%d", s.FlowsUsed, s.FlowBudget)
			}
			if s.HopsMode {
				fmt.Fprintf(os.Stderr, "\nDiscovery complete: %d unique hop(s), %d path(s), %s flows, %d probes confirmed\n",
					s.UniqueHops, s.DistinctPaths, flowStr, s.ProbesConfirmed)
			} else {
				fmt.Fprintf(os.Stderr, "\nDiscovery complete: %d unique path(s), %s flows, %d probes confirmed\n",
					s.DistinctPaths, flowStr, s.ProbesConfirmed)
			}
			if s.StoppedByPortLimit {
				fmt.Fprintf(os.Stderr, "  WARNING: stopped by source port limit (65535). Use -s <lower port> for more range.\n")
			}
			for _, p := range s.Paths {
				hopStrs := make([]string, len(p.Hops))
				for i, h := range p.Hops {
					hopStrs[i] = h.IP
				}
				fmt.Fprintf(os.Stderr, "  path %s  src-port :%d  %s\n",
					p.PathHash, p.SourcePort, strings.Join(hopStrs, " → "))
			} // Write JSON summary to stdout (-J) or file (-j)
			if args.Json {
				_ = json.NewEncoder(os.Stdout).Encode(s)
			} else if args.JsonFile != "" {
				if f, err := os.OpenFile(args.JsonFile, os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
					_ = json.NewEncoder(f).Encode(s)
					_ = f.Close()
				}
			}
		}
	}

	return runErr
}

func waitForCompletion(pm *probe.ProbeManager, done <-chan error, sigChan <-chan os.Signal) error {
	select {
	case err := <-done:
		return finalize(err)
	case <-sigChan:
		slog.Debug("Received interrupt signal, stopping...")
		pm.Stop()
		select {
		case err := <-done:
			return finalize(err)
		case <-sigChan:
			slog.Warn("Second interrupt received, exiting immediately")
			return errForcedExit
		}
	}
}

func finalize(err error) error {
	if err == nil {
		slog.Debug("ECMP traceroute completed")
		return nil
	}
	slog.Error("Probe manager error", "error", err)
	return err
}
