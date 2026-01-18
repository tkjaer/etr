package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"

	"github.com/tkjaer/etr/internal/config"
	"github.com/tkjaer/etr/internal/probe"
)

var errForcedExit = errors.New("second interrupt received")

func main() {
	if err := run(); err != nil {
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

	if args.PprofAddr != "" {
		go func(addr string) {
			slog.Info("Starting pprof server", "addr", addr)
			if err := http.ListenAndServe(addr, nil); err != nil {
				slog.Error("pprof server error", "error", err)
			}
		}(args.PprofAddr)
	}

	var cpuProfileFile *os.File
	if args.CPUProfile != "" {
		cpuProfileFile, err = os.Create(args.CPUProfile)
		if err != nil {
			return fmt.Errorf("failed to create cpu profile: %w", err)
		}
		if err := pprof.StartCPUProfile(cpuProfileFile); err != nil {
			_ = cpuProfileFile.Close()
			return fmt.Errorf("failed to start cpu profile: %w", err)
		}
		defer func() {
			pprof.StopCPUProfile()
			if err := cpuProfileFile.Close(); err != nil {
				slog.Error("Failed to close cpu profile", "error", err)
			}
		}()
	}

	if args.MemProfile != "" {
		defer func(path string) {
			f, err := os.Create(path)
			if err != nil {
				slog.Error("Failed to create mem profile", "error", err)
				return
			}
			defer func() {
				if err := f.Close(); err != nil {
					slog.Error("Failed to close mem profile", "error", err)
				}
			}()
			runtime.GC()
			if err := pprof.WriteHeapProfile(f); err != nil {
				slog.Error("Failed to write mem profile", "error", err)
			}
		}(args.MemProfile)
	}

	if args.MutexProfileFraction > 0 {
		runtime.SetMutexProfileFraction(args.MutexProfileFraction)
	}
	if args.BlockProfileRate > 0 {
		runtime.SetBlockProfileRate(args.BlockProfileRate)
	}

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

	return waitForCompletion(pm, done, sigChan)
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
