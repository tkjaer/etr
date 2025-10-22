package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	args, err := ParseArgs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Setup logging
	logFile, err := SetupLogging(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup logging: %v\n", err)
		os.Exit(1)
	}
	if logFile != nil {
		defer logFile.Close()
	}

	slog.Debug("Starting ECMP traceroute",
		"destination", args.destination,
		"protocol", args.ProtocolName(),
		"parallel_probes", args.parallelProbes,
	)

	pm, err := NewProbeManager(args)
	if err != nil {
		slog.Error("Failed to create probe manager", "error", err)
		os.Exit(1)
	}

	// Set up signal handling for Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Run in a goroutine so we can handle signals
	done := make(chan error)
	go func() {
		done <- pm.Run()
	}()

	// Wait for either completion or interrupt
	select {
	case err = <-done:
		// Probes completed naturally
		if err != nil {
			slog.Error("Probe manager error", "error", err)
			os.Exit(1)
		}
	case <-sigChan:
		// User pressed Ctrl+C
		slog.Debug("Received interrupt signal, stopping...")
		pm.Stop()
		// Wait for Run() to finish cleanup
		if err = <-done; err != nil {
			slog.Error("Error during shutdown", "error", err)
			os.Exit(1)
		}
	}

	slog.Debug("ECMP traceroute completed")
}
