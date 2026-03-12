package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
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
