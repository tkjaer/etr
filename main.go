package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func main() {
	log.Out = os.Stdout
	log.SetLevel(logrus.InfoLevel)

	args, err := ParseArgs()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	pm, err := NewProbeManager(args)
	if err != nil {
		log.Error(err)
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
			log.Error(err)
			os.Exit(1)
		}
	case <-sigChan:
		// User pressed Ctrl+C
		log.Info("Received interrupt signal, stopping...")
		pm.Stop()
		// Wait for Run() to finish cleanup
		if err = <-done; err != nil {
			log.Error(err)
			os.Exit(1)
		}
	}
}
