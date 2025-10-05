package main

import (
	"os"

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

	err = pm.Run()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
}
