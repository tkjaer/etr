package main

import (
	"os"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func main() {
	log.Out = os.Stdout
	log.SetLevel(logrus.InfoLevel)

	err := getArgs()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	p := new(probe)
	p.init()
	p.run()
}
