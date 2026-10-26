package main

import (
	"context"
	"log/slog"

	"github.com/tkjaer/etr/internal/config"
	"github.com/tkjaer/etr/internal/output"
)

// cliOutputs creates the command-line outputs when the run starts
type cliOutputs struct {
	*output.OutputManager
	args   config.Args
	cancel context.CancelFunc
}

func newOutputs(args config.Args, cancel context.CancelFunc) *cliOutputs {
	return &cliOutputs{OutputManager: &output.OutputManager{}, args: args, cancel: cancel}
}

// Start creates the outputs; quitting the TUI cancels the run
func (o *cliOutputs) Start() {
	args := o.args
	om := o.OutputManager

	var tui *output.BubbleTUIOutput

	if args.Json {
		jsonOut, err := output.NewJSONOutput("") // empty string = stdout
		if err == nil {
			om.Register(jsonOut)
		}
	} else if !args.NoTUI {
		tui = output.NewBubbleTUIOutput(output.Info{
			Destination:    args.Destination,
			Protocol:       args.ProtocolName(),
			SrcPort:        uint16(args.SourcePort),
			DstPort:        uint16(args.DestinationPort),
			ParallelProbes: uint16(args.ParallelProbes),
			HashAlgorithm:  args.HashAlgorithm,
			TUIRefresh:     args.TUIRefresh,
			NoStyle:        args.NoStyle,
			DiscoverMode:   args.Discover,
			DiscoverHops:   args.DiscoverHops,
			DiscoMode:      args.Disco,
		})
		tui.Start()
		om.Register(tui)
	}

	if args.JsonFile != "" {
		jsonOut, err := output.NewJSONOutput(args.JsonFile)
		if err == nil {
			om.Register(jsonOut)
		} else {
			slog.Warn("Failed to create JSON file output", "error", err)
		}
	}

	if tui != nil {
		go func() {
			<-tui.QuitChan()
			o.cancel()
		}()
	}
}
