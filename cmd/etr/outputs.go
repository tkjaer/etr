package main

import (
	"log/slog"

	"github.com/tkjaer/etr/internal/config"
	"github.com/tkjaer/etr/internal/output"
	"github.com/tkjaer/etr/internal/shared"
)

func newOutputs(args config.Args) (*output.OutputManager, *output.BubbleTUIOutput) {
	om := &output.OutputManager{}

	var tui *output.BubbleTUIOutput

	if args.Json {
		jsonOut, err := output.NewJSONOutput("") // empty string = stdout
		if err == nil {
			om.Register(jsonOut)
		}
	} else if !args.NoTUI {
		tui = output.NewBubbleTUIOutput(shared.OutputInfo{
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

	return om, tui
}
