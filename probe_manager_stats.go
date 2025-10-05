package main

func (pm *ProbeManager) statsProcessor() {
	for event := range pm.statsChan {
		// Update internal stats (maps, counters, etc.)
		// Decide if/when to output to TUI/JSON
		switch event.EventType {
		case "sent":
			// Update sent count, maybe log
		case "received":
			// Update received count, output to TUI
			pm.outputChan <- outputMsg{ /* ... */ }
		case "timeout":
			// Update loss, output to TUI
			pm.outputChan <- outputMsg{ /* ... */ }
		}
		// When a probe run completes, output summary to JSON
	}
}
