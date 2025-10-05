package main

import "net"

// ptrLookupRoutine handles all PTR lookups centrally
func (pm *ProbeManager) ptrLookupRoutine() {
	// Simple map to track lookup attempts and results
	cache := make(map[string]string)
	// Map to track which probes are interested in which IPs
	subscribers := make(map[string]map[string]bool)

	for {
		select {
		case <-pm.stop:
			return
		case ptrRequest := <-pm.ptrLookupChan:
			ip := ptrRequest[0]
			probeID := ""
			if len(ptrRequest) > 1 {
				probeID = ptrRequest[1]
			}

			// Register this probe as interested in this IP
			if probeID != "" {
				if _, ok := subscribers[ip]; !ok {
					subscribers[ip] = make(map[string]bool)
				}
				subscribers[ip][probeID] = true
			}

			// Check cache first
			if ptr, ok := cache[ip]; ok {
				// Notify all interested probes
				pm.notifyPtrSubscribers(ip, ptr, subscribers[ip])
				continue
			}

			// Lookup PTR only if not already looked up
			if _, alreadyLooking := cache[ip]; !alreadyLooking {
				// Mark as "in progress" to avoid duplicate lookups
				cache[ip] = ""

				go func(ipAddr string) {
					ptr, err := net.LookupAddr(ipAddr)
					result := ipAddr // Default to IP address if lookup fails

					if err == nil && len(ptr) > 0 {
						result = ptr[0][:len(ptr[0])-1] // Remove trailing dot
					}

					// Store in cache regardless of success/failure
					cache[ipAddr] = result

					// Notify all interested probes
					if subs, ok := subscribers[ipAddr]; ok {
						pm.notifyPtrSubscribers(ipAddr, result, subs)
					}
				}(ip)
			}
		}
	}
}

// notifyPtrSubscribers sends PTR results to interested probes
func (pm *ProbeManager) notifyPtrSubscribers(ip, ptr string, subs map[string]bool) {
	// Send message to output channel that will be read by probes
	pm.outputChan <- outputMsg{
		msgType: "ptr_result",
		ip:      ip,
		ptrName: ptr,
	}
}

// updatePTR updates PTR records in aggregated statistics
func (pm *ProbeManager) updatePTR(ip, ptr string) {
	pm.statsMutex.Lock()
	defer pm.statsMutex.Unlock()

	if entry, ok := pm.aggregatedStats[ip]; ok {
		// maybe create a ptr function that'll return it if known,
		// and "" + do a lookup if not known
		entry.ptr = ptr
		pm.aggregatedStats[ip] = entry
	}
}
