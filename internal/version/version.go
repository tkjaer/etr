package version

import (
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Version information set via ldflags during build
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

var (
	once          sync.Once
	runtimeCommit string
	runtimeDate   string
)

// initRuntimeVersion attempts to get version info from git if ldflags weren't used
func initRuntimeVersion() {
	once.Do(func() {
		// Try to get git commit
		if GitCommit == "unknown" {
			if cmd := exec.Command("git", "rev-parse", "--short", "HEAD"); cmd.Err == nil {
				if output, err := cmd.Output(); err == nil {
					runtimeCommit = strings.TrimSpace(string(output))

					// Check if tree is dirty
					if cmd := exec.Command("git", "diff-index", "--quiet", "HEAD", "--"); cmd.Err == nil {
						if err := cmd.Run(); err != nil {
							// Non-zero exit means dirty tree
							runtimeCommit += "-dirty"
						}
					}
				}
			}
		}

		// Use current time as build date if not set
		if BuildDate == "unknown" {
			runtimeDate = time.Now().UTC().Format("2006-01-02_15:04:05")
		}
	})
}

// FullVersion returns a formatted version string
func FullVersion() string {
	initRuntimeVersion()

	commit := GitCommit
	if commit == "unknown" && runtimeCommit != "" {
		commit = runtimeCommit
	}

	buildDate := BuildDate
	if buildDate == "unknown" && runtimeDate != "" {
		buildDate = runtimeDate
	}

	if Version == "dev" {
		return "etr development build " + "(commit: " + commit + ", built: " + buildDate + ")"
	}
	return "etr " + Version + " (commit: " + commit + ", built: " + buildDate + ")"
}
