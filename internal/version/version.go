package version

import (
	"runtime/debug"
	"strings"
	"sync"
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
)

// initRuntimeVersion attempts to get version info from build metadata or git if ldflags weren't used
func initRuntimeVersion() {
	once.Do(func() {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, setting := range info.Settings {
				switch setting.Key {
				case "vcs.revision":
					if runtimeCommit == "" {
						runtimeCommit = setting.Value
					}
				case "vcs.modified":
					if setting.Value == "true" && runtimeCommit != "" && !strings.HasSuffix(runtimeCommit, "-dirty") {
						runtimeCommit += "-dirty"
					}
				}
			}
		}

	})
}

func normalizeCommit(commit string) string {
	if commit == "" {
		return commit
	}
	base := strings.TrimSuffix(commit, "-dirty")
	if len(base) > 7 {
		base = base[:7]
	}
	if strings.HasSuffix(commit, "-dirty") {
		return base + "-dirty"
	}
	return base
}

// FullVersion returns a formatted version string
func FullVersion() string {
	initRuntimeVersion()

	commit := GitCommit
	if commit == "unknown" && runtimeCommit != "" {
		commit = runtimeCommit
	}
	commit = normalizeCommit(commit)
	showCommit := commit != "" && commit != "unknown"

	if Version == "dev" {
		if showCommit {
			return "etr development build (commit: " + commit + ")"
		}
		return "etr development build"
	}

	if showCommit {
		return "etr " + Version + " (commit: " + commit + ")"
	}
	return "etr " + Version
}
