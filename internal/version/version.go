package version

// Version information set via ldflags during build
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

// FullVersion returns a formatted version string
func FullVersion() string {
	if Version == "dev" {
		return "etr development build"
	}
	return "etr " + Version + " (commit: " + GitCommit + ", built: " + BuildDate + ")"
}
