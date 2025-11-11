package config

import (
	"io"
	"log/slog"
	"os"
)

// SetupLogging configures the global slog logger based on args
// Returns the log file handle (caller must close it) or nil if no file
func SetupLogging(args Args) (*os.File, error) {
	// Determine output mode
	mode := "tui"
	if args.Json {
		mode = "json"
	}

	var writers []io.Writer
	var logFile *os.File

	// Add file writer if specified
	if args.Log != "" {
		f, err := os.OpenFile(args.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
		logFile = f
		writers = append(writers, f)
	}

	// Add stderr based on output mode
	switch mode {
	case "tui":
		// TUI mode: only log to file (or discard if no file)
		if len(writers) == 0 {
			writers = append(writers, io.Discard)
		}
	case "json":
		// JSON mode: logs to stderr, data to stdout
		writers = append(writers, os.Stderr)
	case "text":
		// Text mode: logs to stderr
		writers = append(writers, os.Stderr)
	default:
		// Default: stderr
		writers = append(writers, os.Stderr)
	}

	// Combine writers if multiple
	var output io.Writer
	if len(writers) == 1 {
		output = writers[0]
	} else {
		output = io.MultiWriter(writers...)
	}

	// Parse log level
	logLevel := parseLogLevel(args.LogLevel)

	// Create handler based on mode
	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: logLevel,
	}
	if opts.Level == slog.LevelDebug {
		opts.AddSource = true
	}

	if mode == "json" {
		// JSON mode gets JSON-formatted logs
		handler = slog.NewJSONHandler(output, opts)
	} else {
		// TUI and text modes get human-readable logs
		handler = slog.NewTextHandler(output, opts)
	}

	// Set as default logger
	slog.SetDefault(slog.New(handler))

	return logFile, nil
}

// parseLogLevel converts string to slog.Level
func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
