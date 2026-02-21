package logging

import (
	"log/slog"
	"os"
	"strings"
)

// NewLogger creates a structured logger appropriate for the environment.
// Production uses JSON format, development uses human-readable text.
// The level parameter overrides the default log level. If empty,
// production defaults to info and non-production defaults to debug.
func NewLogger(env, level string) *slog.Logger {
	var handler slog.Handler

	logLevel := parseLevel(env, level)

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	if env == "production" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}

// parseLevel converts a level string to slog.Level. When the level
// string is empty, production defaults to info and non-production
// defaults to debug.
func parseLevel(env, level string) slog.Level {
	if level == "" {
		if env == "production" {
			return slog.LevelInfo
		}

		return slog.LevelDebug
	}

	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		if env == "production" {
			return slog.LevelInfo
		}

		return slog.LevelDebug
	}
}
