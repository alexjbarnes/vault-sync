package logging

import (
	"log/slog"
	"os"
)

// NewLogger creates a structured logger appropriate for the environment.
// Production uses JSON format, development uses human-readable text.
func NewLogger(env string) *slog.Logger {
	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	if env == "production" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		opts.Level = slog.LevelDebug
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
