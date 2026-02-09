package logging

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogger_Production_JSONHandler(t *testing.T) {
	logger := NewLogger("production")
	require.NotNil(t, logger)

	handler := logger.Handler()
	_, ok := handler.(*slog.JSONHandler)
	assert.True(t, ok, "production logger should use JSONHandler, got %T", handler)
}

func TestNewLogger_Development_TextHandler(t *testing.T) {
	logger := NewLogger("development")
	require.NotNil(t, logger)

	handler := logger.Handler()
	_, ok := handler.(*slog.TextHandler)
	assert.True(t, ok, "development logger should use TextHandler, got %T", handler)
}

func TestNewLogger_EmptyEnv_TextHandler(t *testing.T) {
	logger := NewLogger("")
	require.NotNil(t, logger)

	handler := logger.Handler()
	_, ok := handler.(*slog.TextHandler)
	assert.True(t, ok, "empty env logger should use TextHandler, got %T", handler)
}

func TestNewLogger_UnknownEnv_TextHandler(t *testing.T) {
	logger := NewLogger("staging")
	require.NotNil(t, logger)

	handler := logger.Handler()
	_, ok := handler.(*slog.TextHandler)
	assert.True(t, ok, "unknown env logger should use TextHandler, got %T", handler)
}

func TestNewLogger_Production_InfoLevel(t *testing.T) {
	logger := NewLogger("production")
	// Production should log at Info but not Debug.
	assert.True(t, logger.Handler().Enabled(nil, slog.LevelInfo))
	assert.False(t, logger.Handler().Enabled(nil, slog.LevelDebug))
}

func TestNewLogger_Development_DebugLevel(t *testing.T) {
	logger := NewLogger("development")
	// Development should log at Debug level.
	assert.True(t, logger.Handler().Enabled(nil, slog.LevelDebug))
	assert.True(t, logger.Handler().Enabled(nil, slog.LevelInfo))
}
