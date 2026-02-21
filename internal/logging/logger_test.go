package logging

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogger_Production_JSONHandler(t *testing.T) {
	logger := NewLogger("production", "")
	require.NotNil(t, logger)

	handler := logger.Handler()
	_, ok := handler.(*slog.JSONHandler)
	assert.True(t, ok, "production logger should use JSONHandler, got %T", handler)
}

func TestNewLogger_Development_TextHandler(t *testing.T) {
	logger := NewLogger("development", "")
	require.NotNil(t, logger)

	handler := logger.Handler()
	_, ok := handler.(*slog.TextHandler)
	assert.True(t, ok, "development logger should use TextHandler, got %T", handler)
}

func TestNewLogger_EmptyEnv_TextHandler(t *testing.T) {
	logger := NewLogger("", "")
	require.NotNil(t, logger)

	handler := logger.Handler()
	_, ok := handler.(*slog.TextHandler)
	assert.True(t, ok, "empty env logger should use TextHandler, got %T", handler)
}

func TestNewLogger_UnknownEnv_TextHandler(t *testing.T) {
	logger := NewLogger("staging", "")
	require.NotNil(t, logger)

	handler := logger.Handler()
	_, ok := handler.(*slog.TextHandler)
	assert.True(t, ok, "unknown env logger should use TextHandler, got %T", handler)
}

func TestNewLogger_Production_InfoLevel(t *testing.T) {
	logger := NewLogger("production", "")
	// Production should log at Info but not Debug.
	assert.True(t, logger.Handler().Enabled(context.TODO(), slog.LevelInfo))
	assert.False(t, logger.Handler().Enabled(context.TODO(), slog.LevelDebug))
}

func TestNewLogger_Development_DebugLevel(t *testing.T) {
	logger := NewLogger("development", "")
	// Development should log at Debug level.
	assert.True(t, logger.Handler().Enabled(context.TODO(), slog.LevelDebug))
	assert.True(t, logger.Handler().Enabled(context.TODO(), slog.LevelInfo))
}

func TestNewLogger_LevelOverride_Warn(t *testing.T) {
	logger := NewLogger("development", "warn")
	// Explicit warn level should suppress info and debug.
	assert.True(t, logger.Handler().Enabled(context.TODO(), slog.LevelWarn))
	assert.False(t, logger.Handler().Enabled(context.TODO(), slog.LevelInfo))
	assert.False(t, logger.Handler().Enabled(context.TODO(), slog.LevelDebug))
}

func TestNewLogger_LevelOverride_Error(t *testing.T) {
	logger := NewLogger("development", "error")
	assert.True(t, logger.Handler().Enabled(context.TODO(), slog.LevelError))
	assert.False(t, logger.Handler().Enabled(context.TODO(), slog.LevelWarn))
}

func TestNewLogger_LevelOverride_Debug_Production(t *testing.T) {
	logger := NewLogger("production", "debug")
	// Explicit debug level overrides the production default.
	assert.True(t, logger.Handler().Enabled(context.TODO(), slog.LevelDebug))
}

func TestNewLogger_LevelOverride_CaseInsensitive(t *testing.T) {
	logger := NewLogger("production", "WARN")
	assert.True(t, logger.Handler().Enabled(context.TODO(), slog.LevelWarn))
	assert.False(t, logger.Handler().Enabled(context.TODO(), slog.LevelInfo))
}

func TestNewLogger_LevelOverride_Unknown(t *testing.T) {
	// Unknown level string falls back to environment default.
	logger := NewLogger("production", "bogus")
	assert.True(t, logger.Handler().Enabled(context.TODO(), slog.LevelInfo))
	assert.False(t, logger.Handler().Enabled(context.TODO(), slog.LevelDebug))
}
