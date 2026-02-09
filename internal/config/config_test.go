package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearConfigEnv unsets all config env vars so tests start clean.
// Returns a restore function (though t.Setenv already handles cleanup).
func clearConfigEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"OBSIDIAN_EMAIL",
		"OBSIDIAN_PASSWORD",
		"OBSIDIAN_VAULT_PASSWORD",
		"OBSIDIAN_VAULT_NAME",
		"OBSIDIAN_SYNC_DIR",
		"OBSIDIAN_DEVICE_NAME",
		"ENVIRONMENT",
	} {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}
}

func setRequiredEnv(t *testing.T, syncDir string) {
	t.Helper()
	t.Setenv("OBSIDIAN_EMAIL", "test@example.com")
	t.Setenv("OBSIDIAN_PASSWORD", "secret123")
	t.Setenv("OBSIDIAN_VAULT_PASSWORD", "vaultpass")
	t.Setenv("OBSIDIAN_SYNC_DIR", syncDir)
}

// --- Load happy path ---

func TestLoad_HappyPath(t *testing.T) {
	clearConfigEnv(t)
	dir := t.TempDir()
	setRequiredEnv(t, dir)

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "test@example.com", cfg.Email)
	assert.Equal(t, "secret123", cfg.Password)
	assert.Equal(t, "vaultpass", cfg.VaultPassword)
	assert.Equal(t, dir, cfg.SyncDir)
}

func TestLoad_DefaultDeviceName(t *testing.T) {
	clearConfigEnv(t)
	setRequiredEnv(t, t.TempDir())

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "vault-sync", cfg.DeviceName)
}

func TestLoad_DefaultEnvironment(t *testing.T) {
	clearConfigEnv(t)
	setRequiredEnv(t, t.TempDir())

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "development", cfg.Environment)
}

func TestLoad_CustomDeviceName(t *testing.T) {
	clearConfigEnv(t)
	setRequiredEnv(t, t.TempDir())
	t.Setenv("OBSIDIAN_DEVICE_NAME", "my-laptop")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "my-laptop", cfg.DeviceName)
}

func TestLoad_CustomEnvironment(t *testing.T) {
	clearConfigEnv(t)
	setRequiredEnv(t, t.TempDir())
	t.Setenv("ENVIRONMENT", "production")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "production", cfg.Environment)
}

func TestLoad_VaultNameOptional(t *testing.T) {
	clearConfigEnv(t)
	setRequiredEnv(t, t.TempDir())

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "", cfg.VaultName)
}

func TestLoad_VaultNameSet(t *testing.T) {
	clearConfigEnv(t)
	setRequiredEnv(t, t.TempDir())
	t.Setenv("OBSIDIAN_VAULT_NAME", "my-vault")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "my-vault", cfg.VaultName)
}

// --- Load resolves SyncDir to absolute path ---

func TestLoad_ResolvesRelativeSyncDir(t *testing.T) {
	clearConfigEnv(t)
	setRequiredEnv(t, "relative/path")

	cfg, err := Load()
	require.NoError(t, err)

	assert.True(t, filepath.IsAbs(cfg.SyncDir), "SyncDir should be absolute, got: %s", cfg.SyncDir)
	assert.Contains(t, cfg.SyncDir, "relative/path")
}

func TestLoad_AbsoluteSyncDirUnchanged(t *testing.T) {
	clearConfigEnv(t)
	dir := t.TempDir()
	setRequiredEnv(t, dir)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, dir, cfg.SyncDir)
}

// --- Validation errors ---

func TestLoad_MissingEmail(t *testing.T) {
	clearConfigEnv(t)
	setRequiredEnv(t, t.TempDir())
	os.Unsetenv("OBSIDIAN_EMAIL")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OBSIDIAN_EMAIL")
}

func TestLoad_MissingPassword(t *testing.T) {
	clearConfigEnv(t)
	setRequiredEnv(t, t.TempDir())
	os.Unsetenv("OBSIDIAN_PASSWORD")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OBSIDIAN_PASSWORD")
}

func TestLoad_MissingVaultPassword(t *testing.T) {
	clearConfigEnv(t)
	setRequiredEnv(t, t.TempDir())
	os.Unsetenv("OBSIDIAN_VAULT_PASSWORD")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OBSIDIAN_VAULT_PASSWORD")
}

func TestLoad_MissingSyncDir(t *testing.T) {
	clearConfigEnv(t)
	setRequiredEnv(t, t.TempDir())
	os.Unsetenv("OBSIDIAN_SYNC_DIR")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OBSIDIAN_SYNC_DIR")
}

// --- IsProduction ---

func TestIsProduction_True(t *testing.T) {
	cfg := &Config{Environment: "production"}
	assert.True(t, cfg.IsProduction())
}

func TestIsProduction_False_Development(t *testing.T) {
	cfg := &Config{Environment: "development"}
	assert.False(t, cfg.IsProduction())
}

func TestIsProduction_False_Empty(t *testing.T) {
	cfg := &Config{Environment: ""}
	assert.False(t, cfg.IsProduction())
}

// --- validate ---

func TestValidate_AllPresent(t *testing.T) {
	cfg := &Config{
		Email:         "a@b.com",
		Password:      "pass",
		VaultPassword: "vp",
		SyncDir:       "/tmp",
	}
	assert.NoError(t, cfg.validate())
}

func TestValidate_EmptyEmail(t *testing.T) {
	cfg := &Config{Password: "p", VaultPassword: "vp", SyncDir: "/tmp"}
	err := cfg.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OBSIDIAN_EMAIL")
}

func TestValidate_EmptyPassword(t *testing.T) {
	cfg := &Config{Email: "a@b.com", VaultPassword: "vp", SyncDir: "/tmp"}
	err := cfg.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OBSIDIAN_PASSWORD")
}

func TestValidate_EmptyVaultPassword(t *testing.T) {
	cfg := &Config{Email: "a@b.com", Password: "p", SyncDir: "/tmp"}
	err := cfg.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OBSIDIAN_VAULT_PASSWORD")
}

func TestValidate_EmptySyncDir(t *testing.T) {
	cfg := &Config{Email: "a@b.com", Password: "p", VaultPassword: "vp"}
	err := cfg.validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OBSIDIAN_SYNC_DIR")
}
