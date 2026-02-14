package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearConfigEnv unsets all config env vars so tests start clean.
func clearConfigEnv(t *testing.T) {
	t.Helper()

	for _, key := range []string{
		"ENABLE_SYNC",
		"ENABLE_MCP",
		"OBSIDIAN_EMAIL",
		"OBSIDIAN_PASSWORD",
		"OBSIDIAN_VAULT_PASSWORD",
		"OBSIDIAN_VAULT_NAME",
		"OBSIDIAN_SYNC_DIR",
		"ENVIRONMENT",
		"MCP_LISTEN_ADDR",
		"MCP_SERVER_URL",
		"MCP_AUTH_USERS",
		"MCP_LOG_LEVEL",
	} {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}
}

// setSyncEnv sets the minimum env vars for sync mode.
func setSyncEnv(t *testing.T, syncDir string) {
	t.Helper()
	t.Setenv("ENABLE_SYNC", "true")
	t.Setenv("OBSIDIAN_EMAIL", "test@example.com")
	t.Setenv("OBSIDIAN_PASSWORD", "secret123")
	t.Setenv("OBSIDIAN_VAULT_PASSWORD", "vaultpass")
	t.Setenv("OBSIDIAN_SYNC_DIR", syncDir)
}

// setMCPEnv sets the minimum env vars for MCP mode.
func setMCPEnv(t *testing.T, syncDir string) {
	t.Helper()
	t.Setenv("ENABLE_MCP", "true")
	t.Setenv("OBSIDIAN_SYNC_DIR", syncDir)
	t.Setenv("MCP_SERVER_URL", "https://vault.example.com")
	t.Setenv("MCP_AUTH_USERS", "alex:$2a$10$hash")
}

// --- Load: sync mode ---

func TestLoad_SyncMode(t *testing.T) {
	clearConfigEnv(t)
	dir := t.TempDir()
	setSyncEnv(t, dir)

	cfg, err := Load()
	require.NoError(t, err)
	assert.True(t, cfg.EnableSync)
	assert.False(t, cfg.EnableMCP)
	assert.Equal(t, "test@example.com", cfg.Email)
	assert.Equal(t, "secret123", cfg.Password)
	assert.Equal(t, "vaultpass", cfg.VaultPassword)
	assert.Equal(t, dir, cfg.SyncDir)
}

func TestLoad_SyncMode_MissingEmail(t *testing.T) {
	clearConfigEnv(t)
	setSyncEnv(t, t.TempDir())
	os.Unsetenv("OBSIDIAN_EMAIL")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OBSIDIAN_EMAIL")
}

func TestLoad_SyncMode_MissingPassword(t *testing.T) {
	clearConfigEnv(t)
	setSyncEnv(t, t.TempDir())
	os.Unsetenv("OBSIDIAN_PASSWORD")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OBSIDIAN_PASSWORD")
}

func TestLoad_SyncMode_MissingVaultPassword(t *testing.T) {
	clearConfigEnv(t)
	setSyncEnv(t, t.TempDir())
	os.Unsetenv("OBSIDIAN_VAULT_PASSWORD")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OBSIDIAN_VAULT_PASSWORD")
}

// --- Load: MCP mode ---

func TestLoad_MCPMode(t *testing.T) {
	clearConfigEnv(t)
	dir := t.TempDir()
	t.Setenv("ENABLE_SYNC", "false")
	setMCPEnv(t, dir)

	cfg, err := Load()
	require.NoError(t, err)
	assert.False(t, cfg.EnableSync)
	assert.True(t, cfg.EnableMCP)
	assert.Equal(t, "https://vault.example.com", cfg.MCPServerURL)
	assert.Equal(t, "alex:$2a$10$hash", cfg.MCPAuthUsers)
	assert.Equal(t, ":8090", cfg.MCPListenAddr) // default
}

func TestLoad_MCPMode_MissingServerURL(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("ENABLE_SYNC", "false")
	t.Setenv("ENABLE_MCP", "true")
	t.Setenv("OBSIDIAN_SYNC_DIR", t.TempDir())
	t.Setenv("MCP_AUTH_USERS", "alex:hash")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MCP_SERVER_URL")
}

func TestLoad_MCPMode_MissingAuthUsers(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("ENABLE_SYNC", "false")
	t.Setenv("ENABLE_MCP", "true")
	t.Setenv("OBSIDIAN_SYNC_DIR", t.TempDir())
	t.Setenv("MCP_SERVER_URL", "https://vault.example.com")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MCP_AUTH_USERS")
}

// --- Load: MCP mode does not require sync fields ---

func TestLoad_MCPMode_NoSyncFieldsNeeded(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("ENABLE_SYNC", "false")
	setMCPEnv(t, t.TempDir())
	// No OBSIDIAN_EMAIL/PASSWORD/VAULT_PASSWORD set.

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "", cfg.Email)
}

// --- Load: both modes ---

func TestLoad_BothModes(t *testing.T) {
	clearConfigEnv(t)
	dir := t.TempDir()
	setSyncEnv(t, dir)
	t.Setenv("ENABLE_MCP", "true")
	t.Setenv("MCP_SERVER_URL", "https://vault.example.com")
	t.Setenv("MCP_AUTH_USERS", "alex:hash")

	cfg, err := Load()
	require.NoError(t, err)
	assert.True(t, cfg.EnableSync)
	assert.True(t, cfg.EnableMCP)
}

// --- Load: neither mode ---

func TestLoad_NeitherMode(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("ENABLE_SYNC", "false")
	t.Setenv("ENABLE_MCP", "false")
	t.Setenv("OBSIDIAN_SYNC_DIR", t.TempDir())

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one")
}

// --- Load: SyncDir behavior ---

func TestLoad_SyncDir_OptionalForSyncMode(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("ENABLE_SYNC", "true")
	t.Setenv("OBSIDIAN_EMAIL", "a@b.com")
	t.Setenv("OBSIDIAN_PASSWORD", "p")
	t.Setenv("OBSIDIAN_VAULT_PASSWORD", "vp")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "", cfg.SyncDir, "SyncDir should be empty; derived later from vault ID")
}

func TestLoad_SyncDir_RequiredForMCPOnly(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("ENABLE_SYNC", "false")
	t.Setenv("ENABLE_MCP", "true")
	t.Setenv("MCP_SERVER_URL", "https://vault.example.com")
	t.Setenv("MCP_AUTH_USERS", "alex:hash")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OBSIDIAN_SYNC_DIR")
}

func TestDefaultSyncDir(t *testing.T) {
	dir, err := DefaultSyncDir("abc123")
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(dir))
	assert.Contains(t, dir, filepath.Join(".vault-sync", "vaults", "abc123"))
}

func TestSetSyncDir_ResolvesToAbsolute(t *testing.T) {
	cfg := &Config{}
	err := cfg.SetSyncDir("relative/path")
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(cfg.SyncDir))
	assert.Contains(t, cfg.SyncDir, "relative/path")
}

// --- Defaults ---

func TestLoad_DefaultDeviceName(t *testing.T) {
	clearConfigEnv(t)
	setSyncEnv(t, t.TempDir())

	cfg, err := Load()
	require.NoError(t, err)

	// Default should be the system hostname, matching Obsidian desktop behavior.
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "vault-sync"
	}

	assert.Equal(t, hostname, cfg.DeviceName)
}

func TestLoad_DefaultEnvironment(t *testing.T) {
	clearConfigEnv(t)
	setSyncEnv(t, t.TempDir())

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "development", cfg.Environment)
}

func TestLoad_DefaultEnableSync(t *testing.T) {
	clearConfigEnv(t)
	// Default ENABLE_SYNC is true.
	setSyncEnv(t, t.TempDir())

	cfg, err := Load()
	require.NoError(t, err)
	assert.True(t, cfg.EnableSync)
}

func TestLoad_CustomEnvironment(t *testing.T) {
	clearConfigEnv(t)
	setSyncEnv(t, t.TempDir())
	t.Setenv("ENVIRONMENT", "production")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "production", cfg.Environment)
}

// --- SyncDir resolution ---

func TestLoad_ResolvesRelativeSyncDir(t *testing.T) {
	clearConfigEnv(t)
	setSyncEnv(t, "relative/path")

	cfg, err := Load()
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(cfg.SyncDir), "SyncDir should be absolute, got: %s", cfg.SyncDir)
	assert.Contains(t, cfg.SyncDir, "relative/path")
}

func TestLoad_AbsoluteSyncDirUnchanged(t *testing.T) {
	clearConfigEnv(t)
	dir := t.TempDir()
	setSyncEnv(t, dir)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, dir, cfg.SyncDir)
}

// --- VaultName ---

func TestLoad_VaultNameOptional(t *testing.T) {
	clearConfigEnv(t)
	setSyncEnv(t, t.TempDir())

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "", cfg.VaultName)
}

func TestLoad_VaultNameSet(t *testing.T) {
	clearConfigEnv(t)
	setSyncEnv(t, t.TempDir())
	t.Setenv("OBSIDIAN_VAULT_NAME", "my-vault")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "my-vault", cfg.VaultName)
}

// --- IsProduction ---

func TestIsProduction_True(t *testing.T) {
	cfg := &Config{Environment: "production"}
	assert.True(t, cfg.IsProduction())
}

func TestIsProduction_False(t *testing.T) {
	cfg := &Config{Environment: "development"}
	assert.False(t, cfg.IsProduction())
}

// --- ParseMCPUsers ---

func TestParseMCPUsers_Valid(t *testing.T) {
	cfg := &Config{MCPAuthUsers: "alex:$2a$10$hash1,bob:$2a$10$hash2"}
	users, err := cfg.ParseMCPUsers()
	require.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, "$2a$10$hash1", users["alex"])
	assert.Equal(t, "$2a$10$hash2", users["bob"])
}

func TestParseMCPUsers_Single(t *testing.T) {
	cfg := &Config{MCPAuthUsers: "alex:hash"}
	users, err := cfg.ParseMCPUsers()
	require.NoError(t, err)
	assert.Len(t, users, 1)
}

func TestParseMCPUsers_Empty(t *testing.T) {
	cfg := &Config{MCPAuthUsers: ""}
	users, err := cfg.ParseMCPUsers()
	require.NoError(t, err)
	assert.Empty(t, users)
}

func TestParseMCPUsers_MissingColon(t *testing.T) {
	cfg := &Config{MCPAuthUsers: "invalidentry"}
	_, err := cfg.ParseMCPUsers()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing ':'")
}

func TestParseMCPUsers_EmptyUsername(t *testing.T) {
	cfg := &Config{MCPAuthUsers: ":hash"}
	_, err := cfg.ParseMCPUsers()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty username")
}

func TestParseMCPUsers_EmptyPassword(t *testing.T) {
	cfg := &Config{MCPAuthUsers: "user:"}
	_, err := cfg.ParseMCPUsers()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty username or password")
}

// --- validate ---

func TestValidate_SyncAllPresent(t *testing.T) {
	cfg := &Config{
		EnableSync:    true,
		Email:         "a@b.com",
		Password:      "pass",
		VaultPassword: "vp",
		SyncDir:       "/tmp",
	}
	assert.NoError(t, cfg.validate())
}

func TestValidate_SyncWithoutSyncDir(t *testing.T) {
	cfg := &Config{
		EnableSync:    true,
		Email:         "a@b.com",
		Password:      "pass",
		VaultPassword: "vp",
	}
	assert.NoError(t, cfg.validate(), "SyncDir should be optional when sync is enabled")
}

func TestValidate_MCPAllPresent(t *testing.T) {
	cfg := &Config{
		EnableMCP:    true,
		SyncDir:      "/tmp",
		MCPServerURL: "https://example.com",
		MCPAuthUsers: "user:hash",
	}
	assert.NoError(t, cfg.validate())
}
