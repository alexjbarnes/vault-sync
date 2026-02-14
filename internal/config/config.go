package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/alexjbarnes/vault-sync/internal/auth"
	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Config struct {
	// Service flags. At least one must be true.
	EnableSync bool `env:"ENABLE_SYNC" envDefault:"true"`
	EnableMCP  bool `env:"ENABLE_MCP" envDefault:"false"`

	// Obsidian account credentials (required when sync is enabled)
	Email    string `env:"OBSIDIAN_EMAIL"`
	Password string `env:"OBSIDIAN_PASSWORD"`

	// Vault encryption password (required when sync is enabled)
	VaultPassword string `env:"OBSIDIAN_VAULT_PASSWORD"`

	// Vault name to sync. If empty and only one vault exists, it is used automatically.
	VaultName string `env:"OBSIDIAN_VAULT_NAME" envDefault:""`

	// Directory to sync vault files into. When sync is enabled and this is
	// empty, it defaults to ~/.vault-sync/vaults/<vault_id>/ after vault
	// selection. Required when MCP is enabled without sync (no vault ID
	// available to derive a default).
	SyncDir string `env:"OBSIDIAN_SYNC_DIR"`

	// Device name this client identifies as. Uses the system hostname,
	// matching the Obsidian desktop app behavior.
	DeviceName string

	// Config sync toggles. These match the Obsidian app's sync settings.
	// All default to false (no .obsidian/ config synced unless opted in).
	SyncMainSettings       bool `env:"SYNC_MAIN_SETTINGS" envDefault:"false"`
	SyncAppearance         bool `env:"SYNC_APPEARANCE" envDefault:"false"`
	SyncThemesAndSnippets  bool `env:"SYNC_THEMES_SNIPPETS" envDefault:"false"`
	SyncHotkeys            bool `env:"SYNC_HOTKEYS" envDefault:"false"`
	SyncActiveCorePlugins  bool `env:"SYNC_ACTIVE_CORE_PLUGINS" envDefault:"false"`
	SyncCorePluginSettings bool `env:"SYNC_CORE_PLUGIN_SETTINGS" envDefault:"false"`
	SyncCommunityPlugins   bool `env:"SYNC_COMMUNITY_PLUGINS" envDefault:"false"`
	SyncInstalledPlugins   bool `env:"SYNC_INSTALLED_PLUGINS" envDefault:"false"`

	// Environment controls log format
	Environment string `env:"ENVIRONMENT" envDefault:"development"`

	// MCP server settings (required when MCP is enabled)
	MCPListenAddr string `env:"MCP_LISTEN_ADDR" envDefault:":8090"`
	MCPServerURL  string `env:"MCP_SERVER_URL"`
	MCPAuthUsers  string `env:"MCP_AUTH_USERS"`
	MCPLogLevel   string `env:"MCP_LOG_LEVEL" envDefault:"info"`
}

// warnInsecureEnvFile checks whether the .env file (if present) has
// overly permissive permissions. On Unix systems, group or world
// readable files risk exposing credentials to other users.
func warnInsecureEnvFile() {
	if runtime.GOOS == "windows" {
		return
	}

	info, err := os.Stat(".env")
	if err != nil {
		return // file does not exist, nothing to check
	}

	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		log.Printf("WARNING: .env file has insecure permissions %04o; recommended 0600", mode)
	}
}

// Load reads configuration from environment variables.
// It first attempts to load a .env file if present, then parses env vars.
func Load() (*Config, error) {
	_ = godotenv.Load()

	warnInsecureEnvFile()

	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if cfg.DeviceName == "" {
		hostname, err := os.Hostname()
		if err != nil || hostname == "" {
			hostname = "vault-sync"
		}

		cfg.DeviceName = hostname
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	// Resolve SyncDir to an absolute path at startup. Downstream code uses
	// it for path traversal checks (ensuring decrypted server paths stay
	// within the sync directory). Those checks rely on string prefix
	// comparison, which only works reliably with absolute paths.
	// When sync is enabled and SyncDir is empty, it will be resolved
	// later in runSync after vault selection.
	if cfg.SyncDir != "" {
		absDir, err := filepath.Abs(cfg.SyncDir)
		if err != nil {
			return nil, fmt.Errorf("resolving sync dir to absolute path: %w", err)
		}

		cfg.SyncDir = absDir
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if !c.EnableSync && !c.EnableMCP {
		return fmt.Errorf("at least one of ENABLE_SYNC or ENABLE_MCP must be true")
	}

	// SyncDir is required when MCP is enabled without sync, because there
	// is no vault selection step to derive a default from. When sync is
	// enabled, an empty SyncDir is allowed and will be derived from the
	// vault ID after authentication.
	if c.SyncDir == "" && !c.EnableSync {
		return fmt.Errorf("OBSIDIAN_SYNC_DIR is required when sync is not enabled")
	}

	if c.EnableSync {
		if c.Email == "" {
			return fmt.Errorf("OBSIDIAN_EMAIL is required when sync is enabled")
		}

		if c.Password == "" {
			return fmt.Errorf("OBSIDIAN_PASSWORD is required when sync is enabled")
		}

		if c.VaultPassword == "" {
			return fmt.Errorf("OBSIDIAN_VAULT_PASSWORD is required when sync is enabled")
		}
	}

	if c.EnableMCP {
		if c.MCPServerURL == "" {
			return fmt.Errorf("MCP_SERVER_URL is required when MCP is enabled")
		}

		if c.MCPAuthUsers == "" {
			return fmt.Errorf("MCP_AUTH_USERS is required when MCP is enabled")
		}
	}

	return nil
}

// DefaultSyncDir returns the default sync directory for a given vault ID:
// ~/.vault-sync/vaults/<vaultID>/
func DefaultSyncDir(vaultID string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determining home directory: %w", err)
	}

	return filepath.Join(home, ".vault-sync", "vaults", vaultID), nil
}

// SetSyncDir sets the sync directory and resolves it to an absolute path.
// Called from runSync after vault selection when OBSIDIAN_SYNC_DIR was not
// explicitly configured.
func (c *Config) SetSyncDir(dir string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolving sync dir to absolute path: %w", err)
	}

	c.SyncDir = absDir

	return nil
}

func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// ParseMCPUsers parses the MCP_AUTH_USERS string into a UserCredentials map.
// Format: "user1:password1,user2:password2"
func (c *Config) ParseMCPUsers() (auth.UserCredentials, error) {
	users := make(auth.UserCredentials)
	if c.MCPAuthUsers == "" {
		return users, nil
	}

	for _, pair := range strings.Split(c.MCPAuthUsers, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		idx := strings.Index(pair, ":")
		if idx < 0 {
			return nil, fmt.Errorf("invalid user entry (missing ':'): %s", pair)
		}

		username := pair[:idx]

		password := pair[idx+1:]
		if username == "" || password == "" {
			return nil, fmt.Errorf("empty username or password in: %s", pair)
		}

		users[username] = password
	}

	return users, nil
}
