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

	// Directory to sync vault files into (required always: used by sync as the
	// sync target, and by MCP as the vault root to serve)
	SyncDir string `env:"OBSIDIAN_SYNC_DIR"`

	// Device name this client identifies as
	DeviceName string `env:"OBSIDIAN_DEVICE_NAME" envDefault:"vault-sync"`

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
	if mode&0077 != 0 {
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

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	// Resolve SyncDir to an absolute path at startup. Downstream code uses
	// it for path traversal checks (ensuring decrypted server paths stay
	// within the sync directory). Those checks rely on string prefix
	// comparison, which only works reliably with absolute paths.
	absDir, err := filepath.Abs(cfg.SyncDir)
	if err != nil {
		return nil, fmt.Errorf("resolving sync dir to absolute path: %w", err)
	}
	cfg.SyncDir = absDir

	return cfg, nil
}

func (c *Config) validate() error {
	if !c.EnableSync && !c.EnableMCP {
		return fmt.Errorf("at least one of ENABLE_SYNC or ENABLE_MCP must be true")
	}

	if c.SyncDir == "" {
		return fmt.Errorf("OBSIDIAN_SYNC_DIR is required")
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

func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// ParseMCPUsers parses the MCP_AUTH_USERS string into a UserCredentials map.
// Format: "user1:bcrypt_hash1,user2:bcrypt_hash2"
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
		hash := pair[idx+1:]
		if username == "" || hash == "" {
			return nil, fmt.Errorf("empty username or hash in: %s", pair)
		}
		users[username] = hash
	}
	return users, nil
}
