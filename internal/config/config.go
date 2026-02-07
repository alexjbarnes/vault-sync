package config

import (
	"fmt"
	"path/filepath"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

type Config struct {
	// Obsidian account credentials
	Email    string `env:"OBSIDIAN_EMAIL,required"`
	Password string `env:"OBSIDIAN_PASSWORD,required"`

	// Vault encryption password
	VaultPassword string `env:"OBSIDIAN_VAULT_PASSWORD,required"`

	// Vault name to sync. If empty and only one vault exists, it is used automatically.
	VaultName string `env:"OBSIDIAN_VAULT_NAME" envDefault:""`

	// Directory to sync vault files into
	SyncDir string `env:"OBSIDIAN_SYNC_DIR,required"`

	// Device name this client identifies as
	DeviceName string `env:"OBSIDIAN_DEVICE_NAME" envDefault:"vault-sync"`

	// Environment controls log format
	Environment string `env:"ENVIRONMENT" envDefault:"development"`
}

// Load reads configuration from environment variables.
// It first attempts to load a .env file if present, then parses env vars.
func Load() (*Config, error) {
	_ = godotenv.Load()

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
	if c.Email == "" {
		return fmt.Errorf("OBSIDIAN_EMAIL is required")
	}
	if c.Password == "" {
		return fmt.Errorf("OBSIDIAN_PASSWORD is required")
	}
	if c.VaultPassword == "" {
		return fmt.Errorf("OBSIDIAN_VAULT_PASSWORD is required")
	}
	if c.SyncDir == "" {
		return fmt.Errorf("OBSIDIAN_SYNC_DIR is required")
	}
	return nil
}

func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}
