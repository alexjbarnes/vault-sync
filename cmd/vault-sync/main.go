package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/alexjbarnes/vault-sync/internal/config"
	"github.com/alexjbarnes/vault-sync/internal/logging"
	"github.com/alexjbarnes/vault-sync/internal/state"
	"github.com/alexjbarnes/vault-sync/obsidian"
	"golang.org/x/sync/errgroup"
)

var Version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	logger := logging.NewLogger(cfg.Environment)
	logger.Info("vault-sync starting", slog.String("version", Version))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	appState, err := state.Load()
	if err != nil {
		return fmt.Errorf("loading state: %w", err)
	}

	client := obsidian.NewClient(nil)

	token, vaultList, err := authenticate(ctx, client, cfg, appState, logger)
	if err != nil {
		return err
	}

	vault, err := selectVault(vaultList, cfg.VaultName)
	if err != nil {
		return err
	}

	logger.Info("selected vault",
		slog.String("name", vault.Name),
		slog.String("id", vault.ID),
		slog.String("host", vault.Host),
		slog.Int("encryption_version", vault.EncryptionVersion),
	)

	// Derive encryption key, keyhash, and cipher.
	logger.Info("deriving encryption key")
	key, err := obsidian.DeriveKey(cfg.VaultPassword, vault.Salt)
	if err != nil {
		return fmt.Errorf("deriving key: %w", err)
	}
	keyHash := obsidian.KeyHash(key)
	logger.Debug("key derived", slog.String("keyhash_prefix", keyHash[:16]))

	cipher, err := obsidian.NewCipherV0(key)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}

	vs := appState.GetVault(vault.ID)
	logger.Info("sync state",
		slog.Int64("version", vs.Version),
		slog.Bool("initial", vs.Initial),
	)

	vaultFS := obsidian.NewVault(cfg.SyncDir)

	// Connect to sync server.
	syncClient := obsidian.NewSyncClient(obsidian.SyncConfig{
		Host:              vault.Host,
		Token:             token,
		VaultID:           vault.ID,
		KeyHash:           keyHash,
		Device:            cfg.DeviceName,
		EncryptionVersion: vault.EncryptionVersion,
		Version:           vs.Version,
		Initial:           vs.Initial,
		Cipher:            cipher,
		Vault:             vaultFS,
		OnReady: func(version int64) {
			if err := appState.SetVault(vault.ID, state.VaultState{
				Version: version,
				Initial: false,
			}); err != nil {
				logger.Warn("failed to save state", slog.String("error", err.Error()))
			}
			logger.Info("state saved", slog.Int64("version", version))
		},
	}, logger)
	defer syncClient.Close()

	if err := syncClient.Connect(ctx, vault.Host); err != nil {
		return fmt.Errorf("connecting to sync server: %w", err)
	}

	watcher := obsidian.NewWatcher(vaultFS, syncClient, logger)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return syncClient.Listen(gctx)
	})
	g.Go(func() error {
		return watcher.Watch(gctx)
	})
	return g.Wait()
}

func authenticate(ctx context.Context, client *obsidian.Client, cfg *config.Config, appState *state.State, logger *slog.Logger) (string, *obsidian.VaultListResponse, error) {
	if appState.Token != "" {
		logger.Debug("trying cached token")
		vaults, err := client.ListVaults(ctx, appState.Token)
		if err == nil && (len(vaults.Vaults) > 0 || len(vaults.Shared) > 0) {
			logger.Info("authenticated with cached token")
			return appState.Token, vaults, nil
		}
		logger.Debug("cached token expired, signing in fresh")
	}

	logger.Info("signing in", slog.String("email", cfg.Email))
	auth, err := client.Signin(ctx, cfg.Email, cfg.Password)
	if err != nil {
		return "", nil, fmt.Errorf("signing in: %w", err)
	}
	logger.Info("signed in", slog.String("name", auth.Name), slog.String("email", auth.Email))

	appState.Token = auth.Token
	if err := appState.Save(); err != nil {
		logger.Warn("failed to save token", slog.String("error", err.Error()))
	}

	vaults, err := client.ListVaults(ctx, auth.Token)
	if err != nil {
		return "", nil, fmt.Errorf("listing vaults: %w", err)
	}

	if len(vaults.Vaults) == 0 && len(vaults.Shared) == 0 {
		return "", nil, fmt.Errorf("no vaults found for this account")
	}

	return auth.Token, vaults, nil
}

func selectVault(vaults *obsidian.VaultListResponse, name string) (*obsidian.VaultInfo, error) {
	total := len(vaults.Vaults) + len(vaults.Shared)

	if name == "" {
		if total == 1 {
			if len(vaults.Vaults) == 1 {
				return &vaults.Vaults[0], nil
			}
			return &vaults.Shared[0], nil
		}
		return nil, fmt.Errorf("multiple vaults found, set OBSIDIAN_VAULT_NAME to pick one: %s", vaultNames(vaults))
	}

	for i := range vaults.Vaults {
		if vaults.Vaults[i].Name == name {
			return &vaults.Vaults[i], nil
		}
	}
	for i := range vaults.Shared {
		if vaults.Shared[i].Name == name {
			return &vaults.Shared[i], nil
		}
	}

	return nil, fmt.Errorf("vault %q not found, available: %s", name, vaultNames(vaults))
}

func vaultNames(vaults *obsidian.VaultListResponse) string {
	names := ""
	for i, v := range vaults.Vaults {
		if i > 0 {
			names += ", "
		}
		names += v.Name
	}
	for _, v := range vaults.Shared {
		names += ", " + v.Name
	}
	return names
}
