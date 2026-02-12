package main

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/auth"
	"github.com/alexjbarnes/vault-sync/internal/config"
	"github.com/alexjbarnes/vault-sync/internal/logging"
	"github.com/alexjbarnes/vault-sync/internal/mcpserver"
	"github.com/alexjbarnes/vault-sync/internal/state"
	"github.com/alexjbarnes/vault-sync/internal/vault"
	"github.com/alexjbarnes/vault-sync/obsidian"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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
	logger.Info("vault-sync starting",
		slog.String("version", Version),
		slog.Bool("sync", cfg.EnableSync),
		slog.Bool("mcp", cfg.EnableMCP),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// When sync is enabled, perform authentication and vault selection
	// before starting any services. This ensures cfg.SyncDir is resolved
	// before the MCP server reads it, preventing the MCP server from
	// serving the wrong directory.
	var syncSetup *syncSetupResult
	var appState *state.State

	if cfg.EnableSync {
		var err error
		syncSetup, err = setupSync(ctx, cfg, logger)
		if err != nil {
			return err
		}
		defer syncSetup.cleanup()
		appState = syncSetup.appState
	} else if cfg.EnableMCP {
		// MCP-only mode: load state for OAuth persistence.
		var err error
		appState, err = state.Load()
		if err != nil {
			return fmt.Errorf("loading state: %w", err)
		}
		defer appState.Close()
	}

	g, gctx := errgroup.WithContext(ctx)

	if cfg.EnableSync {
		g.Go(func() error {
			return runSync(gctx, cfg, logger, syncSetup)
		})
	}

	if cfg.EnableMCP {
		g.Go(func() error {
			return runMCP(gctx, cfg, logger, appState)
		})
	}

	return g.Wait()
}

// syncSetupResult holds state from the pre-sync setup phase. This is
// performed in run() before any goroutines start, ensuring cfg.SyncDir
// is resolved before the MCP server reads it.
type syncSetupResult struct {
	appState *state.State
	client   *obsidian.Client
	token    string
	vault    *obsidian.VaultInfo
	keyHash  string
	cipher   *obsidian.CipherV0
	logger   *slog.Logger
}

// cleanup releases resources acquired during setup. The session token
// is intentionally kept valid so it can be reused on next launch,
// matching the Obsidian app's behavior.
func (s *syncSetupResult) cleanup() {
	s.appState.Close()
}

// setupSync performs authentication, vault selection, SyncDir resolution,
// and key derivation. It runs synchronously before any services start.
func setupSync(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*syncSetupResult, error) {
	appState, err := state.Load()
	if err != nil {
		return nil, fmt.Errorf("loading state: %w", err)
	}

	client := obsidian.NewClient(nil)

	token, vaultList, err := authenticate(ctx, client, cfg, appState, logger)
	if err != nil {
		appState.Close()
		return nil, err
	}

	v, err := selectVault(vaultList, cfg.VaultName)
	if err != nil {
		appState.Close()
		return nil, err
	}

	// Resolve SyncDir before any service starts.
	if cfg.SyncDir == "" {
		defaultDir, err := config.DefaultSyncDir(v.ID)
		if err != nil {
			appState.Close()
			return nil, fmt.Errorf("determining default sync dir: %w", err)
		}
		if err := cfg.SetSyncDir(defaultDir); err != nil {
			appState.Close()
			return nil, err
		}
		logger.Info("using default sync dir", slog.String("dir", cfg.SyncDir))
	}

	// Ensure the vault directory exists before runSync and runMCP
	// launch concurrently. Without this, runMCP can race ahead and
	// fail opening the vault before runSync creates the directory.
	if err := os.MkdirAll(cfg.SyncDir, 0755); err != nil {
		appState.Close()
		return nil, fmt.Errorf("creating vault directory: %w", err)
	}

	logger.Info("selected vault",
		slog.String("name", v.Name),
		slog.String("id", v.ID),
		slog.String("host", v.Host),
		slog.Int("encryption_version", v.EncryptionVersion),
	)

	logger.Info("deriving encryption key")
	key, err := obsidian.DeriveKey(cfg.VaultPassword, v.Salt)
	if err != nil {
		appState.Close()
		return nil, fmt.Errorf("deriving key: %w", err)
	}
	keyHash := obsidian.KeyHash(key)
	logger.Debug("key derived")

	cipher, err := obsidian.NewCipherV0(key)
	if err != nil {
		obsidian.ZeroKey(key)
		appState.Close()
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	obsidian.ZeroKey(key)

	return &syncSetupResult{
		appState: appState,
		client:   client,
		token:    token,
		vault:    v,
		keyHash:  keyHash,
		cipher:   cipher,
		logger:   logger,
	}, nil
}

// runSync starts the Obsidian sync daemon using a pre-computed setup result.
func runSync(ctx context.Context, cfg *config.Config, logger *slog.Logger, setup *syncSetupResult) error {
	v := setup.vault
	appState := setup.appState

	vs, err := appState.GetVault(v.ID)
	if err != nil {
		return fmt.Errorf("reading vault state: %w", err)
	}
	logger.Info("sync state",
		slog.Int64("version", vs.Version),
		slog.Bool("initial", vs.Initial),
	)

	vaultFS, err := obsidian.NewVault(cfg.SyncDir)
	if err != nil {
		return fmt.Errorf("creating vault directory: %w", err)
	}

	syncFilter := &obsidian.SyncFilter{
		MainSettings:       cfg.SyncMainSettings,
		Appearance:         cfg.SyncAppearance,
		ThemesAndSnippets:  cfg.SyncThemesAndSnippets,
		Hotkeys:            cfg.SyncHotkeys,
		ActiveCorePlugins:  cfg.SyncActiveCorePlugins,
		CorePluginSettings: cfg.SyncCorePluginSettings,
		CommunityPlugins:   cfg.SyncCommunityPlugins,
		InstalledPlugins:   cfg.SyncInstalledPlugins,
	}

	if err := appState.InitVaultBuckets(v.ID); err != nil {
		return fmt.Errorf("initializing vault buckets: %w", err)
	}

	syncClient := obsidian.NewSyncClient(obsidian.SyncConfig{
		Host:              v.Host,
		Token:             setup.token,
		VaultID:           v.ID,
		KeyHash:           setup.keyHash,
		Device:            cfg.DeviceName,
		EncryptionVersion: v.EncryptionVersion,
		Version:           vs.Version,
		Initial:           vs.Initial,
		Cipher:            setup.cipher,
		Vault:             vaultFS,
		State:             appState,
		Filter:            syncFilter,
		OnReady: func(version int64) {
			if err := appState.SetVault(v.ID, state.VaultState{
				Version: version,
				Initial: false,
			}); err != nil {
				logger.Warn("failed to save state", slog.String("error", err.Error()))
				return
			}
			logger.Info("state saved", slog.Int64("version", version))
		},
	}, logger)
	defer syncClient.Close()

	if err := syncClient.Connect(ctx); err != nil {
		return fmt.Errorf("connecting to sync server: %w", err)
	}

	var serverPushes []obsidian.ServerPush
	if err := syncClient.WaitForReady(ctx, &serverPushes); err != nil {
		return fmt.Errorf("waiting for server ready: %w", err)
	}

	scan, err := obsidian.ScanLocal(vaultFS, appState, v.ID, logger, syncFilter)
	if err != nil {
		return fmt.Errorf("scanning local files: %w", err)
	}

	reconciler := obsidian.NewReconciler(vaultFS, syncClient, appState, v.ID, setup.cipher, logger, syncFilter)
	if err := reconciler.Phase1(ctx, serverPushes, scan); err != nil {
		return fmt.Errorf("reconciliation phase 1 failed: %w", err)
	}
	serverPushes = nil

	sg, sgctx := errgroup.WithContext(ctx)
	sg.Go(func() error {
		return syncClient.Listen(sgctx)
	})

	if err := reconciler.Phase2And3(sgctx, scan); err != nil {
		logger.Warn("reconciliation phases 2-3 failed", slog.String("error", err.Error()))
	}

	watcher := obsidian.NewWatcher(vaultFS, syncClient, logger, syncFilter)
	sg.Go(func() error {
		return watcher.Watch(sgctx)
	})

	return sg.Wait()
}

// runMCP starts the MCP HTTP server. When appState is non-nil, OAuth
// tokens and client registrations are persisted across restarts.
func runMCP(ctx context.Context, cfg *config.Config, logger *slog.Logger, appState *state.State) error {
	users, err := cfg.ParseMCPUsers()
	if err != nil {
		return fmt.Errorf("parsing MCP auth users: %w", err)
	}

	mcpLogger := logger.With(slog.String("service", "mcp"))

	mcpLogger.Info("opening vault", slog.String("path", cfg.SyncDir))
	v, err := vault.New(cfg.SyncDir)
	if err != nil {
		return fmt.Errorf("opening vault: %w", err)
	}

	if vault.RgPath() != "" {
		mcpLogger.Info("ripgrep available for search", slog.String("path", vault.RgPath()))
	} else {
		mcpLogger.Debug("ripgrep not found, using built-in search")
	}

	mcpServer := mcp.NewServer(
		&mcp.Implementation{Name: "vault-sync-mcp", Version: Version},
		nil,
	)
	mcpserver.RegisterTools(mcpServer, v, mcpLogger)

	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return mcpServer
	}, nil)

	store := auth.NewStore(appState, mcpLogger)
	defer store.Stop()
	authMiddleware := auth.Middleware(store, cfg.MCPServerURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", auth.HandleProtectedResourceMetadata(cfg.MCPServerURL))
	mux.HandleFunc("/.well-known/oauth-authorization-server", auth.HandleAuthServerMetadata(cfg.MCPServerURL))
	mux.HandleFunc("/oauth/register", auth.HandleRegistration(store))
	mux.HandleFunc("/oauth/authorize", auth.HandleAuthorize(store, users, mcpLogger, cfg.MCPServerURL))
	mux.HandleFunc("/oauth/token", auth.HandleToken(store, cfg.MCPServerURL))
	mux.Handle("/mcp", authMiddleware(mcpHandler))

	server := &http.Server{
		Addr:         cfg.MCPListenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	mcpLogger.Info("starting MCP server",
		slog.String("listen", cfg.MCPListenAddr),
		slog.String("server_url", cfg.MCPServerURL),
		slog.Int("users", len(users)),
	)

	// Shutdown HTTP server when context is cancelled.
	go func() {
		<-ctx.Done()
		mcpLogger.Info("shutting down MCP server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	// Run the HTTP server and vault file watcher concurrently. The
	// watcher keeps the in-memory search index fresh when the sync
	// daemon (or any other process) writes files to the vault.
	mg, mctx := errgroup.WithContext(ctx)
	mg.Go(func() error {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("MCP server error: %w", err)
		}
		return nil
	})
	mg.Go(func() error {
		return v.Watch(mctx)
	})

	return mg.Wait()
}

const (
	retryMaxAttempts = 5
	retryBaseDelay   = 2 * time.Second
	retryMaxDelay    = 30 * time.Second
)

// retryDelay returns the backoff delay for the given attempt (0-indexed).
// Uses exponential backoff: 2s, 4s, 8s, 16s, 30s.
func retryDelay(attempt int) time.Duration {
	d := retryBaseDelay * time.Duration(math.Pow(2, float64(attempt)))
	if d > retryMaxDelay {
		d = retryMaxDelay
	}
	return d
}

func authenticate(ctx context.Context, client *obsidian.Client, cfg *config.Config, appState *state.State, logger *slog.Logger) (string, *obsidian.VaultListResponse, error) {
	if token := appState.Token(); token != "" {
		logger.Debug("trying cached token")
		vaults, err := client.ListVaults(ctx, token)
		if err == nil && (len(vaults.Vaults) > 0 || len(vaults.Shared) > 0) {
			logger.Info("authenticated with cached token")
			return token, vaults, nil
		}
		logger.Debug("cached token expired, signing in fresh")
	}

	var err error
	var authResp *obsidian.SigninResponse
	for attempt := range retryMaxAttempts {
		logger.Debug("signing in", slog.String("email", cfg.Email))
		authResp, err = client.Signin(ctx, cfg.Email, cfg.Password)
		if err == nil {
			break
		}
		if !obsidian.IsTransient(err) || attempt == retryMaxAttempts-1 {
			return "", nil, fmt.Errorf("signing in: %w", err)
		}
		delay := retryDelay(attempt)
		logger.Warn("signin failed, retrying",
			slog.String("error", err.Error()),
			slog.Int("attempt", attempt+1),
			slog.Duration("backoff", delay),
		)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return "", nil, ctx.Err()
		}
	}
	logger.Info("signed in")

	if err := appState.SetToken(authResp.Token); err != nil {
		logger.Warn("failed to save token", slog.String("error", err.Error()))
	}

	var vaults *obsidian.VaultListResponse
	for attempt := range retryMaxAttempts {
		vaults, err = client.ListVaults(ctx, authResp.Token)
		if err == nil {
			break
		}
		if !obsidian.IsTransient(err) || attempt == retryMaxAttempts-1 {
			return "", nil, fmt.Errorf("listing vaults: %w", err)
		}
		delay := retryDelay(attempt)
		logger.Warn("list vaults failed, retrying",
			slog.String("error", err.Error()),
			slog.Int("attempt", attempt+1),
			slog.Duration("backoff", delay),
		)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return "", nil, ctx.Err()
		}
	}

	if len(vaults.Vaults) == 0 && len(vaults.Shared) == 0 {
		return "", nil, fmt.Errorf("no vaults found for this account")
	}

	return authResp.Token, vaults, nil
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
	var all []string
	for _, v := range vaults.Vaults {
		all = append(all, v.Name)
	}
	for _, v := range vaults.Shared {
		all = append(all, v.Name+" (shared)")
	}
	return strings.Join(all, ", ")
}
