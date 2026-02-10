package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
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
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/errgroup"
)

var Version = "dev"

func main() {
	// Handle hash-password subcommand before config loading.
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		hashPassword()
		return
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func hashPassword() {
	fmt.Fprint(os.Stderr, "Enter password: ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		fmt.Fprintln(os.Stderr, "no input")
		os.Exit(1)
	}
	password := scanner.Text()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(hash))
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

	g, gctx := errgroup.WithContext(ctx)

	if cfg.EnableSync {
		g.Go(func() error {
			return runSync(gctx, cfg, logger)
		})
	}

	if cfg.EnableMCP {
		g.Go(func() error {
			return runMCP(gctx, cfg, logger)
		})
	}

	return g.Wait()
}

// runSync starts the Obsidian sync daemon.
func runSync(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	appState, err := state.Load()
	if err != nil {
		return fmt.Errorf("loading state: %w", err)
	}
	defer appState.Close()

	client := obsidian.NewClient(nil)

	token, vaultList, err := authenticate(ctx, client, cfg, appState, logger)
	if err != nil {
		return err
	}

	v, err := selectVault(vaultList, cfg.VaultName)
	if err != nil {
		return err
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
		return fmt.Errorf("deriving key: %w", err)
	}
	keyHash := obsidian.KeyHash(key)
	logger.Debug("key derived", slog.String("keyhash_prefix", keyHash[:16]))

	cipher, err := obsidian.NewCipherV0(key)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}

	vs, err := appState.GetVault(v.ID)
	if err != nil {
		return fmt.Errorf("reading vault state: %w", err)
	}
	logger.Info("sync state",
		slog.Int64("version", vs.Version),
		slog.Bool("initial", vs.Initial),
	)

	vaultFS := obsidian.NewVault(cfg.SyncDir)

	if err := appState.InitVaultBuckets(v.ID); err != nil {
		return fmt.Errorf("initializing vault buckets: %w", err)
	}

	syncClient := obsidian.NewSyncClient(obsidian.SyncConfig{
		Host:              v.Host,
		Token:             token,
		VaultID:           v.ID,
		KeyHash:           keyHash,
		Device:            cfg.DeviceName,
		EncryptionVersion: v.EncryptionVersion,
		Version:           vs.Version,
		Initial:           vs.Initial,
		Cipher:            cipher,
		Vault:             vaultFS,
		State:             appState,
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

	scan, err := obsidian.ScanLocal(vaultFS, appState, v.ID, logger)
	if err != nil {
		return fmt.Errorf("scanning local files: %w", err)
	}

	reconciler := obsidian.NewReconciler(vaultFS, syncClient, appState, v.ID, cipher, logger)
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

	watcher := obsidian.NewWatcher(vaultFS, syncClient, logger)
	sg.Go(func() error {
		return watcher.Watch(sgctx)
	})

	return sg.Wait()
}

// runMCP starts the MCP HTTP server.
func runMCP(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
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
	mcpserver.RegisterTools(mcpServer, v)

	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return mcpServer
	}, nil)

	store := auth.NewStore()
	defer store.Stop()
	authMiddleware := auth.Middleware(store, cfg.MCPServerURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", auth.HandleProtectedResourceMetadata(cfg.MCPServerURL))
	mux.HandleFunc("/.well-known/oauth-authorization-server", auth.HandleAuthServerMetadata(cfg.MCPServerURL))
	mux.HandleFunc("/oauth/register", auth.HandleRegistration(store))
	mux.HandleFunc("/oauth/authorize", auth.HandleAuthorize(store, users, mcpLogger))
	mux.HandleFunc("/oauth/token", auth.HandleToken(store))
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

	// Shutdown when context is cancelled.
	go func() {
		<-ctx.Done()
		mcpLogger.Info("shutting down MCP server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("MCP server error: %w", err)
	}

	return nil
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

	logger.Info("signing in", slog.String("email", cfg.Email))
	authResp, err := client.Signin(ctx, cfg.Email, cfg.Password)
	if err != nil {
		return "", nil, fmt.Errorf("signing in: %w", err)
	}
	logger.Info("signed in", slog.String("name", authResp.Name), slog.String("email", authResp.Email))

	if err := appState.SetToken(authResp.Token); err != nil {
		logger.Warn("failed to save token", slog.String("error", err.Error()))
	}

	vaults, err := client.ListVaults(ctx, authResp.Token)
	if err != nil {
		return "", nil, fmt.Errorf("listing vaults: %w", err)
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
