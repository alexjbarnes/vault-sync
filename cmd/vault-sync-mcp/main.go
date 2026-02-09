package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/auth"
	"github.com/alexjbarnes/vault-sync/internal/mcpserver"
	"github.com/alexjbarnes/vault-sync/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/bcrypt"
)

var Version = "dev"

func main() {
	// Handle hash-password subcommand before flag parsing.
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

type config struct {
	VaultPath  string
	ListenAddr string
	ServerURL  string
	AuthUsers  string
	LogLevel   string
}

func loadConfig() *config {
	cfg := &config{}

	flag.StringVar(&cfg.VaultPath, "vault-path", os.Getenv("VAULT_PATH"), "path to vault root directory")
	flag.StringVar(&cfg.ListenAddr, "listen-addr", envOr("LISTEN_ADDR", ":8090"), "HTTP listen address")
	flag.StringVar(&cfg.ServerURL, "server-url", os.Getenv("SERVER_URL"), "external HTTPS URL for this server")
	flag.StringVar(&cfg.AuthUsers, "auth-users", os.Getenv("AUTH_USERS"), "comma-separated user:bcrypt_hash pairs")
	flag.StringVar(&cfg.LogLevel, "log-level", envOr("LOG_LEVEL", "info"), "log level (debug, info, warn, error)")
	flag.Parse()

	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// parseUsers parses "user1:hash1,user2:hash2" into a UserCredentials map.
func parseUsers(s string) (auth.UserCredentials, error) {
	users := make(auth.UserCredentials)
	if s == "" {
		return users, nil
	}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		// Split on first colon only, since bcrypt hashes contain colons... wait,
		// no they don't (they use $). But be safe: split on first colon.
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

func run() error {
	cfg := loadConfig()

	level := parseLogLevel(cfg.LogLevel)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if cfg.VaultPath == "" {
		return fmt.Errorf("VAULT_PATH or --vault-path is required")
	}
	if cfg.ServerURL == "" {
		return fmt.Errorf("SERVER_URL or --server-url is required")
	}
	if cfg.AuthUsers == "" {
		return fmt.Errorf("AUTH_USERS or --auth-users is required")
	}

	users, err := parseUsers(cfg.AuthUsers)
	if err != nil {
		return fmt.Errorf("parsing auth users: %w", err)
	}

	logger.Info("opening vault", slog.String("path", cfg.VaultPath))
	v, err := vault.New(cfg.VaultPath)
	if err != nil {
		return fmt.Errorf("opening vault: %w", err)
	}

	if vault.RgPath() != "" {
		logger.Info("ripgrep available for search", slog.String("path", vault.RgPath()))
	} else {
		logger.Debug("ripgrep not found, using built-in search")
	}

	// MCP server setup.
	mcpServer := mcp.NewServer(
		&mcp.Implementation{Name: "vault-sync-mcp", Version: Version},
		nil,
	)
	mcpserver.RegisterTools(mcpServer, v)

	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return mcpServer
	}, nil)

	// OAuth store.
	store := auth.NewStore()
	authMiddleware := auth.Middleware(store, cfg.ServerURL)

	// HTTP mux.
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", auth.HandleProtectedResourceMetadata(cfg.ServerURL))
	mux.HandleFunc("/.well-known/oauth-authorization-server", auth.HandleAuthServerMetadata(cfg.ServerURL))
	mux.HandleFunc("/oauth/register", auth.HandleRegistration(store))
	mux.HandleFunc("/oauth/authorize", auth.HandleAuthorize(store, users, logger))
	mux.HandleFunc("/oauth/token", auth.HandleToken(store))
	mux.Handle("/mcp", authMiddleware(mcpHandler))

	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Signal handling for graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	logger.Info("starting server",
		slog.String("listen", cfg.ListenAddr),
		slog.String("server_url", cfg.ServerURL),
		slog.Int("users", len(users)),
	)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}
