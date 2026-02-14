# AGENTS.md

## Project overview

vault-sync is a headless CLI that syncs an Obsidian vault using the Obsidian Sync protocol and optionally serves vault content over an MCP HTTP server with OAuth 2.1 auth. Single binary, no subcommands. The protocol spec lives in `docs/obsidian-sync-protocol.md`.

## Build and test commands

```bash
just build                          # build binary to bin/vault-sync
just test                           # go test -v -race ./...
just lint                           # golangci-lint run
just check                          # lint + test + build
just clean                          # remove bin/, coverage artifacts

go test -v -race ./internal/obsidian/...     # test one package
go test -v -race -run TestFoo ./internal/obsidian/...  # run a single test
go build ./...                      # check compilation without producing binary
go vet ./...                        # static analysis

# Cross-compile check (no CGO, must pass on all three):
GOOS=darwin go build ./...
GOOS=windows go build ./...
GOOS=linux go build ./...
```

Go version: 1.25.3 (see go.mod). Build tool is `justfile`, not Makefile.

## Project structure

```
cmd/vault-sync/main.go       Entry point, orchestration, signal handling, retry logic
internal/
  auth/                       OAuth 2.1 server (authorize, token, registration, middleware, store)
  config/                     Env var parsing (caarlos0/env + godotenv)
  errors/                     Sentinel errors
  logging/                    slog setup (JSON for production, text for development)
  mcpserver/                  MCP tool registration (vault_list, vault_read, etc.)
  models/                     Shared types (OAuthToken, OAuthClient) to break circular deps
  obsidian/                   Obsidian Sync protocol implementation
    client.go                 REST API client (signin, signout, list vaults, transient retry)
    types.go                  All JSON message types (REST + WebSocket)
    crypto.go                 scrypt key derivation, AES-GCM encrypt/decrypt
    sync.go                   WebSocket sync client, event loop, push/pull
    reconcile.go              Reconciliation decision tree + three-phase startup
    scanner.go                Local filesystem scan + diff against persisted state
    vault.go                  Thread-safe filesystem operations + path normalization
    watcher.go                fsnotify watcher with debounce + offline queue
    filter.go                 Config sync filter (.obsidian/ path filtering)
    ctime_{linux,darwin,other}.go  Platform-specific ctime extraction
  state/                      bbolt persistence (tokens, vault state, file tracking, OAuth)
  vault/                      Read-only vault access for MCP (file listing, search, editing, index)
```

All packages live under `internal/`. `cmd/` is the entry point only.

## Code style

### Imports

Two groups separated by a blank line. Stdlib first, then external and internal mixed alphabetically:

```go
import (
    "context"
    "fmt"
    "log/slog"

    "github.com/alexjbarnes/vault-sync/internal/state"
    "github.com/coder/websocket"
    "github.com/tidwall/gjson"
)
```

### Error handling

Wrap with `fmt.Errorf` using a lowercase gerund phrase and `%w`:

```go
return fmt.Errorf("reading pull response: %w", err)
return fmt.Errorf("creating directory for %s: %w", relPath, err)
```

Sentinel errors use `errors.New()` with `Err` prefix for exported, `err` prefix for unexported:

```go
var ErrVaultNotFound = errors.New("vault not found")
var errResponseTimeout = fmt.Errorf("response timed out")
```

Non-fatal errors are logged at Warn and execution continues. Fatal errors are returned up to `main()`.

### Logging

Use `log/slog` exclusively. Logger is injected as `*slog.Logger` parameter. Structured fields via typed helpers. Messages are short lowercase phrases:

```go
s.logger.Info("pushed", slog.String("path", path), slog.Int("bytes", len(content)))
s.logger.Warn("stat failed", slog.String("path", relPath), slog.String("error", err.Error()))
```

Errors are always `slog.String("error", err.Error())`, not `slog.Any`.

### Naming

- Constructors: `NewFoo(...)` returning `*Foo`
- Method receivers: single letter matching type (`s` for SyncClient, `v` for Vault, `r` for Reconciler)
- Acronyms: standard Go style (`VaultID`, `UID`, `baseURL`)
- Enum constants: typed int with prefix (`DecisionSkip`, `DecisionDownload`)
- Unexported helpers: descriptive lowercase (`hashFile`, `extractExtension`, `isPermanentError`)

### Types

- Never use `any`. The few places that use `interface{}` are JSON serialization boundaries.
- No generics.
- Pointer receivers on all mutable structs.
- Small structs passed by value to setters, returned as pointer from getters (nil = not found).
- Platform-specific code uses `//go:build` constraints.

### Comments

- All exported symbols have godoc comments: `// TypeName does X.`
- Comments explain WHY, not WHAT. Protocol rationale is documented inline.
- Do not reference the Obsidian app or app.js in comments.

### Formatting

- No trailing whitespace on any line, including blank lines.
- Blank lines between functions use zero whitespace characters.
- `gofmt` standard formatting. No custom formatter config.

## Testing

- Table-driven tests with `t.Run` subtests are the primary pattern.
- Use `stretchr/testify`: `require` for fatal preconditions, `assert` for assertions.
- Test helpers call `t.Helper()` and use `t.TempDir()` for filesystem tests.
- Mocks generated with `go.uber.org/mock` (gomock) for `wsConn` and `syncPusher` interfaces.
- HTTP tests use `net/http/httptest` for server mocking.
- Tests live in the same package (not `_test` package).
- `Reconcile()` is a pure function; test it with values only, no I/O.

## Architecture notes

- `SyncClient` owns the WebSocket connection. All writes go through the event loop goroutine. Reads go through a reader goroutine that posts to `inboundCh`.
- `Reconcile()` is a pure function (no I/O) that returns a decision enum. Executors perform the I/O.
- `Vault` serializes all filesystem access via `sync.RWMutex`.
- Config is loaded from environment variables (or `.env` file). See `internal/config/config.go`.
- State is persisted in `~/.vault-sync/state.db` (bbolt). OAuth tokens and clients are also persisted there.
- Constructor-based dependency injection, no frameworks.
- Two `Vault` types exist: `internal/obsidian.Vault` (sync-oriented, RWMutex) and `internal/vault.Vault` (MCP-oriented, with index and search).
- Interfaces are only created when needed for testing. Both (`wsConn`, `syncPusher`) are unexported with minimal surface area.

## Dependencies

- `coder/websocket` for WebSocket (nhooyr fork)
- `bbolt` for persistent state
- `gjson` for peeking at JSON fields without full unmarshal
- `go-diff/diffmatchpatch` for three-way merge of .md files
- `fsnotify` for file watching
- `golang.org/x/text` for Unicode normalization (NFC, NFKC)
- `golang.org/x/crypto` for scrypt
- `modelcontextprotocol/go-sdk` for MCP server
- `go.uber.org/mock` for test mock generation
- `stretchr/testify` for test assertions

## Things to avoid

- Never use `any` in Go code.
- Never commit `.env` (contains real credentials). It is in `.gitignore`.
- Never use Cobra or other CLI frameworks. This project uses `flag` from stdlib.
- Do not add unnecessary documentation files or READMEs.
- Do not create interfaces unless they have multiple implementations or are needed for testing.
- The `Reconcile()` function must stay pure (no I/O). Side effects go in executors.
- The protocol doc (`docs/obsidian-sync-protocol.md`) is the source of truth for sync behavior.
