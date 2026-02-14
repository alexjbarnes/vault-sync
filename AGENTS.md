# AGENTS.md

## Project overview

vault-sync is a headless CLI that syncs an Obsidian vault using the Obsidian Sync protocol and optionally serves vault content over an MCP HTTP server with OAuth 2.1 auth. Single binary, no subcommands. The protocol spec lives in `docs/obsidian-sync-protocol.md`.

## Build and test commands

```bash
just build                          # build binary to bin/vault-sync
just test                           # go test -v -race ./...
just lint                           # golangci-lint run
just lint-fix                       # golangci-lint run --fix
just check                          # lint + test + build
just clean                          # remove bin/, coverage artifacts
just test-coverage                  # coverage report with total percentage
just test-coverage-pkg ./internal/state/...  # per-package coverage
just docker-build                   # build Docker image

go test -v -race ./internal/obsidian/...     # test one package
go test -v -race -run TestFoo ./internal/obsidian/...  # run a single test
go build ./...                      # check compilation without producing binary

# Cross-compile check (no CGO, must pass on all three):
GOOS=darwin go build ./...
GOOS=windows go build ./...
GOOS=linux go build ./...
```

Go version: 1.25.3 (see go.mod). Build tool is `justfile`, not Makefile.

## Project structure

```
cmd/vault-sync/         Entry point, orchestration, signal handling, retry logic
internal/
  auth/                 OAuth 2.1 server (authorize, token, registration, middleware)
  config/               Env var parsing (caarlos0/env + godotenv)
  errors/               Sentinel errors
  logging/              slog setup (JSON for production, text for development)
  mcpserver/            MCP tool registration (vault_list, vault_read, etc.)
  models/               Shared types (OAuthToken, OAuthClient) to break circular deps
  obsidian/             Sync protocol (client, crypto, sync, reconcile, scanner, watcher)
  state/                bbolt persistence (tokens, vault state, file tracking, OAuth)
  vault/                Vault access for MCP (file listing, search, editing, index)
docker/                 Dockerfile and docker-compose.yml
docs/                   Protocol spec, MCP docs
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
)
```

### Error handling

Wrap with `fmt.Errorf` using a lowercase gerund phrase and `%w`:

```go
return fmt.Errorf("reading pull response: %w", err)
```

Sentinel errors: `Err` prefix for exported, `err` prefix for unexported. Non-fatal errors log at Warn and continue. Fatal errors return up to `main()`.

### Logging

Use `log/slog` exclusively. Logger injected as `*slog.Logger`. Messages are short lowercase phrases. Errors are always `slog.String("error", err.Error())`, not `slog.Any`.

### Naming

- Constructors: `NewFoo(...)` returning `*Foo`
- Method receivers: single letter matching type (`s` for SyncClient, `v` for Vault)
- Acronyms: standard Go style (`VaultID`, `UID`, `baseURL`)
- Unexported helpers: descriptive lowercase (`hashFile`, `extractExtension`)

### Types

- Never use `any` or generics.
- Pointer receivers on all mutable structs.
- Small structs passed by value to setters, returned as pointer from getters (nil = not found).
- Platform-specific code uses `//go:build` constraints.

### Comments

- All exported symbols have godoc comments: `// TypeName does X.`
- Comments explain WHY, not WHAT.
- Do not reference the Obsidian app or app.js in comments.

### Formatting

- No trailing whitespace on any line, including blank lines.
- Blank lines between functions use zero whitespace characters.
- `gofumpt` is the formatter (runs via golangci-lint).

## Linting

22 linters + gofumpt formatter. All listed explicitly in `.golangci.yml`. Key rules:

- **gosec**: Per-line `//nolint:gosec // G<rule>: <reason>` annotations, not blanket exclusions. Disabled in test files via config.
- **mnd**: Extract all magic numbers to named constants. No nolint exceptions.
- **funlen**: 200 lines / 100 statements. No nolint needed at these thresholds.
- **gocognit**: Threshold 50. Disabled in test files.
- **testifylint**: `require` for error assertions, not `assert`. No `require` inside goroutines or HTTP handler closures (use `t.Errorf` + `return`).
- **nolintlint**: Enforces that all `//nolint` directives have a reason.
- **wsl_v5**: Enforces whitespace style (blank lines around blocks).

## Testing

- Table-driven tests with `t.Run` subtests.
- `stretchr/testify`: `require` for fatal preconditions, `assert` for assertions.
- Test helpers call `t.Helper()` and use `t.TempDir()` for filesystem tests.
- Mocks generated with `go.uber.org/mock` (gomock).
- HTTP tests use `net/http/httptest`.
- Tests live in the same package (not `_test` package).
- `Reconcile()` is a pure function; test it with values only, no I/O.

## Architecture notes

- `SyncClient` owns the WebSocket connection. All writes go through the event loop goroutine.
- `Reconcile()` is pure (no I/O), returns a decision enum. Executors perform I/O.
- `Vault` serializes filesystem access via `sync.RWMutex`.
- Config loaded from environment variables or `.env`. See `internal/config/config.go`.
- State persisted in `~/.vault-sync/state.db` (bbolt).
- Constructor-based dependency injection, no frameworks.
- Two `Vault` types: `internal/obsidian.Vault` (sync, RWMutex) and `internal/vault.Vault` (MCP, index/search).
- Interfaces only when needed for testing. Both (`wsConn`, `syncPusher`) are unexported.

## Things to avoid

- Never use `any` in Go code.
- Never commit `.env` (contains real credentials).
- Never use Cobra or other CLI frameworks. This project uses `flag` from stdlib.
- Do not create interfaces unless needed for testing or multiple implementations.
- The `Reconcile()` function must stay pure. Side effects go in executors.
- The protocol doc (`docs/obsidian-sync-protocol.md`) is the source of truth for sync behavior.
