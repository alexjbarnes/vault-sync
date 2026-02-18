# Contributing

Contributions are welcome. This document covers the basics for getting a PR merged.

## Getting Started

```bash
# Clone and build
git clone https://github.com/alexjbarnes/vault-sync.git
cd vault-sync
cp .env.example .env
just build

# Run the full check suite (lint + test + build)
just check
```

Requires Go 1.25+ and [just](https://github.com/casey/just).

## Before Submitting a PR

1. Run `just check` and make sure it passes (lint, test, build)
2. Add tests for new functionality
3. Keep commits focused on a single change

## Architecture

- `internal/obsidian/` handles the sync protocol (WebSocket, encryption, reconciliation)
- `internal/vault/` provides read/write vault access for MCP tools
- `internal/auth/` implements OAuth 2.1 with PKCE
- `internal/mcpserver/` registers MCP tool handlers
- `internal/state/` persists state in bbolt
- `cmd/vault-sync/` is the entry point only

Key design rules:
- `Reconcile()` is a pure function (no I/O). Side effects go in executors.
- `SyncClient` owns the WebSocket. All writes go through the event loop goroutine.
- `Vault` serializes filesystem access via `sync.RWMutex`.
- Constructor-based dependency injection, no frameworks.
