# vault-sync

Unofficial headless CLI that syncs an Obsidian vault using the [Obsidian Sync](https://obsidian.md/sync) service and optionally serves it over MCP with OAuth 2.1 auth. Single binary, no subcommands.

This project is not affiliated with, endorsed by, or associated with Obsidian. It requires an active Obsidian Sync subscription. Use at your own risk.

## Features

- Two-way encrypted sync via WebSocket (AES-256-GCM, scrypt key derivation)
- Three-way merge for `.md` files, shallow JSON merge for `.obsidian/` config
- Real-time file watching with debounce and offline queue
- MCP server with 8 tools: list, read, search, write, edit, delete, move, copy ([docs](docs/mcp.md))
- OAuth 2.1 with PKCE, dynamic client registration, and refresh token rotation
- Full-text search using ripgrep (with Go fallback)
- Cross-platform: Linux, macOS, Windows

## Quick Start

```bash
cp .env.example .env    # fill in credentials
just build
./bin/vault-sync
```

Or with Docker:

```bash
docker compose -f docker/docker-compose.yml up
```

## Configuration

All configuration via environment variables or `.env` file.

### Sync

| Variable | Required | Description |
|---|---|---|
| `OBSIDIAN_EMAIL` | Yes | Account email |
| `OBSIDIAN_PASSWORD` | Yes | Account password |
| `OBSIDIAN_VAULT_PASSWORD` | Yes | Vault encryption password |
| `OBSIDIAN_VAULT_NAME` | No | Vault name (auto-detected if only one exists) |
| `OBSIDIAN_SYNC_DIR` | No | Local directory for vault files (defaults to `~/.vault-sync/vaults/<id>/`) |
| `ENABLE_SYNC` | No | Enable sync (default: `true`) |

### MCP Server

| Variable | Required | Description |
|---|---|---|
| `ENABLE_MCP` | No | Enable MCP server (default: `false`) |
| `MCP_SERVER_URL` | When MCP enabled | Public HTTPS URL (OAuth resource identifier) |
| `MCP_AUTH_USERS` | When MCP enabled | Comma-separated `user:password` pairs |
| `MCP_LISTEN_ADDR` | No | Listen address (default: `:8090`) |

### Config Sync Toggles

These control which `.obsidian/` files are synced. All default to `false`.

`SYNC_MAIN_SETTINGS`, `SYNC_APPEARANCE`, `SYNC_THEMES_SNIPPETS`, `SYNC_HOTKEYS`, `SYNC_ACTIVE_CORE_PLUGINS`, `SYNC_CORE_PLUGIN_SETTINGS`, `SYNC_COMMUNITY_PLUGINS`, `SYNC_INSTALLED_PLUGINS`

## Running Modes

| `ENABLE_SYNC` | `ENABLE_MCP` | Behavior |
|---|---|---|
| `true` | `false` | Sync daemon only |
| `false` | `true` | MCP server over an existing vault directory |
| `true` | `true` | Sync and serve in one process |

## Development

Requires Go 1.25+ and [just](https://github.com/casey/just).

```bash
just build              # build binary to bin/vault-sync
just test               # go test -v -race ./...
just lint               # golangci-lint run
just lint-fix           # golangci-lint run --fix
just check              # lint + test + build
just test-coverage      # run tests with coverage report
just docker-build       # build Docker image
just clean              # remove build artifacts
```

## Project Structure

```
cmd/vault-sync/         Entry point
internal/
  auth/                 OAuth 2.1 server
  config/               Environment variable parsing
  errors/               Sentinel errors
  logging/              Structured logging (slog)
  mcpserver/            MCP tool registration
  models/               Shared types
  obsidian/             Sync protocol implementation
  state/                bbolt persistence
  vault/                Read-only vault access for MCP
docker/                 Dockerfile and docker-compose.yml
docs/                   Protocol spec, MCP docs
```

## Disclaimer

This is an unofficial, third-party client. It is not developed, maintained, or supported by the Obsidian team. The sync protocol is undocumented and may change without notice. No warranty is provided. The authors are not responsible for data loss or account issues arising from use of this software.

## License

MIT
