# vault-sync

[![CI](https://github.com/alexjbarnes/vault-sync/actions/workflows/ci.yml/badge.svg)](https://github.com/alexjbarnes/vault-sync/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/alexjbarnes/81bb8ec507bc7d99a603143e2c7e40a5/raw/coverage.json)](https://github.com/alexjbarnes/vault-sync/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Give any MCP-compatible AI assistant full access to your Obsidian vault. Read, search, create, and edit notes through natural language. Changes sync to every device through Obsidian Sync.

vault-sync connects to the [Obsidian Sync](https://obsidian.md/sync) service as a headless client and exposes your vault over [MCP](https://modelcontextprotocol.io/) (Model Context Protocol). Any MCP client (Claude, Cursor, Windsurf, custom agents) can work with your notes directly, and every change propagates to your phone, tablet, and desktop through the same sync service your vault already uses.

**This is an unofficial, third-party client.** It is not affiliated with or endorsed by Obsidian. Requires an active Obsidian Sync subscription. Use at your own risk.

## Running Modes

vault-sync is a single binary with two features that can be enabled independently.

| `ENABLE_SYNC` | `ENABLE_MCP` | Use case |
|---|---|---|
| `true` | `false` | Headless sync daemon. Keep a server or NAS in sync without running the desktop app. |
| `false` | `true` | MCP server only. Serve a vault directory that already exists on disk. |
| `true` | `true` | Full pipeline. Sync from Obsidian servers and serve to Claude in one process. |

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
docker compose -f docker/docker-compose.yml up -d
```

See the [getting started guide](docs/getting-started.md) for full setup instructions including HTTPS configuration and MCP client setup.

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
docs/                   MCP tool documentation
```

## Disclaimer

This is an unofficial, third-party client. It is not developed, maintained, or supported by the Obsidian team. The sync protocol is undocumented and may change without notice. No warranty is provided. The authors are not responsible for data loss or account issues.

## License

MIT
