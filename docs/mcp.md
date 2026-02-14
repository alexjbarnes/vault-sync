# MCP Server

vault-sync includes an MCP (Model Context Protocol) server that exposes your vault to AI assistants like Claude. It serves over Streamable HTTP with OAuth 2.1 authentication.

## Quick Start

```bash
ENABLE_MCP=true \
MCP_SERVER_URL=https://vault.example.com \
MCP_AUTH_USERS=alice:secret123 \
OBSIDIAN_SYNC_DIR=/path/to/vault \
vault-sync
```

The server listens on `:8090` by default. Point your MCP client at `MCP_SERVER_URL`.

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `ENABLE_MCP` | Yes | `false` | Enable the MCP server |
| `MCP_SERVER_URL` | Yes | - | Public HTTPS URL for this server (used as OAuth resource identifier) |
| `MCP_AUTH_USERS` | Yes | - | Comma-separated `user:password` pairs for login |
| `MCP_LISTEN_ADDR` | No | `:8090` | HTTP listen address |
| `MCP_LOG_LEVEL` | No | `info` | Log level |
| `OBSIDIAN_SYNC_DIR` | When sync disabled | - | Path to vault directory (derived automatically when sync is enabled) |

## Tools

Eight tools are registered. All paths are relative to the vault root.

### vault_list

List vault contents.

- No path: returns every file with metadata (path, size, modified, tags)
- With path: lists one directory level, showing files and folder child counts

```json
{"path": "notes"}
```

### vault_read

Read file content with optional line-range pagination.

- Lines are 1-indexed
- Large files auto-truncate at 200 lines unless a limit is set

```json
{"path": "notes/hello.md", "offset": 1, "limit": 50}
```

### vault_search

Full-text search across file names, frontmatter tags, and file content. Uses ripgrep when available, falls back to a Go implementation.

- Case-insensitive
- Returns matching files with context snippets and line numbers
- Default max 20 results

```json
{"query": "project ideas", "max_results": 10}
```

### vault_write

Create a new file or replace an existing file. Uses atomic write (temp file + rename).

- Creates parent directories by default
- Cannot write to `.obsidian/`

```json
{"path": "notes/new.md", "content": "# New Note\n\nContent here."}
```

### vault_edit

Find-and-replace on an existing file. The old text must appear exactly once.

```json
{"path": "notes/hello.md", "old_text": "draft", "new_text": "final"}
```

### vault_delete

Delete one or more files. Best-effort: each file is attempted independently.

- Cannot delete directories or `.obsidian/` paths
- Failures reported per-item

```json
{"paths": ["notes/old.md", "archive/stale.md"]}
```

### vault_move

Move or rename a file. Creates destination parent directories automatically.

- Refuses to overwrite existing files
- Cannot move directories or `.obsidian/` paths

```json
{"source": "notes/draft.md", "destination": "archive/draft.md"}
```

### vault_copy

Copy a file. Creates destination parent directories automatically. Uses atomic write.

- Refuses to overwrite existing files
- Cannot copy directories or `.obsidian/` paths

```json
{"source": "templates/daily.md", "destination": "notes/2026-02-14.md"}
```

## Security

- All paths are validated against traversal attacks (`..` and symlink escape)
- `.obsidian/` is protected from read, write, edit, delete, move, and copy
- OAuth 2.1 with PKCE protects all tool endpoints
- Dynamic client registration supported
- Access tokens expire; refresh token rotation enabled

## Running Modes

vault-sync supports three configurations:

| Mode | `ENABLE_SYNC` | `ENABLE_MCP` | Use case |
|---|---|---|---|
| Sync only | `true` | `false` | Headless sync daemon |
| MCP only | `false` | `true` | Serve an existing vault directory |
| Both | `true` | `true` | Sync and serve in one process |
