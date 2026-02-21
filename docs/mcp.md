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

The server listens on `:8090` by default. Point your MCP client at `MCP_SERVER_URL` with `/mcp` appended (e.g. `https://vault.example.com/mcp`).

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `ENABLE_MCP` | Yes | `false` | Enable the MCP server |
| `MCP_SERVER_URL` | Yes | - | Base URL for this server, without `/mcp` (e.g. `https://vault.example.com`). Used as the OAuth resource identifier. MCP clients connect to `MCP_SERVER_URL/mcp`. |
| `MCP_AUTH_USERS` | Conditional | - | Comma-separated `user:password` pairs for the OAuth login page. Required unless `MCP_CLIENT_CREDENTIALS` or `MCP_API_KEYS` is set. |
| `MCP_CLIENT_CREDENTIALS` | No | - | Comma-separated `client_id:secret` pairs for headless OAuth (client_credentials flow) |
| `MCP_API_KEYS` | No | - | Comma-separated `user:vs_<hex>` pairs for static API key authentication |
| `MCP_LISTEN_ADDR` | No | `:8090` | HTTP listen address |
| `MCP_LOG_LEVEL` | No | `info` | Log level |
| `OBSIDIAN_SYNC_DIR` | When sync disabled | - | Path to vault directory (derived automatically when sync is enabled) |

At least one of `MCP_AUTH_USERS`, `MCP_CLIENT_CREDENTIALS`, or `MCP_API_KEYS` must be set.

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
- Three authentication methods: OAuth 2.1 (authorization code + PKCE, client credentials), API key
- Dynamic client registration supported for OAuth
- Access tokens expire; refresh token rotation enabled for auth code flow
- All secrets and tokens stored as SHA-256 hashes at rest


