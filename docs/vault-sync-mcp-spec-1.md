# vault-sync MCP Server Specification

## Overview

An MCP server that exposes an Obsidian vault as a set of tools for reading, searching, and editing markdown notes. The server reads from a local directory that is kept in sync by the vault-sync daemon. It serves over Streamable HTTP transport using the official Go MCP SDK, with OAuth 2.1 authentication for use with Claude on the web, Claude Code, and other MCP clients.

## Architecture

```
Obsidian App ←→ Obsidian Sync Servers ←→ vault-sync daemon → Local Directory ← MCP Server → Claude (web/code)
```

The MCP server is a separate process from the sync daemon. It only reads/writes files on the local filesystem. It has no knowledge of the sync protocol — the daemon handles that independently.

## Configuration

All configuration via environment variables and/or CLI flags. Flags take precedence.

| Config | Env Var | Flag | Required | Description |
|--------|---------|------|----------|-------------|
| Vault path | `VAULT_PATH` | `--vault-path` | Yes | Absolute path to the vault root directory |
| Listen address | `LISTEN_ADDR` | `--listen-addr` | No | HTTP listen address. Default: `:8090` |
| Server URL | `SERVER_URL` | `--server-url` | Yes | External HTTPS URL clients use to reach this server (e.g. `https://vault.example.com`). Used as the OAuth resource identifier (RFC 8707) |
| Auth users | `AUTH_USERS` | `--auth-users` | Yes | Comma-separated `user:bcrypt_hash` pairs for login |
| Log level | `LOG_LEVEL` | `--log-level` | No | Log level. Default: `info` |

Passwords stored as bcrypt hashes. A CLI helper command generates hashes:

```bash
vault-sync-mcp hash-password
```

## OAuth 2.1 Implementation

The server acts as **both the resource server and the authorization server** (combined mode). This is the simplest architecture for a single-user homelab deployment. The official MCP Go SDK provides types for metadata documents and token handling via `auth` and `oauthex` packages; the authorization server logic (login form, code issuance, token exchange, DCR) is custom.

### MCP Auth Discovery Flow

When Claude (or any MCP client) connects, this is the full flow:

```
1. Client POSTs to /mcp (MCP endpoint)
   → Server returns 401 with:
     WWW-Authenticate: Bearer resource_metadata="https://vault.example.com/.well-known/oauth-protected-resource"

2. Client GETs /.well-known/oauth-protected-resource  (RFC 9728)
   → Returns Protected Resource Metadata including authorization_servers

3. Client GETs /.well-known/oauth-authorization-server  (RFC 8414)
   → Returns Authorization Server Metadata with all OAuth endpoints

4. Client POSTs to /oauth/register  (RFC 7591 — Dynamic Client Registration)
   → Client self-registers, receives a client_id

5. Client redirects user to /oauth/authorize with:
   - client_id, redirect_uri, state
   - code_challenge + code_challenge_method=S256  (PKCE)
   - resource=https://vault.example.com  (RFC 8707)

6. Server renders login form → user enters credentials

7. On valid credentials, server redirects to redirect_uri with code + state

8. Client POSTs to /oauth/token with:
   - grant_type=authorization_code, code, code_verifier, redirect_uri
   → Returns access_token (+ optional refresh_token)

9. All subsequent MCP requests include Authorization: Bearer <token>
```

### Endpoints

| Endpoint | Method | Purpose | RFC |
|----------|--------|---------|-----|
| `/.well-known/oauth-protected-resource` | GET | Protected resource metadata — advertises this server's resource identifier and which authorization server to use | RFC 9728 |
| `/.well-known/oauth-authorization-server` | GET | Authorization server metadata — lists all OAuth endpoints, supported grant types, PKCE methods, scopes | RFC 8414 |
| `/oauth/register` | POST | Dynamic Client Registration — Claude registers itself at runtime to get a `client_id` | RFC 7591 |
| `/oauth/authorize` | GET | Authorization endpoint — renders login form, validates credentials, redirects with auth code | OAuth 2.1 |
| `/oauth/token` | POST | Token endpoint — exchanges code + PKCE verifier for access token | OAuth 2.1 |
| `/mcp` | POST/GET | MCP endpoint (protected) — requires valid Bearer token | MCP Spec |

### Protected Resource Metadata (RFC 9728)

`GET /.well-known/oauth-protected-resource` returns:

```json
{
  "resource": "https://vault.example.com",
  "authorization_servers": ["https://vault.example.com"],
  "bearer_methods_supported": ["header"]
}
```

Uses `oauthex.ProtectedResourceMetadata` from the official SDK for the struct.

### Authorization Server Metadata (RFC 8414)

`GET /.well-known/oauth-authorization-server` returns:

```json
{
  "issuer": "https://vault.example.com",
  "authorization_endpoint": "https://vault.example.com/oauth/authorize",
  "token_endpoint": "https://vault.example.com/oauth/token",
  "registration_endpoint": "https://vault.example.com/oauth/register",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"]
}
```

**Critical:** `code_challenge_methods_supported` must include `"S256"` or Claude will refuse to complete the flow.

### Dynamic Client Registration (RFC 7591)

`POST /oauth/register` accepts:

```json
{
  "client_name": "Claude",
  "redirect_uris": ["https://claude.ai/oauth/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

Returns:

```json
{
  "client_id": "<generated-uuid>",
  "client_name": "Claude",
  "redirect_uris": ["https://claude.ai/oauth/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

Implementation: store registered clients in memory (map of client_id → client info). No client_secret issued (public clients using PKCE). Accept any redirect_uri at registration time.

### PKCE Verification

At `/oauth/token`, verify that `SHA256(code_verifier) == code_challenge` stored with the authorization code. Use `crypto/sha256` and `encoding/base64` (URL-safe, no padding). Reject if mismatch.

### 401 Response Format

When the MCP endpoint receives a request without a valid token:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://vault.example.com/.well-known/oauth-protected-resource"
```

This header bootstraps the entire discovery flow for MCP clients.

### Token Storage

In-memory maps. No database required.

| Item | Expiry | Storage |
|------|--------|---------|
| Authorization codes | 5 minutes | `map[string]Code` (code → client_id, redirect_uri, code_challenge, user_id, expiry) |
| Access tokens | 24 hours | `map[string]TokenInfo` (token → user_id, scopes, expiry) |
| Registered clients | No expiry (in-memory, lost on restart) | `map[string]ClientInfo` (client_id → name, redirect_uris) |

Tokens are opaque random strings (32 bytes, hex-encoded). On restart, all tokens are invalidated — Claude will re-authenticate.

## MCP Transport

Streamable HTTP transport as defined by the MCP specification (2025-03-26+). The official Go SDK's `mcp.StreamableHTTPHandler` handles the protocol:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/mcp` | POST | Client sends JSON-RPC messages, server responds (optionally via SSE for streaming) |
| `/mcp` | GET | Optional SSE stream for server-to-client notifications |

The `StreamableHTTPHandler` from `github.com/modelcontextprotocol/go-sdk/mcp` provides the `http.Handler`. Auth middleware wraps this handler to validate Bearer tokens before requests reach the MCP layer.

```go
mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
    return server
}, nil)

mux.Handle("/mcp", authMiddleware(mcpHandler))
```

## Tools

### vault_list_all

Returns a flat list of every file in the vault with metadata. No content. Intended as the AI's first call to get a complete map of the vault.

**Parameters:** None

**Response:**

```json
{
  "total_files": 247,
  "files": [
    {
      "path": "projects/vault-sync.md",
      "size": 2340,
      "modified": "2026-02-08T14:30:00Z",
      "tags": ["project", "go"]
    },
    {
      "path": "daily/2026-02-08.md",
      "size": 890,
      "modified": "2026-02-08T09:15:00Z",
      "tags": ["daily"]
    },
    {
      "path": "recipes/cold-brew.md",
      "size": 450,
      "modified": "2026-01-15T11:00:00Z",
      "tags": ["coffee", "recipe"]
    }
  ]
}
```

**Implementation notes:**
- Walk the vault directory recursively
- Parse YAML frontmatter from each `.md` file to extract tags
- Cache the file list and frontmatter in memory, invalidate on file mtime change
- Exclude `.obsidian/` directory and any hidden files/folders
- Include all file types present in the vault (images, PDFs, etc.) but only parse frontmatter for `.md` files

---

### vault_list

Lists contents of a specific folder, one level deep.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| path | string | No | `/` | Folder path relative to vault root |

**Response:**

```json
{
  "path": "/projects",
  "entries": [
    {
      "name": "vault-sync.md",
      "type": "file",
      "size": 2340,
      "modified": "2026-02-08T14:30:00Z"
    },
    {
      "name": "archive",
      "type": "folder",
      "children": 12
    }
  ],
  "total_entries": 15
}
```

**Implementation notes:**
- Read single directory, do not recurse
- For folders, count immediate children (files + subfolders)
- Return error if path does not exist or is outside vault root
- Path traversal protection: reject any path containing `..`

---

### vault_read

Reads file content with optional line-range pagination.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| path | string | Yes | - | File path relative to vault root |
| offset | integer | No | 1 | Start line (1-indexed, inclusive) |
| limit | integer | No | 0 | Number of lines to return. 0 = all remaining lines from offset |

**Response:**

```json
{
  "path": "projects/vault-sync.md",
  "total_lines": 347,
  "showing": [1, 100],
  "content": "# Vault Sync\n\nA Go library for..."
}
```

**Implementation notes:**
- Line numbers are 1-indexed to match how editors and Claude Code work
- When `offset` and `limit` are omitted, return the entire file
- If the file exceeds a configurable threshold (default: 200 lines), return only the first 200 lines and include `truncated: true` in the response so the AI knows to paginate
- Return error if file does not exist
- Support non-markdown files (return raw content)
- Path traversal protection: reject any path containing `..`

---

### vault_search

Full-text search across file names, content, and frontmatter tags.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| query | string | Yes | - | Search query |
| max_results | integer | No | 20 | Maximum number of results |

**Response:**

```json
{
  "query": "heating controller",
  "total_matches": 3,
  "results": [
    {
      "path": "projects/heating-system.md",
      "match_type": "content",
      "snippet": "...the Go-based **heating controller** communicates via MQTT...",
      "line": 14
    },
    {
      "path": "homelab/mqtt-setup.md",
      "match_type": "content",
      "snippet": "...used by the heating controller and other IoT devices...",
      "line": 7
    },
    {
      "path": "projects/home-automation.md",
      "match_type": "tag",
      "snippet": "tags: [heating, controller, go, mqtt]",
      "line": 3
    }
  ]
}
```

**Implementation notes:**
- Case-insensitive search
- Search in this order: file names/paths, frontmatter tags, file content
- `match_type` indicates where the match was found: `filename`, `tag`, or `content`
- Snippets should include surrounding context (~50 chars either side of match)
- Highlight the match in the snippet using markdown bold (`**match**`)
- `line` is the 1-indexed line number of the match, useful for follow-up `vault_read` with offset
- Consider using an in-memory index for performance (rebuild on file changes). Simple approach: load all files into memory on startup, re-read on mtime change. For vaults under ~1000 files this is fine.

---

### vault_write

Creates a new file or fully replaces an existing file.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| path | string | Yes | - | File path relative to vault root |
| content | string | Yes | - | Full file content |
| create_dirs | boolean | No | true | Create parent directories if they don't exist |

**Response:**

```json
{
  "path": "projects/new-idea.md",
  "created": true,
  "size": 1240,
  "total_lines": 45
}
```

**Implementation notes:**
- If file exists, `created` is `false` (it was overwritten)
- If file does not exist, `created` is `true`
- Create parent directories by default
- Write to a temp file first, then rename (atomic write) to avoid partial writes if sync picks up mid-write
- Path traversal protection: reject any path containing `..`
- Do not allow writing to `.obsidian/` directory
- Update in-memory index/cache after write

---

### vault_edit

Find-and-replace edit on an existing file. Mirrors the `str_replace` semantics that Claude is trained on.

**Parameters:**

| Name | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| path | string | Yes | - | File path relative to vault root |
| old_text | string | Yes | - | Exact text to find (must appear exactly once in the file) |
| new_text | string | Yes | - | Text to replace it with. Empty string to delete. |

**Response:**

```json
{
  "path": "projects/vault-sync.md",
  "replaced": true,
  "total_lines": 349
}
```

**Error cases:**

- File does not exist → error
- `old_text` not found in file → error with message "Text not found in file"
- `old_text` found multiple times → error with message "Text appears N times in file, must be unique"

**Implementation notes:**
- The entire `old_text` must match exactly (including whitespace and newlines)
- This is the same semantic as Claude Code's `str_replace` tool — Claude already knows how to use it effectively
- Atomic write (temp file + rename)
- Update in-memory index/cache after edit
- Path traversal protection

## Error Handling

All tool errors return a consistent structure:

```json
{
  "error": {
    "code": "FILE_NOT_FOUND",
    "message": "File not found: projects/nonexistent.md"
  }
}
```

Error codes:

| Code | Meaning |
|------|---------|
| `FILE_NOT_FOUND` | File or directory does not exist |
| `PATH_NOT_ALLOWED` | Path traversal attempt or write to protected directory |
| `TEXT_NOT_FOUND` | Edit target text not found in file |
| `TEXT_NOT_UNIQUE` | Edit target text appears multiple times |
| `INVALID_RANGE` | Read offset/limit out of bounds |
| `AUTH_REQUIRED` | Missing or invalid Bearer token |

## Project Structure

```
cmd/
  vault-sync-mcp/
    main.go              # Entry point, config loading, HTTP mux, server startup
internal/
  auth/
    metadata.go          # /.well-known/* endpoint handlers (uses oauthex types)
    registration.go      # Dynamic Client Registration (RFC 7591)
    authorize.go         # /oauth/authorize — login form + code issuance
    token.go             # /oauth/token — code exchange, PKCE verification
    middleware.go         # Bearer token validation, 401 with WWW-Authenticate
    store.go             # In-memory token, code, and client stores
  mcp/
    tools.go             # Tool registration and dispatch (vault_list_all, etc.)
  vault/
    vault.go             # Vault filesystem operations (read, write, list, search)
    index.go             # In-memory file index with frontmatter cache
    frontmatter.go       # YAML frontmatter parser
go.mod
go.sum
```

The `vault` package has no dependency on MCP or HTTP — it is a pure library for vault operations. The `mcp` package adapts it to MCP tool calls via the SDK. The `auth` package handles OAuth independently.

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/modelcontextprotocol/go-sdk/mcp` | Official MCP SDK — server, tool registration, `StreamableHTTPHandler` |
| `github.com/modelcontextprotocol/go-sdk/auth` | OAuth token primitives, `TokenInfo` |
| `github.com/modelcontextprotocol/go-sdk/oauthex` | `ProtectedResourceMetadata`, authorization server metadata types |
| `golang.org/x/crypto/bcrypt` | Password hashing for login credentials |
| `gopkg.in/yaml.v3` | Frontmatter parsing |
| Standard library | HTTP server, JSON, crypto/sha256, crypto/rand, file I/O |

## Reference Examples

These Go MCP servers implement OAuth and can be used as implementation references:

| Repository | Description | Key Patterns |
|-----------|-------------|--------------|
| [`wadahiro/go-mcp-server-example`](https://github.com/wadahiro/go-mcp-server-example) | Official SDK + Keycloak. Best reference for the resource server side — uses `oauthex.ProtectedResourceMetadata`, JWT validation middleware, `StreamableHTTPHandler`. Clean 2-file implementation. | `oauthex` types, middleware pattern, `mcp.NewStreamableHTTPHandler` |
| [`go-training/mcp-workshop/03-oauth-mcp`](https://github.com/go-training/mcp-workshop) | Workshop example with full OAuth server (authorize, token, register, metadata endpoints) built in Go. Separate oauth-server and mcp-server. Supports in-memory and Redis storage. | Full auth server implementation, DCR, PKCE, multiple providers |
| [`ggoodman/mcp-server-go`](https://github.com/ggoodman/mcp-server-go) | Independent MCP framework with built-in OAuth. Serves `/.well-known/oauth-protected-resource`, mirrors auth server metadata, emits `WWW-Authenticate` headers automatically. | `SecurityConfig` pattern, automatic metadata serving |

The `wadahiro` example is closest to our architecture (official SDK, middleware approach), but uses an external auth server (Keycloak). The `go-training` workshop example shows how to build the auth server endpoints themselves. We combine both: official SDK for MCP + resource server metadata, custom auth endpoints for the login flow.

## Deployment

Single binary. Runs as a systemd service on the homelab alongside the vault-sync daemon. Reverse proxied through existing setup (Caddy/nginx) with TLS termination. The `SERVER_URL` must match the external HTTPS URL that Claude will use.

**Important:** OAuth requires HTTPS. The reverse proxy must terminate TLS. The MCP server itself listens on HTTP (`:8090`) behind the proxy.

Example systemd unit:

```ini
[Unit]
Description=Vault Sync MCP Server
After=network.target vault-sync.service

[Service]
ExecStart=/usr/local/bin/vault-sync-mcp
Environment=VAULT_PATH=/data/obsidian-vault
Environment=LISTEN_ADDR=:8090
Environment=SERVER_URL=https://vault.example.com
Environment=AUTH_USERS=alex:$2a$10$...
Restart=always

[Install]
WantedBy=multi-user.target
```

## Known Issues & Considerations

- **Claude OAuth bugs:** Multiple developers report issues with Claude's OAuth implementation — scope handling, token refresh, DCR edge cases. Test early with the MCP Inspector before testing with Claude.
- **DCR is now MAY not MUST:** The latest MCP spec (2025-11-25) changed DCR from SHOULD to MAY. Claude still uses it in practice, so we implement it. If a client doesn't use DCR, they can be given a pre-configured client_id.
- **Token restart:** In-memory tokens are lost on restart. This is acceptable for a homelab — Claude re-authenticates automatically. For persistence, tokens could be written to a file or SQLite, but adds complexity for minimal benefit.
- **MCP spec evolution:** The auth spec is actively evolving. The `resource` parameter (RFC 8707) was added in the 2025-06-18 revision. Monitor the spec for changes.
