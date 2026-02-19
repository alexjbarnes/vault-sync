# Getting Started

This guide walks you through running vault-sync and connecting it to an MCP client.

## Prerequisites

- An [Obsidian Sync](https://obsidian.md/sync) subscription with at least one vault
- Your vault encryption password (set in the Obsidian desktop app under Settings > Sync)
- Docker (recommended), or a pre-built binary from [GitHub Releases](https://github.com/alexjbarnes/vault-sync/releases)

## 1. Configure

Copy the example config and fill in your credentials:

```bash
cp .env.example .env
```

Edit `.env` and set these values:

```
OBSIDIAN_EMAIL=your@email.com
OBSIDIAN_PASSWORD=your-obsidian-password
OBSIDIAN_VAULT_PASSWORD=your-vault-encryption-password
MCP_SERVER_URL=https://your-server.example.com
MCP_AUTH_USERS=alice:a-strong-password
```

If you have multiple vaults, set `OBSIDIAN_VAULT_NAME` to the one you want to sync. Otherwise it auto-detects.

## 2. Run with Docker (recommended)

```bash
docker compose -f docker/docker-compose.yml up -d
```

This pulls the latest image, starts the service, and persists vault data in a Docker volume. The MCP server listens on port 8090.

To check logs:

```bash
docker compose -f docker/docker-compose.yml logs -f
```

On first start, vault-sync will pull your entire vault from the Obsidian servers. This may take a few minutes depending on vault size. You will see log lines as files are downloaded and decrypted.

## 3. Run from pre-built binary (alternative)

Download the latest release for your platform from [GitHub Releases](https://github.com/alexjbarnes/vault-sync/releases).

```bash
# Linux (amd64)
tar xzf vault-sync_*_linux_amd64.tar.gz
./vault-sync

# macOS (Apple Silicon)
tar xzf vault-sync_*_darwin_arm64.tar.gz
./vault-sync

# Windows (amd64)
# Extract the zip, then run vault-sync.exe
```

Place the binary somewhere on your `PATH` if you want to run it from anywhere.

## 4. Build from source (alternative)

Requires Go 1.25+ and [just](https://github.com/casey/just).

```bash
git clone https://github.com/alexjbarnes/vault-sync.git
cd vault-sync
just build
./bin/vault-sync
```

## 5. Set MCP_SERVER_URL

`MCP_SERVER_URL` tells the OAuth flow where the server lives. For local use, plain HTTP works fine:

```
MCP_SERVER_URL=http://localhost:8090
```

If you want to access vault-sync from outside your machine, you need HTTPS. The easiest option is [Tailscale Funnel](https://tailscale.com/kb/1223/funnel), which gives you a public HTTPS URL with zero configuration and no domain or certificate management.

### Tailscale Funnel (recommended for remote access)

```bash
# Install Tailscale if you haven't already
# https://tailscale.com/download

tailscale funnel 8090
```

This gives you a URL like `https://your-machine.tail1234.ts.net`. Set `MCP_SERVER_URL` to that URL.

### Reverse proxy (alternative)

If you already have a domain and a server, use Caddy or nginx.

Caddy example (`Caddyfile`):

```
vault.yourdomain.com {
    reverse_proxy localhost:8090
}
```

Set `MCP_SERVER_URL` to your public URL (e.g. `https://vault.yourdomain.com`).

## 6. Authentication

vault-sync uses OAuth 2.1 with PKCE (authorization code flow). MCP clients that support OAuth handle this automatically. Here's what happens:

1. Your MCP client discovers the OAuth endpoints from vault-sync's `/.well-known/oauth-authorization-server`
2. The client registers itself via `/oauth/register` (one-time, automatic)
3. The client opens a browser window pointing to vault-sync's login page
4. You enter the username and password you configured in `MCP_AUTH_USERS`
5. vault-sync redirects back to the client with an authorization code
6. The client exchanges the code for an access token
7. The client uses the access token for all subsequent requests to `/mcp`

Access tokens expire after 1 hour. The client refreshes them automatically using a refresh token, so you only log in once.

### Headless authentication (no browser)

For automated pipelines and headless MCP clients that cannot open a browser, vault-sync supports the OAuth `client_credentials` flow. Pre-configure client credentials in `.env`:

```
MCP_CLIENT_CREDENTIALS=my-bot:a-strong-random-secret
```

The client authenticates by posting its `client_id` and `client_secret` directly to the token endpoint. No browser interaction is needed. See the [OAuth documentation](oauth.md) for request examples and details.

## 7. Connect an MCP client

Point your MCP client at the server URL.

### Claude Desktop

Add to your Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "vault-sync": {
      "url": "https://vault.yourdomain.com/mcp"
    }
  }
}
```

Claude will prompt you to authorize through the OAuth login page on first connection.

### Other MCP clients

Any MCP client that supports Streamable HTTP transport can connect. Point it at `https://your-server.example.com/mcp`. The client handles OAuth discovery and authentication automatically via the `/.well-known/oauth-authorization-server` endpoint.

## 8. Verify

Once connected, ask your assistant to list your vault:

> "List all files in my vault"

You should see your vault contents. Try reading a file, searching, or creating a new note to confirm two-way sync is working.

## Sync-only mode

If you just want to keep a server in sync without the MCP server:

```
ENABLE_SYNC=true
ENABLE_MCP=false
```

This runs vault-sync as a headless sync daemon. Useful for keeping a NAS or backup server up to date.

## Troubleshooting

**"vault not found"**: Check that `OBSIDIAN_VAULT_NAME` matches exactly, or remove it to auto-detect.

**"decryption failed"**: Your `OBSIDIAN_VAULT_PASSWORD` does not match the encryption password set in the Obsidian desktop app.

**OAuth login page not loading**: Make sure `MCP_SERVER_URL` matches the URL you are accessing. The OAuth flow validates the redirect URI against this value.

**Files not syncing**: Check logs for WebSocket connection errors. vault-sync reconnects automatically, but firewall rules or proxy timeouts can interfere.
