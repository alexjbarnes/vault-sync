# Authentication

vault-sync supports three authentication methods: interactive OAuth (browser-based), headless OAuth (machine-to-machine), and static API keys.

## Interactive flow (authorization_code)

This is the default. MCP clients that support OAuth will handle it automatically.

1. The client discovers the OAuth endpoints via `/.well-known/oauth-authorization-server`
2. The client registers itself via `POST /oauth/register`
3. The client redirects the user's browser to `/oauth/authorize` with a PKCE challenge
4. The user logs in with credentials from `MCP_AUTH_USERS`
5. The server redirects back to the client with an authorization code
6. The client exchanges the code for an access token at `/oauth/token`

Configure users in `.env`:

```
MCP_AUTH_USERS=alice:her-password,bob:his-password
```

## Non-interactive flow (client_credentials)

For headless MCP clients that cannot open a browser. The client authenticates directly with a pre-configured client ID and secret.

1. The client sends `POST /oauth/token` with `grant_type=client_credentials`, `client_id`, and `client_secret`
2. The server validates the credentials and returns an access token (no refresh token)

Configure client credentials in `.env`:

```
MCP_CLIENT_CREDENTIALS=my-client:my-secret,another-client:another-secret
```

Secrets must be at least 16 characters. Use strong, random values. Secrets are hashed at rest and never logged.

### Example token request

```bash
curl -X POST https://your-server.example.com/oauth/token \
  -d grant_type=client_credentials \
  -d client_id=my-client \
  -d client_secret=my-secret
```

Response:

```json
{
  "access_token": "abc123...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

No refresh token is issued for client_credentials (RFC 6749 Section 4.4.3). The client already holds credentials to re-authenticate when the access token expires.

### Using the token

Include the access token in requests to the `/mcp` endpoint:

```
POST https://your-server.example.com/mcp
Authorization: Bearer abc123...
```

## API key authentication

For the simplest setup, use a static API key. Generate a key with 32 bytes of entropy:

```bash
echo "vs_$(openssl rand -hex 32)"
```

Configure in `.env`:

```
MCP_API_KEYS=myuser:vs_<64 hex chars>
```

Use the raw key as a Bearer token in requests to the `/mcp` endpoint:

```
POST https://your-server.example.com/mcp
Authorization: Bearer vs_<64 hex chars>
```

The `vs_` prefix lets the middleware route to API key validation instead of OAuth token lookup. Keys are stored as SHA-256 hashes at rest.

## Client compatibility notes

### Claude web (claude.ai)

Claude's connector settings show optional "OAuth Client ID" and "OAuth Client Secret" fields under Advanced. It may look like these fields are for the `client_credentials` flow — they are not.

When you populate those fields, Claude still initiates the interactive authorization code flow. It uses the provided `client_id` at `/oauth/authorize` instead of registering a new one via DCR, then expects a browser login page. Pre-configured clients in `MCP_CLIENT_CREDENTIALS` are locked to `client_credentials` only and will be rejected at the authorize endpoint.

**Leave those fields empty.** Claude will register itself via DCR and walk you through the browser login flow using your `MCP_AUTH_USERS` credentials. That is the correct path for Claude web.

The `client_credentials` grant exists as a [draft MCP extension](https://modelcontextprotocol.io/extensions/auth/oauth-client-credentials) but no major MCP client has shipped support for it yet.

### API key header injection

Some clients (e.g. OpenCode) allow you to configure arbitrary HTTP headers on the MCP connection. You can use this to inject an API key directly:

```
Authorization: Bearer vs_<your key>
```

This bypasses OAuth entirely and requires no browser interaction.

## Security

- Client secrets and API keys are hashed (SHA-256) at rest. Raw values are never stored.
- OAuth tokens are stored as SHA-256 hashes in bbolt. Raw tokens are never persisted.
- Per-IP rate limiting on the token endpoint (5 failed attempts per minute).
- Per-client lockout after 10 consecutive failures (15 minute cooldown).
- Constant-time comparison for all credential validation.
- Dynamically registered clients cannot use the `client_credentials` flow. Only pre-configured clients from `MCP_CLIENT_CREDENTIALS` can.
- Pre-configured clients cannot use the interactive `authorization_code` flow.
- Scopes are not implemented. All authenticated requests get full vault access.
