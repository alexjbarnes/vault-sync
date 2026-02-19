# OAuth Authentication

vault-sync supports two authentication flows: interactive (browser-based) and non-interactive (machine-to-machine).

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
2. The server validates the credentials and returns an access token and refresh token

Configure client credentials in `.env`:

```
MCP_CLIENT_CREDENTIALS=my-client:my-secret,another-client:another-secret
```

Use strong, random secrets. These are hashed at rest and never logged.

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
  "expires_in": 3600,
  "refresh_token": "def456..."
}
```

### Using the token

Include the access token in requests to the MCP endpoint:

```
Authorization: Bearer abc123...
```

### Token refresh

Access tokens expire after 1 hour. Use the refresh token to get a new one without re-authenticating:

```bash
curl -X POST https://your-server.example.com/oauth/token \
  -d grant_type=refresh_token \
  -d refresh_token=def456... \
  -d client_id=my-client
```

## Security

- Client secrets are hashed (SHA-256) at rest. The raw secret is never stored.
- Per-IP rate limiting on the token endpoint (5 failed attempts per minute).
- Per-client lockout after 10 consecutive failures (15 minute cooldown).
- Constant-time comparison for all credential validation.
- Dynamically registered clients cannot use the `client_credentials` flow. Only pre-configured clients from `MCP_CLIENT_CREDENTIALS` can.
- Pre-configured clients cannot use the interactive `authorization_code` flow.
