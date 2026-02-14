# OAuth Refresh Token Support

## Problem

Access tokens expire after 24 hours. When the token expires, Claude (Android, iOS, web) forces a full re-authorization flow requiring user interaction. Other MCP services like Linear avoid this by issuing refresh tokens.

## Background

The MCP authorization spec (2025-06-18) requires that public clients (PKCE-only, no client secret) rotate refresh tokens on each use per OAuth 2.1 Section 4.3.1. Anthropic's documentation confirms Claude supports token refresh: "Claude supports token expiry and refresh -- servers should support this functionality in order to provide the best experience for users."

## Design

### Token lifetimes

| Token | Current | New |
|-------|---------|-----|
| Access token | 24 hours | 1 hour |
| Refresh token | N/A | 30 days |
| Auth code | 5 minutes | 5 minutes (unchanged) |

Short-lived access tokens limit exposure from leaks. The refresh token handles seamless renewal.

### Token model changes

Add three fields to `models.OAuthToken`:

- `Kind string` -- `"access"` or `"refresh"`. Tokens without a Kind (pre-existing) are treated as access tokens for backward compatibility.
- `RefreshToken string` -- On access tokens only. The associated refresh token string. Used to delete the refresh token when the access token is revoked by GC.
- `ClientID string` -- Which client this token was issued to. Validated during refresh to prevent cross-client token use.

### Storage

Refresh tokens are stored as `OAuthToken` entries in the existing `oauth_tokens` bbolt bucket and in-memory map. The `Kind` field distinguishes them from access tokens. No new buckets or maps needed.

The existing GC loop (5-minute interval) already reaps expired tokens regardless of kind.

### Token issuance (authorization_code grant)

When exchanging an auth code for tokens, the token endpoint now:

1. Generates a 32-byte random hex access token (unchanged)
2. Generates a 32-byte random hex refresh token (new)
3. Saves both to the store with appropriate Kind, expiry, and ClientID
4. Returns both in the response:

```json
{
  "access_token": "abc123...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "def456..."
}
```

### Token refresh (refresh_token grant)

New code path in the token endpoint for `grant_type=refresh_token`:

1. Parse `refresh_token`, `client_id`, and `resource` from request body
2. Look up the refresh token in the store
3. Validate: exists, not expired, Kind is `"refresh"`, client_id matches, resource matches
4. Delete the old refresh token (rotation)
5. Delete the old access token if still present
6. Issue new access token + new refresh token (same lifetimes as initial issuance)
7. Return new tokens in response

On any validation failure, return `400 invalid_grant`. This forces a full re-auth.

### Token rotation

Every refresh operation invalidates the old refresh token and issues a new one. This is mandatory for public clients per OAuth 2.1 and the MCP 2025-06-18 spec.

If a stolen refresh token is used after the legitimate client has already rotated, the request fails because the old token was deleted. No family-based revocation is needed given the single-user nature of this service.

### Metadata update

Add `"refresh_token"` to `GrantTypesSupported` in the auth server metadata at `/.well-known/oauth-authorization-server`.

### Middleware update

Add `error="invalid_token"` to the `WWW-Authenticate` header on 401 responses per RFC 6750 Section 3.1. This signals to Claude that the token has expired and it should attempt a refresh before falling back to full re-auth.

Current:
```
WWW-Authenticate: Bearer resource_metadata="https://..."
```

New:
```
WWW-Authenticate: Bearer error="invalid_token", resource_metadata="https://..."
```

## Files changed

| File | Change |
|------|--------|
| `internal/models/oauth.go` | Add Kind, RefreshToken, ClientID fields to OAuthToken |
| `internal/auth/token.go` | Add refreshTokenExpiry constant, refresh_token grant handling, issue refresh tokens on auth_code grant |
| `internal/auth/store.go` | Add ValidateRefreshToken method, add DeleteToken method |
| `internal/auth/metadata.go` | Add "refresh_token" to GrantTypesSupported |
| `internal/auth/middleware.go` | Add error="invalid_token" to WWW-Authenticate header |
| `internal/auth/auth_test.go` | New tests for refresh flow |
| `internal/state/state.go` | No changes (existing bucket and methods handle new token kind) |

## Backward compatibility

- Existing access tokens in bbolt have no `Kind` field. On load, tokens with empty Kind are treated as `"access"` tokens. They continue to work until they expire (within 24 hours of the upgrade).
- Existing clients re-authorize after their current access token expires. The new auth code exchange issues a refresh token, and subsequent refreshes are seamless.
- The bbolt bucket structure is unchanged. No migration needed.

## Not included

- Token revocation endpoint (RFC 7009). For a single-user service, revoking tokens can be done by deleting the bbolt database or restarting with a fresh state.
- Scope enforcement on refresh. Scopes are carried through the auth flow but not validated. This is a pre-existing gap unrelated to refresh tokens.
- Family-based revocation. Token rotation with immediate deletion is sufficient.

## Test plan

| Test | Description |
|------|-------------|
| TestToken_FullFlowWithRefresh | Auth code exchange returns access_token and refresh_token |
| TestToken_RefreshGrant | Exchange refresh token for new access + refresh tokens |
| TestToken_RefreshRotation | Old refresh token is invalid after use |
| TestToken_RefreshExpired | Expired refresh token returns 400 |
| TestToken_RefreshWrongClient | Refresh token from different client is rejected |
| TestToken_RefreshWrongResource | Mismatched resource is rejected |
| TestToken_RefreshMissingToken | Missing refresh_token field returns 400 |
| TestMiddleware_ExpiredTokenHeader | 401 includes error="invalid_token" in WWW-Authenticate |
| TestStore_ValidateRefreshToken | Validates kind and expiry |
| TestStore_DeleteToken | Explicit token deletion |
