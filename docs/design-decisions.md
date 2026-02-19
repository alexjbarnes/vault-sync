# Design Decisions

## Credential storage

### Login passwords (MCP_AUTH_USERS)

Stored in the `.env` file and held in-memory as a plaintext map. Never written to bbolt or any persistent store.

Bcrypt is not used because anyone with access to the `.env` file already has the passwords. The in-memory map is the only other copy. Process memory dumping is outside the threat boundary for this deployment model.

### Client secrets (MCP_CLIENT_CREDENTIALS)

Persisted to bbolt as SHA-256 hashes. The plaintext is cleared from the config struct after hashing at startup.

SHA-256 was chosen over bcrypt because these are machine-generated secrets with high entropy (operators should use long random strings). This matches the pattern used by GitHub (personal access tokens), Stripe (API keys), and similar production systems for machine-to-machine credentials.

Bcrypt would protect against low-entropy secrets but adds the `golang.org/x/crypto` dependency and approximately 100ms of CPU time per authentication request. For high-entropy random secrets, SHA-256 is computationally infeasible to brute-force offline (256 bits of search space).

## Token design

### Access tokens

32 random bytes, hex-encoded (256 bits of entropy). 1 hour expiry. Bound to a resource (server URL) per RFC 8707.

### Refresh tokens

32 random bytes, hex-encoded. 30 day expiry. Single-use with rotation: consumed on use, new token pair issued. Bound to the issuing client_id to prevent cross-client token theft.

### Authorization codes

32 random bytes, hex-encoded. 5 minute expiry. Single-use (consumed on exchange). Bound to client_id, redirect_uri, PKCE challenge, and resource.

## Authentication flows

### Authorization code (interactive)

PKCE is mandatory, S256 only. The plain challenge method is not supported.

The login form includes a CSRF token bound to the specific client_id and redirect_uri to prevent cross-site form submission and cross-client CSRF reuse.

### Client credentials (headless)

Only available to pre-configured clients from `MCP_CLIENT_CREDENTIALS`. Cannot be obtained through dynamic client registration. Pre-configured clients cannot use the authorization_code flow. Grant types are mutually exclusive between the two client types.

## Rate limiting and lockout

### Token endpoint

Per-IP sliding window: 5 failed attempts per minute. Per-client_id lockout: 10 consecutive failures triggers a 15 minute lock. Lockout resets on successful authentication.

### Login endpoint

Per-IP sliding window: 10 failed attempts per 5 minutes.

### Registration endpoint

Global rate limit: 10 registrations per minute.

## Scope enforcement

Scopes (`vault:read`, `vault:write`) are advertised in server metadata for forward compatibility. They are not currently enforced. All authenticated requests get full vault access.

This is a single-purpose server with one resource (the vault). Per-scope enforcement adds complexity without meaningful access control benefit today.

## Client registration

### Dynamic registration (RFC 7591)

Allowed grant types: `authorization_code` only. Requests for `client_credentials` are rejected at registration time. Maximum 100 registered clients to prevent unbounded growth from unauthenticated registration requests. Client IDs are 16 random bytes, hex-encoded.

### Pre-configured clients

Registered at startup from `MCP_CLIENT_CREDENTIALS`. These bypass the 100 client cap since they are operator-managed. Stored with a SHA-256 hashed secret and the `client_credentials` grant type.
