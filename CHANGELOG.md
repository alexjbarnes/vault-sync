# Changelog

## v1.1.0

### Added

- OAuth `client_credentials` grant for headless MCP clients (`MCP_CLIENT_CREDENTIALS`)
- API key authentication (`MCP_API_KEYS`) with `vs_` prefix format
- Dynamic client registration (RFC 7591) with `authorization_code` and `refresh_token` grant types
- `client_secret_basic` (HTTP Basic) authentication on the token endpoint
- `iss` parameter in authorization responses (RFC 9207)
- `client_id_issued_at` in DCR responses
- `Pragma: no-cache` on token responses
- `scope` field in token responses (echoed from request, not enforced)
- Enriched MCP tool call logs with user, client_id, and remote IP
- `DEVICE_NAME` environment variable
- Dev image CI workflow and scheduled cleanup for old dev images

### Changed

- `MCP_AUTH_USERS` no longer required when `MCP_CLIENT_CREDENTIALS` or `MCP_API_KEYS` is set
- Pre-configured clients restricted to `client_credentials` grant only (cannot use authorization code flow)
- OAuth tokens stored as SHA-256 hashes in bbolt (raw tokens never persisted)
- Scopes removed from OAuth metadata endpoints (never enforced, removed to avoid false promises)
- DCR validates `token_endpoint_auth_method` against supported values
- Redirect URI validation for clients with no registered URIs now only accepts loopback addresses
- Extracted HTTP mux construction into `internal/server/mux.go`

### Fixed

- Sync feedback loop: local delete echoed back to server when fsnotify fired before state cleanup
- Password timing leak: SHA-256 normalization before constant-time comparison
- CSRF ordering: rate limit check moved before CSRF token consumption
- Authorization errors now redirect per RFC 6749 Section 4.1.2.1 (were plain text)
- Loopback redirect URI matching uses URL-parsed hostname (prevents `127.0.0.1.evil.com` bypass)
- `response_type` validation on authorize endpoint (now requires `response_type=code`)
- Confidential DCR clients now receive a generated `client_secret`
- DCR fields (`response_types`, `token_endpoint_auth_method`) persisted on client model
- Authorization code scopes now stored and carried through to token response
- Refresh token grant type allowed alongside authorization_code in DCR
- Content-Type validation on DCR requests (requires `application/json`)
- MCP SSE connections dropped after 60 seconds due to HTTP server write timeout (now disabled)
- Clean shutdown logged as error and exited with code 1 due to `context.Canceled` propagating through errgroup
- `liveMergeMD` trivial cases did not update hash cache, causing spurious re-uploads on every subsequent sync write

### Security

- OAuth tokens hashed at rest (SHA-256)
- API keys hashed at rest (SHA-256) with constant-time validation
- Client secrets cleared from config struct after hashing at startup
- API keys cleared from config struct after registration
- Stale API keys purged from bbolt on startup reconciliation
- Rate limiting and client lockout on token endpoint
- Symlink bypass in vault index and search (symlinks to files outside vault no longer indexed)
- Authorize endpoint rejects clients not authorized for authorization code flow
- `MCP_LOG_LEVEL` environment variable now wired to logger (was parsed but ignored)
- `localhost` rejected as loopback (literal IPs only per RFC 8252 Section 8.3)

## v1.0.0

Initial public release.

### Added

- Two-way encrypted sync via WebSocket (AES-256-GCM, scrypt key derivation)
- Three-way merge for markdown files, shallow JSON merge for config files
- Real-time file watching with debounce and offline queue
- MCP server with 8 tools: `vault_list`, `vault_read`, `vault_search`, `vault_write`, `vault_edit`, `vault_delete`, `vault_move`, `vault_copy`
- OAuth 2.1 with PKCE, dynamic client registration (RFC 7591), refresh token rotation
- Interactive login page for browser-based OAuth flows
- Full-text search using ripgrep with pure-Go fallback
- Vault file index with incremental updates via fsnotify
- bbolt persistence for OAuth clients, tokens, and sync state
- Per-IP rate limiting and per-client lockout on auth endpoints
- CSRF protection on the authorization endpoint
- `ENABLE_SYNC` and `ENABLE_MCP` feature flags for running sync-only or MCP-only
- Cross-platform builds: Linux, macOS, Windows (amd64 and arm64)
- Docker support with `docker-compose.yml`
- CI/CD with GitHub Actions: lint, test (80% coverage gate), build, cross-compile, secret scanning
- goreleaser for automated release builds and GitHub release creation
- `.env` file support with insecure permissions warning at startup
