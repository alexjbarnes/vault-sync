# Changelog

## v0.0.5

Initial public release.

- Two-way encrypted sync via WebSocket (AES-256-GCM, scrypt key derivation)
- Three-way merge for markdown files, shallow JSON merge for config files
- Real-time file watching with debounce and offline queue
- MCP server with 8 tools: list, read, search, write, edit, delete, move, copy
- OAuth 2.1 with PKCE, dynamic client registration, refresh token rotation
- Full-text search using ripgrep (with Go fallback)
- Cross-platform: Linux, macOS, Windows
- Docker support
