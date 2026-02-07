# Bugs and Issues

## Accepted Risk

### 19. 12-byte ciphertext bypasses GCM authentication
**File:** `obsidian/crypto.go:111-113`

Intentional for Obsidian app compatibility (empty files). A compromised server could send 12-byte payloads for any file and the client accepts it as empty content without authentication, silently wiping file contents. TLS mitigates this.
