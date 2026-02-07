# Bugs and Issues

## Fixed

### 1. Path traversal on decrypted server paths
**Status:** Fixed in `obsidian/vault.go:110`

`Vault.resolve()` rejects any path that resolves outside the sync directory via prefix check. SyncDir is resolved to absolute at config load time.

### 2. Deadlock if pushCh fills during pull
**Status:** Fixed

`pushCh` and the dispatcher goroutine no longer exist. The sync rewrite uses a single read loop with inline pull and `writeMu` for write serialization.

### 3. Heartbeat ping races with push/pull protocol sequences
**Status:** Fixed in `obsidian/sync.go`

All writes go through `writeMu`. Heartbeat acquires it before sending pings. Push holds it for the entire metadata + binary chunk sequence.

### 4. Append may mutate original vault slice
**Status:** Fixed in `cmd/vault-sync/main.go`

`selectVault` searches both `Vaults` and `Shared` arrays directly. No append/merge.

### 5. Empty content sends 1 piece of 0 bytes
**Status:** Fixed in `obsidian/sync.go`

`pieces = 0` when encrypted content is empty. Comment explains why.

### 6. decrypt skips GCM auth tag for 12-byte input
**Status:** Not a bug

Matches Obsidian app behavior. Empty files sync as nonce-only payloads with no ciphertext or tag. Commented in `obsidian/crypto.go:106`.

## Open

### 7. No reconnection logic
**Status:** Fixed in `obsidian/sync.go` and `obsidian/watcher.go`

`Listen` now wraps the read loop with automatic reconnection. On disconnect: cancels the per-connection heartbeat context, waits with exponential backoff (1s to 60s cap, with jitter), reconnects, re-runs WaitForReady to catch up on missed server pushes, then resumes the read loop. Permanent errors (auth failure) exit immediately.

The watcher checks `Connected()` before pushing. While disconnected, events are queued in a map (last event per path wins). The queue drains on the next ticker tick after reconnection.

### 8. No timeout on response channel reads
**File:** `obsidian/sync.go`

If the server hangs without closing the connection, `Push` blocks forever on `responseCh`. Only escape is context cancellation. Should add a timeout (e.g. 30s) around the channel read.

### 9. No bounds check on PullResponse size
**File:** `obsidian/sync.go:430`

Server-controlled `Size` field is used directly in `make([]byte, 0, resp.Size)`. A malicious or buggy server could send a huge value and cause an out-of-memory panic. Should cap at `perFileMax` or a reasonable limit.

### 10. Watcher ignores dotfiles including .obsidian
**File:** `obsidian/watcher.go:191`

The `shouldIgnore` filter drops all paths starting with `.`. Obsidian Sync syncs `.obsidian/` (workspace, plugins, config). The scanner handles `.obsidian` correctly during reconciliation, but the live watcher skips it, so local config changes won't push.

Fix: exempt `.obsidian` from the dotfile filter, matching what the scanner already does.

### 11. Watcher returns nil on fsnotify channel close
**File:** `obsidian/watcher.go:69,97`

When `watcher.Events` or `watcher.Errors` channels close, `Watch` returns `nil`. The errgroup in main sees a clean exit even though the file watcher died unexpectedly. Should return an error so errgroup cancels the context.
