# Bugs and Issues

## Bugs

### 1. Path traversal on decrypted server paths
**File:** `obsidian/sync.go:304`

Decrypted path from server is joined with `syncDir` without validation. A path like `../../etc/passwd` writes outside the sync directory. Needs a check that the resolved path is within `syncDir`.

### 2. Deadlock if pushCh fills during pull
**File:** `obsidian/sync.go:222`

`pushCh` is buffered at 64. If `processPush` calls `pull` (holding `reqMu`, waiting on `responseCh`), and the server sends 64+ push messages before the pull response arrives, the dispatcher goroutine blocks on `pushCh` and can never deliver the response. Deadlock. Unlikely during incremental sync, plausible during initial sync of a large vault.

### 3. Heartbeat ping races with push/pull protocol sequences
**File:** `obsidian/sync.go:613`

Heartbeat sends pings via `writeJSON` without holding `reqMu`. A ping could land between push metadata and binary chunks, corrupting the protocol sequence from the server's perspective.

### 4. Append may mutate original vault slice
**File:** `cmd/vault-sync/main.go:128,154`

`append(vaults.Vaults, vaults.Shared...)` can write into the backing array of `vaults.Vaults` if it has spare capacity. Safe pattern is to allocate a new slice first.

### 5. Empty content sends 1 piece of 0 bytes
**File:** `obsidian/sync.go:506`

When encrypted content is empty, `pieces` is set to 1 and an empty binary frame is sent. Should be 0 pieces with no binary frame sent.

### 6. decrypt skips GCM auth tag for 12-byte input
**File:** `obsidian/crypto.go:106`

Returns empty content without GCM verification when input is exactly 12 bytes (nonce size). Valid encrypted empty content is 28 bytes (12 nonce + 16 tag). A 12-byte input is malformed and should be rejected.

## Issues

### 7. No reconnection logic
**File:** `obsidian/sync.go`

Any network hiccup kills the process. Heartbeat timeout, server close, transient error all cause `Listen` to return an error and the process to exit.

### 8. No timeout on response/data channel reads
**File:** `obsidian/sync.go`

If the server hangs without closing the connection, `pull` and `Push` block forever on `responseCh`/`dataCh`. Only escape is context cancellation.

### 9. No bounds check on PullResponse size
**File:** `obsidian/sync.go:418`

Server-controlled `Size` field is used directly in `make([]byte, 0, resp.Size)`. A malicious or buggy server could send a huge value and cause an out-of-memory panic.

### 10. Watcher ignores dotfiles including .obsidian
**File:** `obsidian/watcher.go:189`

The `shouldIgnore` filter drops all paths starting with `.`. Obsidian Sync syncs `.obsidian/` by default (workspace, plugins, config). Our watcher silently skips it.

### 11. Watcher returns nil on fsnotify channel close
**File:** `obsidian/watcher.go:66,93`

When `watcher.Events` or `watcher.Errors` channels close, `Watch` returns `nil`. The errgroup in main sees a clean exit even though the file watcher died unexpectedly.
