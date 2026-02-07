# Bugs and Issues

## High

### 1. Deadlock between readLoop and Push via writeMu + responseCh
**Status:** Fixed in `obsidian/sync.go`

Replaced the read loop + writeMu + responseCh architecture with a single event loop. A reader goroutine feeds `inboundCh`. The event loop selects on `inboundCh` (server messages), `opCh` (watcher push operations), and a heartbeat ticker. All writes happen from the event loop, eliminating `writeMu` and the deadlock. Server pushes arriving mid-operation are handled inline (folders/deletes/hash-matches) or deferred to `pendingPulls` and processed after the current operation completes.

### 2. s.conn replaced without synchronization during reconnect
**Status:** Fixed in `obsidian/sync.go`

The heartbeat is now a ticker case in the event loop, not a separate goroutine. Only the reader goroutine and the event loop touch the connection. On reconnect, `connCancel` stops the reader, then `Connect` replaces `s.conn`, and a new reader is started. No concurrent access to `s.conn`.

### 3. TOCTOU on Connected() check in watcher
**Status:** Mitigated

The watcher still checks `Connected()` before pushing, but `Push()` now submits an op to `opCh` and blocks for the result. If the connection drops mid-push, the event loop returns an error, the op gets an error result, and `requeueIfDisconnected` queues it. The watcher never writes to the connection directly.

### 4. Race condition on s.version and s.initial
**Status:** Fixed in `obsidian/sync.go`

`s.version` and `s.initial` are now only written by the event loop goroutine (via `handleInbound` and `processPush`) and by `WaitForReady` which runs before the event loop starts. `Connect` reads them to build the init message, but only during reconnect which happens in the event loop goroutine after the reader has been stopped. No concurrent access.

## Medium

### 5. Unbounded content accumulation in pull() binary frames
**File:** `obsidian/sync.go:758-766`

`resp.Size` is validated against `perFileMax * 2`, but the actual content accumulation loop appends whatever data arrives in binary frames without checking the total. A malicious server could send more data than `resp.Size` declared. `append` grows beyond the initial capacity.

### 6. DeleteLocalFile return value silently ignored
**File:** `obsidian/sync.go:462,497,697` and `obsidian/reconcile.go:140,166,411,468,495`

`DeleteLocalFile` returns an error but every call site discards it. If the bbolt transaction fails (database corruption, disk full), local state becomes inconsistent with disk. The next scan sees the file as still tracked, potentially re-uploading deleted content.

### 7. json.Unmarshal errors ignored in state.go
**File:** `internal/state/state.go:130,176,241`

`GetVault`, `GetLocalFile`, and `GetServerFile` discard `json.Unmarshal` errors. Corrupted stored data returns zero-value structs that look valid. Reconciliation logic makes decisions based on `Hash`, `UID`, `Folder`, and `Deleted` fields that would all be zero values.

### 8. Conflict copy path not deduplicated
**File:** `obsidian/reconcile.go:370-373`

`handleTypeConflict` creates a conflict copy at `base + " (Conflicted copy)" + ext`. If a conflict copy already exists at that path, `WriteFile` silently overwrites it.

### 9. Conflict copy write error ignored
**File:** `obsidian/reconcile.go:381`

`r.vault.WriteFile(conflictPath, content)` error is discarded. If writing the conflict copy fails (disk full, permissions), the original file is then deleted, losing the user's data.

### 10. Three-way merge discards patch application failures
**File:** `obsidian/reconcile.go:298`

`dmp.PatchApply(patches, serverText)` returns `(string, []bool)`. The second return value indicates which patches were successfully applied. The code discards it. Failed patches mean the user's local edits silently disappear from the merge result.

### 11. Heartbeat closes connection without holding writeMu
**Status:** Fixed in `obsidian/sync.go`

The heartbeat is now a ticker case in the event loop select. All writes happen from the event loop goroutine. There is no separate heartbeat goroutine and no writeMu. No concurrent access to the connection.

### 12. drainQueue modifies map while iterating and callees add entries back
**File:** `obsidian/watcher.go:224-238`

`drainQueue` iterates `w.queued` with range and calls `handleWrite`/`handleDelete` which can add entries back via `requeueIfDisconnected`. Adding keys to a map during range iteration means those keys may or may not be visited. The `break` on connection loss partially mitigates this.

### 13. WebSocket read limit set to 256MB
**File:** `obsidian/sync.go:158`

A single WebSocket frame of 256MB is allowed. This is separate from the `pull()` size validation. A malicious server can send a single 256MB text frame and it will be fully read into memory.

## Low

### 14. io.ReadAll on HTTP response body is unbounded
**File:** `obsidian/client.go:52`

`io.ReadAll(resp.Body)` reads the entire response into memory. API responses are small in practice, but a compromised endpoint could return a multi-GB response.

### 15. handleTypeConflict fails when local is a folder and server wants a file
**File:** `obsidian/reconcile.go:362-367`

When local is a folder and server wants a file at the same path, `downloadServerFile` calls `vault.WriteFile` which calls `os.WriteFile`. This fails on Linux because you cannot create a file at a path that is an existing directory. The folder is never removed first.

### 16. Filesystem watcher does not remove watches for deleted directories
**File:** `obsidian/watcher.go:98-103`

When a directory is deleted, the watcher pushes the deletion but never calls `w.watcher.Remove()` to unregister the watch. On Linux inotify handles this automatically, but on other platforms it could leak watch descriptors.

### 17. vaultNames produces malformed output with no owned vaults
**File:** `cmd/vault-sync/main.go:225-237`

When `vaults.Vaults` is empty and `vaults.Shared` has entries, shared vault names are prepended with ", ", producing output like ", SharedVault1, SharedVault2".

### 18. processServerPushes always returns nil
**File:** `obsidian/reconcile.go:104-114`

`processServerPushes` logs errors from `processOneServerPush` but always returns nil. If every push fails (cipher key mismatch), reconciliation silently succeeds.

### 19. 12-byte ciphertext bypasses GCM authentication
**File:** `obsidian/crypto.go:111-113`

Intentional for Obsidian app compatibility (empty files). A compromised server could send 12-byte payloads for any file and the client accepts it as empty content without authentication, silently wiping file contents. TLS mitigates this.

### 20. vault.resolve rejects empty path
**File:** `obsidian/vault.go:112`

`strings.HasPrefix(absPath, v.dir+string(os.PathSeparator))` rejects `absPath == v.dir` (empty relPath). If the server sends an empty decrypted path, this produces a path traversal error instead of a meaningful message.
