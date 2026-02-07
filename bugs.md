# Bugs and Issues

## High

### 1. Deadlock between readLoop and Push via writeMu + responseCh
**File:** `obsidian/sync.go`

If the server pushes a file from another device while the watcher is mid-Push, `processPush` calls `pull()` which tries to acquire `writeMu`. Push holds `writeMu` waiting on `responseCh`, which only the read loop can feed. The hash cache dedup only prevents echoes of our own pushes. A push from another device passes the hash check, `processPush` is called, and the application deadlocks.

### 2. s.conn replaced without synchronization during reconnect
**File:** `obsidian/sync.go:157`

`Connect` assigns `s.conn` with no lock. The heartbeat goroutine accesses `s.conn` concurrently. During reconnect, `connCancel()` is called but there is a window before the heartbeat actually exits. The heartbeat could call `s.conn.Close()` after `s.conn` has been reassigned to the new connection, closing the fresh connection. The watcher goroutine running Push could also be mid-write when `s.conn` changes.

### 3. TOCTOU on Connected() check in watcher
**File:** `obsidian/watcher.go:127,183`

`handleWrite` checks `Connected()` then proceeds to `Push()`. Between those points the connection can drop and `s.conn` can be replaced by `reconnect`. The watcher may write to a stale/closed connection. `requeueIfDisconnected` partially mitigates this on failure, but the write to the old connection is still attempted.

### 4. Race condition on s.version and s.initial
**File:** `obsidian/sync.go:166-167,234-237,255-256,377-378`

`s.version` and `s.initial` are written by `WaitForReady` and `readLoop`, and read by `Connect` when constructing the `InitMessage`. No mutex protects these fields. In the current flow reads happen before reconnect starts so there is no actual concurrent access today, but the design is fragile.

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
**File:** `obsidian/sync.go:1009`

When the heartbeat detects a timeout, it calls `s.conn.Close()` without holding `writeMu`. The watcher goroutine might be mid-push with `writeMu` held, writing binary chunks. The close races with the active write.

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
