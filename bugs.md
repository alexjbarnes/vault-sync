# Bugs and Issues

## Accepted Risk

### 19. 12-byte ciphertext bypasses GCM authentication
**File:** `obsidian/crypto.go:111-113`

Intentional for Obsidian app compatibility (empty files). A compromised server could send 12-byte payloads for any file and the client accepts it as empty content without authentication, silently wiping file contents. TLS mitigates this.

## Review 3

### 27-29. Reconciliation matches Obsidian app behavior (NOT BUGS)

Bugs 27, 28, 29 were originally flagged as data loss issues in reconciliation. After reviewing `app.js`, these all match the Obsidian desktop app's behavior exactly:
- Non-mergeable files: server wins silently, no conflict copy.
- Conflict copy write failure: log warning, proceed with server overwrite.
- Pull/decrypt base failure: fall back to server wins, no conflict copy.

See "Reconciliation Behavior" section in `obsidian-sync-protocol.md` for full documentation.

### 30. No error check on push metadata response before sending binary chunks (HIGH)
**File:** `sync.go:638-667`

After reading the server's response to push metadata, the code only checks for `"ok"` (skip upload). Any non-"ok" response, including error responses, falls through to the chunk sending loop. The client sends binary frames the server never asked for, desynchronizing the protocol.

### 31. `persistPushedFile` stores `ServerFile.UID` as zero (NOT A BUG)

The zero UID is a transient placeholder. The server echoes back every push as a push message to all clients including the sender. This echo contains the server-assigned UID. Our `handlePushWhileBusy` catches the echo via hash cache match and calls `persistServerFile` with the full `PushMessage`, overwriting the zero-UID entry. Same pattern as Obsidian, which also stores `uid: 0` for folders at push time and relies on the echo to populate the real UID. See "Push (Upload) Flow" in `obsidian-sync-protocol.md`.

### 32. `uniqueConflictPath` returns a colliding path after 100 attempts (MEDIUM)
**File:** `reconcile.go:452-458`

The loop runs from 1 to 99. If all candidates exist, it returns the last `candidate` which was verified to already exist. Writing to that path overwrites whatever file is there.

### 33. `drainQueue` deletes map entry before handler runs (NOT A BUG)

Matches Obsidian's behavior. Connected push failures are treated as permanent for that cycle. Obsidian's `requeueIfDisconnected` has the same logic: only re-queue if the connection dropped, not on a connected rejection. The watcher will pick up the file change again on the next fsnotify event. See "Sync Loop and Failure Handling" in `obsidian-sync-protocol.md`.

### 34. `deleteRemoteFiles` uses string length as depth proxy (NOT A BUG)

Matches Obsidian's behavior exactly. The Obsidian app uses `path.length` (string length) as its depth proxy for deepest-first delete ordering. It also deletes files before folders, and processes one delete per sync cycle. See "Sync Loop and Failure Handling" in `obsidian-sync-protocol.md`.

### 35. bbolt open with no timeout (MEDIUM)
**File:** `internal/state/state.go:76`

`bolt.Open(p, 0600, nil)` blocks indefinitely on the file lock if another instance is running.

### 36. Negative `resp.Pieces` causes pull to return empty content (LOW)
**File:** `sync.go:1177-1204`

`PullResponse.Pieces` is `int`. A negative value passes the max-pieces guard and makes the `for` loop execute zero iterations, returning empty content. Requires a buggy server.

### 37. `OnReady` callback logs "state saved" even on failure (LOW)
**File:** `main.go:115`

The success log fires regardless of whether `SetVault` returned an error.

### 38. `defer syncClient.Close()` before `Connect()` succeeds (NOT A BUG)

`Close()` already guards against nil `conn` and nil `connCancel` with nil checks before use. Safe to call on an unconnected client.

### 39. `threeWayMerge` treats genuinely empty base as "no base" (NOT A BUG)

Matches Obsidian's behavior. The Obsidian app checks truthiness of the base text variable, and empty string is falsy in JS. A three-way merge with an empty base would produce poor results anyway (all local content treated as inserts, duplicating into server version). The "no base" fallback is the better outcome for this edge case.
