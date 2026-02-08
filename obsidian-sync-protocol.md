# Obsidian Sync Protocol — Reverse Engineered Specification

## Overview

Obsidian Sync uses a JSON-over-WebSocket protocol with AES-GCM-256 encryption. The protocol is straightforward: authenticate, exchange version numbers, then push/pull encrypted file metadata and content.

---

## Architecture

```
REST API (https://api.obsidian.md)  →  Account auth, vault management
WebSocket (wss://sync-{N}.obsidian.md)  →  Real-time file sync
```

---

## REST API

Base URL: `https://api.obsidian.md`
All requests: `POST` with `Content-Type: application/json`

All requests require `Origin: app://obsidian.md` header. Without it, the API rejects requests with a misleading "invalid credentials" error rather than a proper 403. The API also returns errors as HTTP 200 with an `error` field in the JSON body, not as HTTP error status codes.

### Authentication

```
POST /user/signin
Body: {"email": "...", "password": "..."}
Response: {"token": "...", "email": "...", "name": "...", "license": "..."}
```

The token from signin works for `/vault/list`, `/user/info`, and WebSocket `init`. It does NOT work with `/user/authtoken` (that endpoint expects a different kind of long-lived token used internally by the Obsidian app).

```
POST /user/info
Body: {"token": "..."}
Response: {"uid": "...", "email": "...", "name": "...", "mfa": false, ...}
```

```
POST /user/signout
Body: {"token": "..."}
```

### Endpoints

| Endpoint | Purpose | Params |
|----------|---------|--------|
| `/user/signin` | Sign in with email/password | `{email, password}` |
| `/user/info` | Get account info | `{token}` |
| `/user/signout` | Invalidate token | `{token}` |
| `/user/authtoken` | Rotate long-lived token (app internal) | `{token}` |
| `/vault/list` | List user's vaults | `{token, supported_encryption_version: 3}` |
| `/vault/create` | Create vault | `{token, name, keyhash, salt, region, encryption_version}` |
| `/vault/regions` | List available regions | `{token, host}` |
| `/vault/delete` | Delete vault | `{token, vault_uid}` |
| `/vault/rename` | Rename vault | `{token, vault_uid, name}` |
| `/vault/share/invite` | Share vault | `{token, vault_uid, ...}` |
| `/vault/share/list` | List shares | `{token, vault_uid}` |
| `/vault/share/remove` | Remove share | `{token, vault_uid, share_uid}` |

### Token Behavior

Tokens from `/user/signin` persist across requests and survive process restarts. They can be cached and reused. The simplest way to validate a cached token is to call `/vault/list` with it. If it returns data, the token is valid. If it returns an error, sign in again.

The `/user/authtoken` endpoint rotates tokens: it returns a new token and invalidates the old one. The Obsidian app uses this to refresh its stored token on startup. Tokens from `/user/signin` are not compatible with this endpoint.

### Vault List Response

Each vault contains: `id`, `host` (e.g. `sync-32.obsidian.md`), `salt`, `encryption_version` (0, 2, or 3), `name`, `size`, `region`.

---

## Key Derivation

### Step 1: Password → Raw Key (scrypt)

```
password = password.normalize("NFKC")
salt     = salt.normalize("NFKC")
key      = scrypt(password, salt, N=32768, r=8, p=1, dkLen=32)
```

Parameters: `N=32768 (2^15)`, `r=8`, `p=1`, `maxmem=67108864`, output = 32 bytes.

The key is stored locally as base64.

### Step 2: Key → Encryption Provider

Depends on `encryption_version`:

#### Version 0 (Legacy)

```
keyhash   = hex(SHA-256(key))
cryptoKey = AES-GCM-256.importKey(key)
```

Path encryption: deterministic AES-GCM using SHA-256(plaintext)[0:12] as IV.
Content encryption: AES-GCM with random 12-byte IV.

#### Version 2/3 (Current)

Uses HKDF to derive separate keys from the master key:

```
hkdfBaseKey = HKDF.importKey(key)

// Key hash (for server verification)
keyhashKey = HKDF-SHA256(hkdfBaseKey, salt=utf8(salt), info="ObsidianKeyHash") → AES-CBC-256
keyhash    = hex(exportKey(keyhashKey))

// Content encryption key
contentKey = HKDF-SHA256(hkdfBaseKey, salt=empty, info="ObsidianAesGcm") → AES-GCM-256

// Path encryption keys (AES-SIV)
macKey = HKDF-SHA256(hkdfBaseKey, salt=utf8(salt), info="ObsidianAesSivMac") → AES-CBC-256
ctrKey = HKDF-SHA256(hkdfBaseKey, salt=utf8(salt), info="ObsidianAesSivEnc") → AES-CTR-256
```

Path encryption: AES-SIV (deterministic, using CMAC + CTR).
Content encryption: AES-GCM with random 12-byte IV.

---

## Encryption Functions

### Content Encryption (both v0 and v2/3)

Algorithm: AES-256-GCM

```
encrypt(plaintext, cryptoKey):
  iv = crypto.getRandomValues(12 bytes)
  ciphertext = AES-GCM.encrypt(plaintext, cryptoKey, iv)
  return iv || ciphertext          // 12 bytes IV prepended

decrypt(data, cryptoKey):
  if data.length < 12: error
  if data.length == 12: return empty
  iv = data[0:12]
  ciphertext = data[12:]
  return AES-GCM.decrypt(ciphertext, cryptoKey, iv)
```

### Path Encryption — Version 0 (Deterministic)

```
deterministicEncodeStr(plaintext, cryptoKey):
  plaintextBytes = utf8encode(plaintext)
  hash = SHA-256(plaintextBytes)
  iv = hash[0:12]                  // Deterministic IV from content hash
  ciphertext = AES-GCM.encrypt(plaintextBytes, cryptoKey, iv)
  return hex(ciphertext)

deterministicDecodeStr(hexStr, cryptoKey):
  data = hexDecode(hexStr)
  plaintext = AES-GCM.decrypt(data, cryptoKey)  // IV extraction handled by decrypt
  return utf8decode(plaintext)
```

Note: v0 path encryption reuses AES-GCM with a deterministic IV derived from SHA-256 of the plaintext. The first 12 bytes of the SHA-256 hash serve as the IV.

### Path Encryption — Version 2/3 (AES-SIV)

Uses AES-SIV (Synthetic Initialization Vector) which is designed for deterministic encryption.

```
seal(plaintext):
  siv = S2V(plaintext)             // CMAC-based
  clearBits(siv)                   // Clear bits 63 and 31
  ciphertext = AES-CTR.encrypt(plaintext, ctrKey, counter=siv)
  return siv || ciphertext         // 16 bytes SIV prepended

open(data):
  siv = data[0:16]
  ciphertext = data[16:]
  clearedSiv = clearBits(copy(siv))
  plaintext = AES-CTR.decrypt(ciphertext, ctrKey, counter=clearedSiv)
  computedSiv = S2V(plaintext)
  if !constantTimeEqual(siv, computedSiv): error
  return plaintext
```

The S2V (String-to-Vector) uses CMAC (AES-CBC-MAC with subkey derivation, block size 16).

### File Hash

```
hash = hex(SHA-256(fileContent))
```

The hash is then encrypted with `deterministicEncodeStr` before being sent to the server, so the server never sees plaintext hashes.

---

## WebSocket Protocol

### Connection

```
wss://sync-{N}.obsidian.md/
```

Where `{N}` is from the vault's `host` field (e.g. `sync-32`).

Headers: Standard WebSocket upgrade. Origin: `app://obsidian.md`.

### Message Types

All messages are JSON text frames except file content which uses binary frames.

| Op | Direction | Purpose |
|----|-----------|---------|
| `init` | Client → Server | Authentication handshake |
| `ready` | Server → Client | Server version acknowledgement |
| `ping` | Client → Server | Keepalive (sent after 10s idle) |
| `pong` | Server → Client | Keepalive response |
| `push` | Bidirectional | File metadata + content |
| `pull` | Client → Server | Request file content by uid |
| `deleted` | Client → Server | List deleted files |
| `history` | Client → Server | Get file version history |
| `restore` | Client → Server | Restore deleted file |
| `purge` | Client → Server | Purge all deleted files |
| `size` | Client → Server | Get vault size |
| `usernames` | Client → Server | Get user list |

### Handshake Flow

```
Client → Server:
{
  "op": "init",
  "token": "<account_token>",
  "id": "<vault_id>",
  "keyhash": "<hex_keyhash>",
  "version": <last_known_version>,
  "initial": false,              // true for first sync
  "device": "<device_name>",
  "encryption_version": 0        // 0, 2, or 3
}

Server → Client:
{
  "res": "ok",
  "perFileMax": 5242880,         // 5MB per file limit
  "userId": 1
}
```

After `ok`, the server sends changes as `push` ops. What gets sent depends on `initial` and `version`:

- `initial: true, version: 0` -- Server sends a compacted snapshot of the vault. Only the latest live state of each file. Deleted files are excluded entirely. This is not a full event log replay.
- `initial: false, version: N` -- Server sends an incremental event log of all changes since version N, including deletions.

After all pushes are delivered:

```
Server → Client:
{
  "op": "ready",
  "version": <server_latest_version>
}
```

### Keepalive

- Client sends `{"op": "ping"}` after 10 seconds of inactivity
- Server responds with `{"op": "pong"}`
- Client disconnects after 120 seconds of no messages

### Push (Upload) Flow

1. Encrypt path: `encPath = deterministicEncodeStr(path)`
2. Encrypt related path if present (for renames)
3. For folders or deletions, send metadata only:
   ```json
   {
     "op": "push",
     "path": "<encrypted_path>",
     "relatedpath": null,
     "extension": "",
     "hash": "",
     "ctime": 0, "mtime": 0,
     "folder": true/false,
     "deleted": true/false
   }
   ```
4. For files with content:
   - Encrypt content: `encContent = encrypt(content)`
   - Encrypt hash: `encHash = deterministicEncodeStr(hash)`
   - Calculate pieces: `pieces = ceil(encContent.length / 2097152)` (2MB chunks)
   ```json
   {
     "op": "push",
     "path": "<encrypted_path>",
     "relatedpath": null,
     "extension": "md",
     "hash": "<encrypted_hash>",
     "ctime": <creation_time_ms>,
     "mtime": <modification_time_ms>,
     "folder": false,
     "deleted": false,
     "size": <encrypted_content_size>,
     "pieces": <num_chunks>
   }
   ```
5. Server responds with a JSON message:
   - `{"res": "ok"}` -- server already has this file (hash matches). Skip upload, return.
   - `{"err": "..."}` -- server rejected the push. The Obsidian app's `request()` checks `resp.err` and throws if non-empty. Abort, do not send chunks.
   - Any other response -- server is ready for binary chunks. Proceed to step 6.
6. Send binary frames in 2MB chunks. After each chunk, wait for a server JSON ack. The ack content is consumed but not inspected by the Obsidian app (no error checking on per-chunk acks).
7. For folder/deletion pushes (no `size`/`pieces` fields), the server response is consumed by `request()` (which checks `err`) but the call site does not inspect it further.

### Push Echo (Server → Sender)

After a successful push, the server broadcasts a push message back to all clients, including the sender. This echo is how the client learns the server-assigned UID for the file it just pushed.

The Obsidian app uses a `justPushed` field to detect these echoes:
- Before sending push metadata, set `justPushed = {path, folder, deleted, mtime, hash}` (all encrypted values).
- Clear `justPushed` after push completes (either "ok" skip or all chunks sent).
- When `onServerPush` fires, compare the incoming push against `justPushed` on all 5 fields.
- If all match: stamp `wasJustPushed = true` on the message, clear `justPushed`.
- In `onPushedFile`: if `wasJustPushed`, store the server record directly into `serverFiles` with the real UID. Do NOT queue it for download or trigger a sync cycle. This prevents re-downloading a file we just uploaded.
- If NOT `wasJustPushed`: treat as a normal server push from another device, queue for sync.

The UID from the echo also updates the global version cursor (`this.version = e.uid`).

Race condition: if the connection drops between push completion and echo receipt, the client has no UID stored. On reconnect, the server replays the echo as part of the catch-up since the client's version predates the push. The echo is then processed as a normal server push (since `justPushed` was cleared), potentially triggering a redundant download that the hash comparison short-circuits.

### Push (Server → Client) — Incoming Changes

Same JSON structure as above, but includes additional fields:

```json
{
  "op": "push",
  "path": "<encrypted_path>",
  "hash": "<encrypted_hash>",
  "size": 915,
  "ctime": 0,
  "mtime": 1770399182173,
  "folder": false,
  "deleted": false,
  "device": "hp-zbook",
  "uid": 12545,                  // Version number for this change
  "user": 1
}
```

The `uid` is used to pull file content.

### Pull (Download) Flow

```
Client → Server:
{"op": "pull", "uid": <version_uid>}

Server → Client:
{"size": <encrypted_size>, "pieces": <num_chunks>, "deleted": false}
```

Then receive `pieces` binary frames, concatenate them, and decrypt:

```
encryptedContent = concatenate(binaryFrames)
if encryptedContent.length > 0:
  content = decrypt(encryptedContent)
```

### Deleted Files

```
Client → Server:
{"op": "deleted", "suppressrenames": true}

Server → Client:
{"items": [{"path": "<encrypted_path>", ...}, ...]}
```

### File History

```
Client → Server:
{"op": "history", "path": "<encrypted_path>", "last": <count>}

Server → Client:
{"items": [{"path": "<encrypted_path>", "uid": <version>, ...}, ...]}
```

---

## Sync State Management

### Version Tracking

The version number is an integer that increases monotonically. Each file change on the server gets a new version (the `uid` field on push messages). The client tracks its last known version and sends it in the `init` message on connect.

After the server sends all pending pushes, it sends a `ready` message with the latest version. The client persists this version for the next connection.

### The `initial` Flag

The `initial` flag controls two things: what the server sends, and how the client processes it.

**Server behavior:**

| `initial` | `version` | Server sends |
|-----------|-----------|-------------|
| `true` | `0` | Compacted snapshot: latest state of every live file, no deletions |
| `false` | `N` | Incremental event log: all changes since N, including deletions |

During initial sync, the server does NOT replay the full version history. It sends one push per currently-existing file. Files that were created and later deleted are excluded entirely. This means the initial push stream is a snapshot, not a log.

**Client behavior (Obsidian app):**

During initial sync (`initial: true`):
- Deleted pushes are dropped (safety net, since the server already excludes them)
- Each file record is tagged with `initial: true` internally
- Conflict resolution uses simple timestamp comparison (server wins if mtime is newer)
- Three-way merge is skipped for .md files

During incremental sync (`initial: false`):
- Deleted pushes are processed normally (local files get deleted)
- .md files with conflicting hashes go through three-way merge using the common ancestor
- The common ancestor is fetched via `pull` using the previous known server version uid

**Lifecycle:**

1. First connection: `version: 0, initial: true`
2. Server streams compacted snapshot of all live files
3. Server sends `ready` with latest version (e.g. 12560)
4. Client sets `initial = false`, persists `version = 12560`
5. Next connection: `version: 12560, initial: false`
6. Server sends only changes since 12560, including any deletions

### Persistence

The Obsidian app stores these values in IndexedDB between sessions:
- `version` -- last known server version
- `initial` -- whether first sync is complete (starts `true`, set to `false` after first `ready`)
- `localFiles` -- map of local file states (path, hash, mtime)
- `serverFiles` -- map of server file states (path, hash, mtime, uid)

---

## Client Implementation (from app.js)

All behavior in this section was reverse-engineered from the Obsidian desktop app's minified webpack bundle (`app.js`). The sync plugin is class `a0`.

### Plugin Initialization Sequence

1. Register vault event listeners (create, modify, delete, rename, raw).
2. Wait for workspace layout ready.
3. Load persisted state from IndexedDB (database named `{appId}-sync`).
4. Call `scanFiles()` to walk the vault tree and populate `localFiles`.
5. Set `initialized = true`.
6. Call `requestSync()` to start the first sync cycle.
7. Start a 30-second `setInterval` timer that calls `requestSync()`.

On shutdown: unregister vault events, clear the interval timer, disconnect WebSocket.

App ID mismatch detection: if the persisted `appId` differs from the current app (vault restored from backup on different device), sync auto-pauses and resets to `initial=true, version=0` with empty state.

### Local State Tracking

The `localFiles` dictionary (keyed by file path) tracks every file in the vault:

```
{
    path:         string   // current file path
    previouspath: string   // old path before rename ("" if not renamed)
    folder:       boolean  // true for directories
    ctime:        number   // creation time (ms, ceiled to integer)
    mtime:        number   // modification time (ms, ceiled to integer)
    size:         number   // file size in bytes
    hash:         string   // SHA-256 hex digest ("" = not yet computed)
    synctime:     number   // Date.now() at last sync operation
    synchash:     string   // hash at last successful upload
}
```

The `serverFiles` dictionary (keyed by path) tracks server state:

```
{
    path:    string
    size:    number
    hash:    string   // encrypted hash from server
    ctime:   number
    mtime:   number
    folder:  boolean
    deleted: boolean
    uid:     number   // server version number for this change
    device:  string
    user:    number
}
```

### Vault Event Handlers

`create` and `modify` share the same handler (`onFileAdd`):
- Creates entry in `localFiles` if missing.
- For files: updates mtime, ctime, size. Clears `hash` to `""` if mtime or size changed (forcing recomputation at sync time).
- For folders: sets `folder=true`, zeroes file-specific fields.
- Calls `requestSync()`.

`delete` (`onFileRemove`):
- Removes the entry entirely from `localFiles`.
- The sync loop detects deletions by finding paths in `serverFiles` that are absent from `localFiles`.
- Calls `requestSync()`.

`rename` (`onFileRename`):
- Moves the entry from old key to new key in `localFiles`.
- Sets `previouspath` to old path (only if not already tracking a prior rename, preserving the chain: A -> B -> C keeps `previouspath` as "A").
- Sets `synctime = 0` (bypasses per-file cooldown, makes rename immediately eligible for sync).
- Re-runs `onFileAdd` for fresh stat.
- Calls `setDirty()` then `requestSync()`.

`raw` (`onRaw`):
- Only handles paths under `.obsidian/`. Adds them to `scanSpecialFileQueue` for the sync loop to stat.

### Hash Computation

Hashes are **lazy** -- computed at sync time, not on file change events. `onFileAdd` clears the hash to `""` when mtime or size changes.

Two paths to compute hashes:
1. **Metadata cache (free)**: `getHashFromMetadataCache` checks Obsidian's internal metadata indexer. If mtime and size match, uses the cached hash without disk I/O.
2. **Full file read**: `updateHash` reads the file via `adapter.readBinary()` and computes `SHA-256` hex via `crypto.subtle.digest`. The read buffer is reused for the subsequent upload to avoid double I/O.

### File Filtering

`_allowSyncFile(path, isFolder)` determines what gets synced:

**Always synced:** `.md` and `.canvas` files.

**Always excluded:**
- `workspace.json` and `workspace-mobile.json`
- `node_modules` directories and dotfiles within `.obsidian/`
- Files/folders starting with `.` outside `.obsidian/`
- Files not matching any enabled category

**User-configurable exclusions:** `ignoreFolders` list.

**File type categories** (user-toggleable via `allowTypes` set):
- `image`: bmp, png, jpg, jpeg, gif, svg, webp, avif
- `audio`: mp3, wav, m4a, 3gp, flac, ogg, oga, opus
- `video`: mp4, webm, ogv, mov, mkv
- `pdf`: pdf
- `unsupported`: everything else

Defaults enabled: image, audio, pdf, video. The `unsupported` category requires opt-in.

**Config file categories** (user-toggleable via `allowSpecialFiles` set):
- `app`: app.json, types.json
- `appearance`: appearance.json
- `hotkey`: hotkeys.json
- `core-plugin`: core-plugins.json, core-plugins-migration.json
- `community-plugin`: community-plugins.json
- `appearance-data`: themes/*/theme.css, themes/*/manifest.json, snippets/*.css
- `core-plugin-data`: any top-level .json in .obsidian/ (not named above)
- `community-plugin-data`: plugins/*/manifest.json, main.js, styles.css, data.json

Defaults enabled: app, appearance, appearance-data, hotkey, core-plugin, core-plugin-data. Community plugin sync is opt-in.

Filter results are cached per-path in `filterCache`. Cache is invalidated when filters change.

### Per-File Upload Cooldown

`canSyncLocalFile(now, entry)` rate-limits uploads based on file size:
- Files never synced (`synctime=0`): eligible immediately
- Files <= 10KB: 10-second cooldown after last sync
- Files 10KB-100KB: 20-second cooldown
- Files > 100KB: 30-second cooldown

Renames reset `synctime` to 0, bypassing the cooldown.

### Rename Protocol

`previouspath` tracks the original path the server knows about. It persists through chained renames (A -> B -> C keeps `previouspath` as A). Cleared after successful upload.

The push message includes `relatedpath` (encrypted `previouspath`). The server uses this to track renames rather than treating them as delete + create.

### Persistence (IndexedDB)

Fields saved to IndexedDB via `saveData()`:
- `appId`, `vaultId`, `vaultName`, `key`, `salt`, `encryptionVersion`, `host`
- `deviceName`, `userId`, `pause`
- `version`, `initial`
- `local` (localFiles dictionary)
- `remote` (serverFiles dictionary)
- `pending` (newServerFiles array)
- `allowTypes`, `allowSpecialFiles`, `ignoreFolders`
- `preventSleep`, `dataVer`

`saveData()` is gated by a `dirty` flag. `setDirty()` sets the flag and triggers a status-change event. `requestSaveData` is debounced to 2 seconds.

`onFileAdd` and `onFileRemove` do NOT call `setDirty()`. They modify `localFiles` in memory and call `requestSync()`. Persistence happens when something structurally meaningful changes (renames, completed syncs, config changes).

### WebSocket Client Lifecycle

**Hostname validation**: only `*.obsidian.md` and `127.0.0.1` are allowed. The native `WebSocket` constructor and `URL.prototype.hostname` getter are captured at module scope to prevent prototype pollution.

**Auth phase**: On `onopen`, start 20s heartbeat timer and send `{op: "init", ...}`. A temporary `onmessage` handler waits for `{res: "ok"}` or `{res: "err"}`. On success, swap to the permanent `onMessage` handler.

**Permanent `onMessage` routing**:
1. Update `lastMessageTs` on every message.
2. Text frames are JSON-parsed. Parse failure disconnects.
3. `pong` -> consumed silently (timestamp already updated).
4. `ready` -> dispatched to `onReady(version)`.
5. `push` -> dispatched to `onServerPush(msg)`.
6. Everything else -> resolves the pending `responsePromise`.
7. Binary frames -> resolve the pending `dataPromise`.

**request() vs response()**:
- `request(msg, timeout=60s)`: sends JSON, creates deferred, starts timeout. Disconnects on timeout. Checks `resp.err` and throws if non-empty.
- `response()`: creates deferred only, no send, no timeout. Used for per-chunk acks during push.
- Both share the same `responsePromise` slot, resolved by `onMessage`.

**Two independent serial queues**:
- `queue` (SerialQueue): serializes all outbound operations (push, pull, history, etc.)
- `notifyQueue` (SerialQueue): serializes inbound server push decryption and dispatch. Runs independently from the outbound queue.

**Disconnect cleanup**: close socket, clear heartbeat interval, reject pending `responsePromise` and `dataPromise`.

### Connection Backoff

Connection-level exponential backoff (`Y1` class):
- Base: 5 seconds
- Factor: 2x per failure
- Jitter: 50%-100% of computed value
- Cap: 5 minutes
- Reset to 0 on success

The client never gives up. The 30-second `setInterval` timer keeps calling `requestSync()`, which checks `backoff.isReady()`. As long as the plugin is enabled, reconnection attempts continue indefinitely.

### The Sync Loop (`requestSync` + `_sync`)

`requestSync()` is a re-entrant-guarded loop:
1. If `syncing` is true, drop the call.
2. Set `syncing = true`.
3. Sleep 50ms.
4. Loop: call `_sync()` until it returns `false` or plugin is disabled/paused. Throttle 50ms between calls.
5. On `_sync()` throw: catch, log, record per-path backoff via `failedSync`, stop loop.
6. Set `syncing = false`.

Events arriving during an active sync cycle are implicitly coalesced: they mutate `localFiles` in memory, and the next `_sync()` iteration picks up the changes.

### `_sync()` Phases

Each `_sync()` call processes exactly one file, then returns `true` (more work) or `false` (done).

**Pre-flight checks**: pause flag, backoff readiness, auth token exists, establish/verify WebSocket connection.

**Config dir scanning**: walks `.obsidian/` for themes, snippets, plugins. Updates `localFiles` with fresh stat data.

**Phase 1 -- Process incoming server changes** (`newServerFiles` array):

For each entry, in order:
1. Filter: `allowSyncFile`, valid filename, path traversal check, retry backoff.
2. Dedup: skip if same path appears later in the array.
3. If file doesn't exist locally: download (or no-op if server says deleted).
4. Compute local hash if needed (metadata cache first, then disk read).
5. Both folders: accept. If server says deleted, only delete empty folders.
6. Hashes match: no-op.
7. Local is clean (hash matches previous server record): server wins. Delete or download.
8. Type conflict (file vs folder): rename local to `(Conflicted copy)`, return `true` to re-enter.
9. Initial sync with newer server mtime: server wins.
10. Both changed, `.md` file: three-way merge (see Merge Strategy section).
11. Both changed, `.json` in `.obsidian/`: shallow JSON merge.
12. All other both-changed: server wins via `syncFileDown`.
13. Catch-all: "Rejected server change", accept record silently.

On completion of each entry: call `f()` which splices it from the array, updates `serverFiles`, sets `synctime`, marks dirty.

**Phase 2 -- Delete remote files**:

Scan `serverFiles` for paths not in `localFiles`. Pick the deepest file (longest path). Push a delete. Then pick the deepest folder. One delete per `_sync()` call. Files before folders.

**Phase 3 -- Upload local changes**:

Scan `localFiles` for paths needing upload. Pick folders first (shallowest, shortest path). Then files (smallest size first).

Upload candidates:
- No server record, or server record is deleted.
- Both are files but hashes differ.
- Type mismatch.

Hash is computed at upload time: try metadata cache first, then read file and hash. If hash matches server after computation ("Comparing" path), skip upload.

The file buffer from hashing is reused for the push to avoid double disk I/O.

After upload: set `synchash = hash`, clear `previouspath`, set `synctime = Date.now()`.

**End**: if no skipped files, log "Fully synced", clear `fileRetry`, return `false`. If skipped files exist (in retry cooldown), return `true`.

### syncFileDown() -- Download Flow

1. If server entry is a folder:
   - If path exists as a folder: check for case-sensitive collisions, rename if needed.
   - If path exists as a file: delete the file, create the folder.
   - If path doesn't exist: create the folder.

2. If server entry is a file:
   - If path exists as a folder: if empty, remove it. If non-empty, rename to `(Conflicted copy)`.
   - Pull encrypted content via `server.pull(uid)`, decrypt.
   - Patch `core-plugins.json` to ensure sync stays enabled.
   - Concurrency guard: wait for pending filesystem operations, re-stat the file. If mtime or size changed during download, throw error (triggers per-path retry).
   - Write file with server's mtime and ctime preserved.
   - Update `localFiles` entry: `hash = synchash = downloadedHash`.

### Per-Path Retry Backoff

`failedSync(message)` records failure for `syncingPath`:
- `fileRetry[path] = { count, error, ts }`
- Delay: `5s * 2^count`, capped at 5 minutes.
- `canSyncPath(now, path)` blocks any path starting with a failed path's prefix until cooldown expires.
- On success, the retry entry is cleared.

### patchCorePluginsFile

Self-preservation: ensures the `sync` plugin stays enabled in `core-plugins.json`. Called during download and JSON merge of that file. If `sync` is missing from the plugin list, it gets added back.

### File Size Limits

Default `perFileMax`: 208,666,624 bytes (~199 MB). The server can override this during handshake. Files exceeding the limit are silently skipped during upload. No warning to the user.

### Device Name

Desktop: `require("os").hostname()`. Mobile: `Capacitor Device.getInfo().name`. Users can override in settings. Sent during WebSocket connect and shown in sync log for remote changes.

---

## Reconciliation Behavior (from app.js)

This section documents how the Obsidian desktop app handles reconciliation decisions. All behavior was reverse-engineered from `app.js`. Our implementation should match these decisions.

### Decision Tree for Incoming Server Pushes

For each server push received during the `init` -> `ready` window:

```
1. Server push is a deletion?
   - File exists locally and local hash matches server's previous hash (clean):
     Delete local file.
   - File exists locally but local hash differs (dirty):
     Keep local file, do not delete.
   - File does not exist locally:
     No-op (already gone).

2. Server push is a folder?
   - Create folder locally. No merge logic.

3. File does not exist locally?
   - Download from server (pull by uid).

4. Local hash matches server hash?
   - No-op. Files are identical.

5. Local hash matches previous server hash (clean local)?
   - Local is unchanged since last sync. Download server version.

6. Both sides changed — merge attempt:
   See "Merge Strategy by File Type" below.
```

### Merge Strategy by File Type

When both local and server have changed a file (hashes differ, local is dirty):

#### Markdown files (.md)

Three-way merge using diff-match-patch:

1. Fetch the base version from the server using `pull(prev.uid)`.
2. If no base is available (no previous uid, or pull fails):
   - If file was created less than 3 minutes ago: server wins.
   - Otherwise: compare mtimes. Server wins if server is newer. Local wins if local is newer or equal.
   - Local content is backed up to File Recovery plugin (fire-and-forget, errors swallowed).
   - No conflict copy file is created.
3. If base is available:
   - Back up local content to File Recovery (fire-and-forget).
   - Compute `diff(base, local)`, generate patches, apply patches onto server version.
   - The result of `patch_apply` includes a boolean array indicating which patches succeeded. Obsidian discards this array and writes the result regardless. Failed patches are silently lost.
   - No conflict copy file is created even on partial patch failure.
   - Logs "Merge successful" unconditionally.

#### JSON config files (.obsidian/*.json)

Shallow key merge:

1. Parse local JSON and server JSON.
2. For each key in server JSON, overwrite the local key.
3. Keys that exist locally but not on server are preserved.
4. Keys deleted on server are NOT removed locally.
5. Write merged result to disk.
6. If parsing fails, fall through to server-wins.

#### All other file types

Server wins unconditionally. No conflict copy. No backup to File Recovery. Local content is silently overwritten via `syncFileDown`.

### Conflict Copy Files

The Obsidian app only creates `(Conflicted copy)` files for type conflicts (file vs folder collisions):

- Local is a file, server wants a folder at the same path: rename local file to `path (Conflicted copy).ext`, then create folder.
- Local is a folder, server wants a file at the same path: rename folder to `path (Conflicted copy)`, then download file.

Conflict copy files are NOT created for:
- Non-mergeable file content conflicts (server wins silently)
- Three-way merge failures (partial patches silently applied)
- No-base merge fallbacks (server or local wins by mtime)

Conflict copy paths use a single fixed name (`path (Conflicted copy).ext`). No deduplication or counter. If a conflict copy already exists at that path, it gets overwritten.

The rename operations for conflict copies have no error handling. A failed rename propagates as an uncaught exception and aborts the reconciliation cycle.

### File Recovery Plugin

The only backup mechanism for merge scenarios is `storeTextFileBackup`, which stores content in the File Recovery plugin's internal database (not a visible file). This is:

- Fire-and-forget (errors are swallowed in a try/catch)
- Only called for .md files going through the merge path
- Not called for non-mergeable files
- Dependent on the File Recovery plugin being enabled
- An internal database, not a user-visible file

### Server Push Handling During Operations

When the client is in the middle of a push or pull and receives a server push:

- Folder pushes and delete pushes are processed inline immediately.
- File pushes that need content are queued as pending pulls and drained after the current operation completes.
- Pong messages are handled inline (no-op beyond keepalive tracking).

### Sync Loop and Failure Handling

The Obsidian app does not use a separate offline event queue. Instead:

- `localFiles` is a persistent dictionary (saved to IndexedDB) tracking the state of every local file. Vault event handlers (create, modify, delete, rename) update this dictionary regardless of connection state.
- `newServerFiles` is a persistent array of server-pushed records waiting to be reconciled. Saved to IndexedDB as `pending`.
- `requestSync()` is called after every vault event, on WebSocket reconnect (`onReady`), and every 30 seconds via a timer.
- `_sync()` processes exactly one file per call (download, upload, delete, or merge), then returns `true` if more work remains. `requestSync()` loops calling `_sync()` with 50ms throttle until nothing remains.

On failure:
- `_sync()` throws, which is caught by `requestSync()`.
- The failed file stays in `localFiles` or `newServerFiles` (never removed on failure).
- Per-path exponential backoff is recorded in `fileRetry`: `5s * 2^count`, capped at 5 minutes.
- On the next `_sync()` call, `canSyncPath()` checks the backoff timer and skips files still in their cooldown window.
- On success, the retry entry is cleared.
- Connection-level backoff uses a separate `Y1` class: `5s * 2^count` with jitter, capped at 5 minutes.

Failed pushes while connected are treated as permanent failures for that sync cycle. The file remains in the persistent state dictionaries and will be retried with backoff on the next cycle. There is no separate retry queue.

### Delete and Upload Ordering

When pushing deletes to the server (files that exist on server but not locally):
- Deepest-first ordering using `path.length` (string length, not separator count) as a proxy for depth.
- Files are deleted before folders.
- One delete per sync cycle pass. The sync loop re-enters for the next one.
- After a successful delete push, the server record is marked `deleted = true` in the local state.
- Guard on incoming folder deletes: the app refuses to delete a local folder that still has children.

When uploading local changes to the server:
- Folders uploaded first, shallowest-first (shortest `path.length`).
- Files uploaded after folders, smallest-first (by `size`).

### Operation Serialization

The Obsidian app uses a single-operation promise queue (class `cL`) that serializes all push and pull operations. Only one operation executes at a time. Pings bypass this queue and are sent directly on the socket via `setInterval`. The server tolerates pings arriving between binary chunks during a push sequence.

---

## Data Encoding Helpers

| Function | Purpose |
|----------|---------|
| `hf(str)` | String → ArrayBuffer (TextEncoder UTF-8) |
| `df(buf)` | ArrayBuffer → String (TextDecoder UTF-8) |
| `bf(buf)` | ArrayBuffer → hex string |
| `yf(hex)` | Hex string → ArrayBuffer |
| `gf(buf)` | SHA-256 hash (returns ArrayBuffer) |
| `pf(b64)` | Base64 → ArrayBuffer |
| `ff(buf)` | ArrayBuffer → Base64 |
| `uf(u8)` | Uint8Array → ArrayBuffer (slice from typed array) |

---

## Constants

| Name | Value | Purpose |
|------|-------|---------|
| `perFileMax` | 5,242,880 (5MB) | Max file size |
| Chunk size | 2,097,152 (2MB) | Binary frame chunk size for uploads |
| Ping interval | 10,000ms | Send ping after this idle time |
| Disconnect timeout | 120,000ms | Disconnect after this idle time |
| Heartbeat check | 20,000ms | Interval to check connection health |
| scrypt N | 32,768 | Cost parameter |
| scrypt r | 8 | Block size |
| scrypt p | 1 | Parallelization |
| scrypt maxmem | 67,108,864 | Max memory |
| scrypt dkLen | 32 | Output key length |
| AES-GCM IV | 12 bytes | Nonce size |
| AES-SIV block | 16 bytes | CMAC block size |
