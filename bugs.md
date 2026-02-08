# Bugs and Issues -- Review 4 (Final app.js Audit)

## Bug 40: NFKC normalization missing in DeriveKey
- **File**: `obsidian/crypto.go:16-17`
- **Severity**: Medium
- **Status**: FIXED
- app.js normalizes both password and salt to NFKC before scrypt. We pass raw strings. Users with non-ASCII characters in their password or email (salt) will derive a wrong key.
- Fix: added `norm.NFKC.String()` from `golang.org/x/text/unicode/norm`

## Bug 41: No mtime preservation on downloaded files
- **File**: `obsidian/vault.go:47`
- **Severity**: High
- **Status**: FIXED
- app.js calls `utimes()` to set mtime to the server value after writing. We use bare `os.WriteFile` so downloads get the current system time. The scanner then detects them as "changed" and may re-upload.
- Fix: added `mtime time.Time` parameter to `WriteFile`, calls `os.Chtimes()` when non-zero. Server download paths pass `time.UnixMilli(push.MTime)`. Conflict copies pass zero time.

## Bug 42: Extension extraction operates on full path instead of basename
- **File**: `obsidian/sync.go:543`
- **Severity**: Medium
- **Status**: FIXED
- `strings.LastIndex(op.path, ".")` finds the last dot in the entire path. For `folder.with.dots/file` this returns `"with.dots/file"` as the extension. app.js extracts basename first. Also not lowercased.
- Fix: extract basename first, find dot after position 0 and before end, lowercase result. Matches app.js edge cases for dotfiles and trailing dots.

## Bug 43: Initial sync processes deletions
- **File**: `obsidian/reconcile.go`
- **Severity**: Medium
- **Status**: OPEN
- app.js drops deleted pushes during initial sync (`if (this.initial && e.deleted) return`). We process them, potentially deleting local files that the server already excluded.
- Fix: check `initial` flag in Phase1 and skip deleted entries.

## Bug 44: Delete ordering doesn't separate files from folders
- **File**: `obsidian/reconcile.go`
- **Severity**: Medium
- **Status**: OPEN
- app.js deletes files first (deepest first), then folders (deepest first) in separate passes. We don't separate them. If we delete a folder before its children, the server may reject it.

## Bug 45: MFA field missing from signin
- **File**: `obsidian/client.go`
- **Severity**: Low (only affects 2FA users)
- **Status**: WON'T FIX
- `SigninRequest` is missing the `mfa` field. Users with 2FA enabled cannot authenticate. vault-sync is a headless daemon with no way to prompt for a TOTP code. Users with 2FA must disable it or obtain a token through other means.

## Bug 46: isPermanentError too narrow
- **File**: `obsidian/sync.go:1530-1539`
- **Severity**: Medium
- **Status**: FIXED
- Only checked for "auth failed". Now also detects "subscription" and "Vault not found" as permanent errors.

## Bug 47: Response timeout is 30s vs app.js 60s
- **File**: `obsidian/sync.go`
- **Severity**: Low
- **Status**: FIXED
- Bumped `responseTimeout` from 30s to 60s to match app.js.

## Bug 48: Reconnect backoff caps at 60s vs app.js 300s
- **File**: `obsidian/sync.go`
- **Severity**: Low
- **Status**: FIXED
- Bumped `reconnectMax` from 60s to 5 minutes. Also bumped `reconnectMin` from 1s to 5s to match app.js base.

## Bug 49: Default perFileMax is 0
- **File**: `obsidian/sync.go:76`
- **Severity**: Low
- **Status**: FIXED
- Set default `perFileMax` to 208,666,624 (~199 MB) in `NewSyncClient`, matching app.js client default.

## Bug 50: No perFileMax enforcement before upload
- **File**: `obsidian/sync.go`
- **Severity**: Low
- **Status**: FIXED
- Added size check in `executePush` before encrypting content. Files exceeding `perFileMax` are logged and silently skipped, matching app.js behavior.

## Bug 51: No pre-write re-stat guard during download
- **File**: `obsidian/sync.go:904`
- **Severity**: Medium
- **Status**: OPEN
- app.js re-stats the file after pulling content and before writing. If mtime/size changed (user edited while downloading), app.js aborts. We silently overwrite. Lower risk for a headless daemon but still a race condition.

## Bug 52: No per-path retry backoff
- **File**: `obsidian/sync.go`, `obsidian/watcher.go`
- **Severity**: Medium
- **Status**: OPEN
- app.js tracks `{count, error, ts}` per path with `5s * 2^count` backoff capped at 5 minutes. If a file fails repeatedly, we retry on every watcher event with no delay. Could cause log spam and server load.

## Bug 53: Extension not lowercased
- **File**: `obsidian/sync.go:543`
- **Severity**: Low
- **Status**: FIXED (covered by Bug 42 fix)

## Bug 54: No workspace.json exclusion
- **File**: `obsidian/watcher.go`, `obsidian/scanner.go`
- **Severity**: Low
- **Status**: FIXED
- Added `workspace.json` and `workspace-mobile.json` to `shouldIgnore` in watcher and scanner skip logic.

## Bug 55: Auth response missing msg field
- **File**: `obsidian/types.go:68`
- **Severity**: Low
- **Status**: FIXED
- Added `Msg string` field to `InitResponse`. Auth failure now uses `msg` for descriptive error messages.
