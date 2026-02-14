package obsidian

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSyncVaultID = "sync-test-vault"

var quietLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// cachedCipher is derived once and reused across all tests in this file.
// scrypt is intentionally slow, so running it per-test adds ~0.4s each.
var cachedCipher *CipherV0

func init() {
	key, err := DeriveKey("testpass", "testsalt")
	if err != nil {
		panic("DeriveKey failed: " + err.Error())
	}

	c, err := NewCipherV0(key)
	if err != nil {
		panic("NewCipherV0 failed: " + err.Error())
	}

	cachedCipher = c
}

// fullSyncClient builds a SyncClient with real cipher, vault, and state.
// No WebSocket connection is set (conn is nil). For tests that need a
// conn (executePush), set s.conn and s.inboundCh separately.
func fullSyncClient(t *testing.T) (*SyncClient, *Vault, *state.State, *CipherV0) {
	t.Helper()

	cipher := cachedCipher

	vault := tempVault(t)

	dbPath := filepath.Join(t.TempDir(), "test.db")
	appState, err := state.LoadAt(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { appState.Close() })
	require.NoError(t, appState.InitVaultBuckets(testSyncVaultID))

	s := NewSyncClient(SyncConfig{
		VaultID: testSyncVaultID,
		Cipher:  cipher,
		Vault:   vault,
		State:   appState,
	}, quietLogger)

	return s, vault, appState, cipher
}

// fakePull returns a pullFunc that returns the given encrypted content.
func fakePull(encContent []byte) pullFunc {
	return func(ctx context.Context, uid int64) ([]byte, error) {
		return encContent, nil
	}
}

// fakePullDeleted returns a pullFunc that returns nil (file was deleted).
func fakePullDeleted() pullFunc {
	return func(ctx context.Context, uid int64) ([]byte, error) {
		return nil, nil
	}
}

// fakePullError returns a pullFunc that returns an error.
func fakePullError(msg string) pullFunc {
	return func(ctx context.Context, uid int64) ([]byte, error) {
		return nil, fmt.Errorf("%s", msg)
	}
}

// encryptContent is a test helper that encrypts content with the given cipher.
func encryptContent(t *testing.T, cipher *CipherV0, plaintext []byte) []byte {
	t.Helper()

	enc, err := cipher.EncryptContent(plaintext)
	require.NoError(t, err)

	return enc
}

// encryptPath is a test helper that encrypts a path with the given cipher.
func encryptPath(t *testing.T, cipher *CipherV0, path string) string {
	t.Helper()

	enc, err := cipher.EncryptPath(path)
	require.NoError(t, err)

	return enc
}

// --- executeLiveDecision ---

func TestExecuteLiveDecision_Skip(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)
	ctx := context.Background()

	push := PushMessage{UID: 1, Hash: "h1", MTime: 1000}
	err := s.executeLiveDecision(ctx, DecisionSkip, "notes/skip.md", push, nil, nil, nil)
	require.NoError(t, err)

	// Should persist server file state.
	sf, err := appState.GetServerFile(testSyncVaultID, "notes/skip.md")
	require.NoError(t, err)
	require.NotNil(t, sf)
	assert.Equal(t, int64(1), sf.UID)
}

func TestExecuteLiveDecision_DownloadFile(t *testing.T) {
	s, vault, appState, cipher := fullSyncClient(t)
	ctx := context.Background()

	content := []byte("downloaded content")
	encContent := encryptContent(t, cipher, content)

	push := PushMessage{
		UID:   10,
		Hash:  "enc-hash",
		MTime: 5000,
		Size:  int64(len(encContent)),
	}

	err := s.executeLiveDecision(ctx, DecisionDownload, "dl.md", push, nil, nil, fakePull(encContent))
	require.NoError(t, err)

	// File should be written to vault.
	data, err := vault.ReadFile("dl.md")
	require.NoError(t, err)
	assert.Equal(t, content, data)

	// Server state persisted.
	sf, err := appState.GetServerFile(testSyncVaultID, "dl.md")
	require.NoError(t, err)
	require.NotNil(t, sf)
	assert.Equal(t, int64(10), sf.UID)

	// Local state persisted.
	lf, err := appState.GetLocalFile(testSyncVaultID, "dl.md")
	require.NoError(t, err)
	require.NotNil(t, lf)
	assert.Equal(t, sha256Hex(content), lf.Hash)
}

func TestExecuteLiveDecision_DownloadFolder(t *testing.T) {
	s, vault, appState, _ := fullSyncClient(t)
	ctx := context.Background()

	push := PushMessage{UID: 20, Folder: true}

	err := s.executeLiveDecision(ctx, DecisionDownload, "new-folder", push, nil, nil, nil)
	require.NoError(t, err)

	// Directory should exist.
	info, err := vault.Stat("new-folder")
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	// Server state.
	sf, err := appState.GetServerFile(testSyncVaultID, "new-folder")
	require.NoError(t, err)
	require.NotNil(t, sf)
	assert.True(t, sf.Folder)

	// Local state.
	lf, err := appState.GetLocalFile(testSyncVaultID, "new-folder")
	require.NoError(t, err)
	require.NotNil(t, lf)
	assert.True(t, lf.Folder)
}

func TestExecuteLiveDecision_DeleteLocalFile(t *testing.T) {
	s, vault, appState, _ := fullSyncClient(t)
	ctx := context.Background()

	// Create a file that will be deleted.
	require.NoError(t, vault.WriteFile("doomed.md", []byte("bye"), time.Time{}))
	require.NoError(t, appState.SetLocalFile(testSyncVaultID, state.LocalFile{
		Path: "doomed.md",
		Size: 3,
	}))

	push := PushMessage{UID: 30, Deleted: true}
	err := s.executeLiveDecision(ctx, DecisionDeleteLocal, "doomed.md", push, nil, nil, nil)
	require.NoError(t, err)

	// File should be gone.
	_, err = vault.ReadFile("doomed.md")
	assert.True(t, os.IsNotExist(err))

	// Local state removed.
	lf, err := appState.GetLocalFile(testSyncVaultID, "doomed.md")
	require.NoError(t, err)
	assert.Nil(t, lf)

	// Server state should be removed (deleted entry).
	sf, err := appState.GetServerFile(testSyncVaultID, "doomed.md")
	require.NoError(t, err)
	assert.Nil(t, sf)
}

func TestExecuteLiveDecision_DeleteLocalFolder_Empty(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)
	ctx := context.Background()

	require.NoError(t, vault.MkdirAll("empty-dir"))

	push := PushMessage{Folder: true, Deleted: true}
	err := s.executeLiveDecision(ctx, DecisionDeleteLocal, "empty-dir", push, nil, nil, nil)
	require.NoError(t, err)

	// Directory should be removed.
	_, err = vault.Stat("empty-dir")
	assert.True(t, os.IsNotExist(err))
}

func TestExecuteLiveDecision_DeleteLocalFolder_NonEmpty(t *testing.T) {
	s, vault, appState, _ := fullSyncClient(t)
	ctx := context.Background()

	// Folder with a child -- DeleteEmptyDir will fail, should not error.
	require.NoError(t, vault.WriteFile("non-empty/child.md", []byte("keep"), time.Time{}))

	push := PushMessage{Folder: true, Deleted: true}
	err := s.executeLiveDecision(ctx, DecisionDeleteLocal, "non-empty", push, nil, nil, nil)
	require.NoError(t, err)

	// Folder should still exist.
	info, err := vault.Stat("non-empty")
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	// Server state still persisted (as deleted).
	sf, err := appState.GetServerFile(testSyncVaultID, "non-empty")
	require.NoError(t, err)
	assert.Nil(t, sf, "deleted server entry should be removed from bbolt")
}

func TestExecuteLiveDecision_KeepLocal(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("kept.md", []byte("local only"), time.Time{}))

	push := PushMessage{Deleted: true}
	err := s.executeLiveDecision(ctx, DecisionKeepLocal, "kept.md", push, nil, nil, nil)
	require.NoError(t, err)

	// File should still exist.
	data, err := vault.ReadFile("kept.md")
	require.NoError(t, err)
	assert.Equal(t, []byte("local only"), data)
}

func TestExecuteLiveDecision_MergeMD(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("merge.md", []byte("local content"), time.Time{}))

	// Server has different content; no prev, so liveMergeMD will fall back
	// to mtime comparison. Server mtime is newer, so server wins.
	serverContent := []byte("server content")
	encContent := encryptContent(t, cipher, serverContent)

	local := &state.LocalFile{Path: "merge.md", MTime: 1000}
	push := PushMessage{UID: 40, MTime: 2000}

	err := s.executeLiveDecision(ctx, DecisionMergeMD, "merge.md", push, local, nil, fakePull(encContent))
	require.NoError(t, err)

	data, _ := vault.ReadFile("merge.md")
	assert.Equal(t, serverContent, data)
}

func TestExecuteLiveDecision_MergeJSON(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile(".obsidian/app.json", []byte(`{"local":"val"}`), time.Time{}))

	serverJSON := []byte(`{"server":"val"}`)
	encContent := encryptContent(t, cipher, serverJSON)

	push := PushMessage{UID: 41, MTime: time.Now().UnixMilli()}

	err := s.executeLiveDecision(ctx, DecisionMergeJSON, ".obsidian/app.json", push, nil, nil, fakePull(encContent))
	require.NoError(t, err)

	data, _ := vault.ReadFile(".obsidian/app.json")
	assert.Contains(t, string(data), "local")
	assert.Contains(t, string(data), "server")
}

func TestExecuteLiveDecision_TypeConflict_LocalFile(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("clash.txt", []byte("local file"), time.Time{}))

	local := &state.LocalFile{Path: "clash.txt", Folder: false}
	push := PushMessage{UID: 42, Folder: true}

	err := s.executeLiveDecision(ctx, DecisionTypeConflict, "clash.txt", push, local, nil, nil)
	require.NoError(t, err)

	// Conflict copy should exist.
	cpData, err := vault.ReadFile("clash (Conflicted copy).txt")
	require.NoError(t, err)
	assert.Equal(t, []byte("local file"), cpData)

	// Original path should be a folder.
	info, err := vault.Stat("clash.txt")
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestExecuteLiveDecision_TypeConflict_LocalFolder(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	require.NoError(t, vault.MkdirAll("fclash"))

	plain := []byte("server file")
	encContent := encryptContent(t, cipher, plain)

	local := &state.LocalFile{Path: "fclash", Folder: true}
	push := PushMessage{UID: 43, MTime: time.Now().UnixMilli()}

	err := s.executeLiveDecision(ctx, DecisionTypeConflict, "fclash", push, local, nil, fakePull(encContent))
	require.NoError(t, err)

	// Conflict copy of folder.
	_, err = vault.Stat("fclash (Conflicted copy)")
	assert.NoError(t, err)

	// Server file at original path.
	data, err := vault.ReadFile("fclash")
	require.NoError(t, err)
	assert.Equal(t, plain, data)
}

func TestExecuteLiveDecision_UnknownDecision(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	ctx := context.Background()

	err := s.executeLiveDecision(ctx, ReconcileDecision(99), "x.md", PushMessage{}, nil, nil, nil)
	assert.NoError(t, err)
}

// --- liveDownload ---

func TestLiveDownload_WritesDecryptedContent(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	content := []byte("fresh from server")
	encContent := encryptContent(t, cipher, content)

	push := PushMessage{UID: 100, MTime: 2000}
	err := s.liveDownload(ctx, "server-file.md", push, fakePull(encContent))
	require.NoError(t, err)

	data, err := vault.ReadFile("server-file.md")
	require.NoError(t, err)
	assert.Equal(t, content, data)
}

func TestLiveDownload_DeletedContentSkips(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)
	ctx := context.Background()

	push := PushMessage{UID: 200}
	err := s.liveDownload(ctx, "deleted-on-server.md", push, fakePullDeleted())
	require.NoError(t, err)

	// Should not create the file. Server state persisted as deleted.
	sf, err := appState.GetServerFile(testSyncVaultID, "deleted-on-server.md")
	require.NoError(t, err)
	assert.Nil(t, sf)
}

func TestLiveDownload_CreatesFolder(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)
	ctx := context.Background()

	push := PushMessage{Folder: true}
	err := s.liveDownload(ctx, "new-dir", push, nil)
	require.NoError(t, err)

	info, err := vault.Stat("new-dir")
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestLiveDownload_PullError(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	ctx := context.Background()

	push := PushMessage{UID: 300}
	err := s.liveDownload(ctx, "fail.md", push, fakePullError("connection dropped"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection dropped")
}

func TestLiveDownload_EmptyContent(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	// Empty content encrypts to just the nonce.
	encContent := encryptContent(t, cipher, []byte{})

	push := PushMessage{UID: 400, MTime: 3000}
	err := s.liveDownload(ctx, "empty.md", push, fakePull(encContent))
	require.NoError(t, err)

	data, err := vault.ReadFile("empty.md")
	require.NoError(t, err)
	assert.Empty(t, data)
}

func TestLiveDownload_PopulatesHashCache(t *testing.T) {
	s, _, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	content := []byte("cache me")
	encContent := encryptContent(t, cipher, content)

	push := PushMessage{UID: 500, Hash: "enc-hash-value"}
	err := s.liveDownload(ctx, "cached.md", push, fakePull(encContent))
	require.NoError(t, err)

	// ContentHash should return the plaintext content hash.
	assert.Equal(t, sha256Hex(content), s.ContentHash("cached.md"))
}

func TestLiveDownload_FileChangedDuringDownload(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	// Pre-existing file that gets modified during the "pull".
	require.NoError(t, vault.WriteFile("racing.md", []byte("original"), time.Time{}))

	content := []byte("from server")
	encContent := encryptContent(t, cipher, content)

	// Use a pull that modifies the file mid-download.
	modifyingPull := func(ctx context.Context, uid int64) ([]byte, error) {
		// Simulate local modification during download.
		_ = vault.WriteFile("racing.md", []byte("modified locally while downloading"), time.Time{})
		return encContent, nil
	}

	push := PushMessage{UID: 600}
	err := s.liveDownload(ctx, "racing.md", push, modifyingPull)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "changed locally during download")
}

// --- processPush ---

func TestProcessPush_DownloadsNewFile(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	content := []byte("new from server push")
	encContent := encryptContent(t, cipher, content)
	encPath := encryptPath(t, cipher, "pushed.md")

	// processPush uses s.pull which reads from inboundCh. We need
	// to bypass that by setting up a pullFunc. Since processPush
	// hardcodes s.pull, we test the full flow via executeLiveDecision
	// with a real Reconcile call instead.
	push := PushMessage{
		UID:  700,
		Path: encPath,
		Hash: encryptPath(t, cipher, "somehash"),
		Size: int64(len(encContent)),
	}

	// Call the parts processPush calls: decrypt, reconcile, execute.
	path, err := cipher.DecryptPath(push.Path)
	require.NoError(t, err)

	path = normalizePath(path)

	local, encLocalHash := s.resolveLocalState(path)
	decision := Reconcile(local, nil, push, encLocalHash, false)
	assert.Equal(t, DecisionDownload, decision)

	err = s.executeLiveDecision(ctx, decision, path, push, local, nil, fakePull(encContent))
	require.NoError(t, err)

	data, err := vault.ReadFile("pushed.md")
	require.NoError(t, err)
	assert.Equal(t, content, data)
}

func TestProcessPush_SkipsDeletedWithNoLocal(t *testing.T) {
	s, _, _, cipher := fullSyncClient(t)

	encPath := encryptPath(t, cipher, "nonexistent.md")
	push := PushMessage{
		UID:     800,
		Path:    encPath,
		Deleted: true,
	}

	path, _ := cipher.DecryptPath(push.Path)
	path = normalizePath(path)

	local, encLocalHash := s.resolveLocalState(path)
	assert.Nil(t, local)
	decision := Reconcile(local, nil, push, encLocalHash, false)
	assert.Equal(t, DecisionSkip, decision)
}

// --- resolveLocalState ---

func TestResolveLocalState_FileNotOnDisk(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	local, encHash := s.resolveLocalState("nonexistent.md")
	assert.Nil(t, local)
	assert.Empty(t, encHash)
}

func TestResolveLocalState_NewFileOnDisk(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)

	content := []byte("local file")
	require.NoError(t, vault.WriteFile("local.md", content, time.Time{}))

	local, encHash := s.resolveLocalState("local.md")
	require.NotNil(t, local)
	assert.Equal(t, "local.md", local.Path)
	assert.Equal(t, int64(len(content)), local.Size)
	assert.Equal(t, sha256Hex(content), local.Hash)
	// encHash should be non-empty (encrypted form of the hash).
	assert.NotEmpty(t, encHash)
}

func TestResolveLocalState_PersistedHashReused(t *testing.T) {
	s, vault, appState, _ := fullSyncClient(t)

	content := []byte("persisted content")
	require.NoError(t, vault.WriteFile("persisted.md", content, time.Time{}))

	info, _ := vault.Stat("persisted.md")
	require.NoError(t, appState.SetLocalFile(testSyncVaultID, state.LocalFile{
		Path:  "persisted.md",
		MTime: info.ModTime().UnixMilli(),
		Size:  info.Size(),
		Hash:  "cached-hash-value",
	}))

	local, _ := s.resolveLocalState("persisted.md")
	require.NotNil(t, local)
	// Should reuse the persisted hash since mtime/size match.
	assert.Equal(t, "cached-hash-value", local.Hash)
}

func TestResolveLocalState_Directory(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)
	require.NoError(t, vault.MkdirAll("some-dir"))

	local, encHash := s.resolveLocalState("some-dir")
	require.NotNil(t, local)
	assert.True(t, local.Folder)
	assert.Empty(t, encHash, "directories have no content hash")
}

func TestResolveLocalState_HashMismatch_ReHashFromDisk(t *testing.T) {
	s, vault, appState, _ := fullSyncClient(t)

	// Write file, persist with matching mtime but wrong size to trigger re-hash.
	content := []byte("real content on disk")
	require.NoError(t, vault.WriteFile("changed.md", content, time.Time{}))

	info, _ := vault.Stat("changed.md")
	require.NoError(t, appState.SetLocalFile(testSyncVaultID, state.LocalFile{
		Path:     "changed.md",
		MTime:    info.ModTime().UnixMilli(),
		Size:     999, // Different from actual size -> triggers re-hash.
		Hash:     "stale-hash",
		SyncHash: "old-sync-hash",
		SyncTime: 42,
	}))

	local, encHash := s.resolveLocalState("changed.md")
	require.NotNil(t, local)

	// Hash should be recomputed from disk.
	assert.Equal(t, sha256Hex(content), local.Hash)
	assert.NotEmpty(t, encHash)

	// SyncHash should be carried over from persisted state.
	assert.Equal(t, "old-sync-hash", local.SyncHash)
	assert.Equal(t, int64(42), local.SyncTime)
}

func TestResolveLocalState_HashMismatch_NoPersistedState(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)

	// File on disk with no persisted state at all -> hash from disk, no SyncHash.
	content := []byte("new file")
	require.NoError(t, vault.WriteFile("fresh.md", content, time.Time{}))

	local, encHash := s.resolveLocalState("fresh.md")
	require.NotNil(t, local)
	assert.Equal(t, sha256Hex(content), local.Hash)
	assert.NotEmpty(t, encHash)
	assert.Empty(t, local.SyncHash)
}

func TestResolveLocalState_PersistedEmptyHash(t *testing.T) {
	s, vault, appState, _ := fullSyncClient(t)

	// Persisted entry with matching mtime/size but empty hash -> re-hash from disk.
	content := []byte("has content")
	require.NoError(t, vault.WriteFile("empty-hash.md", content, time.Time{}))

	info, _ := vault.Stat("empty-hash.md")
	require.NoError(t, appState.SetLocalFile(testSyncVaultID, state.LocalFile{
		Path:  "empty-hash.md",
		MTime: info.ModTime().UnixMilli(),
		Size:  info.Size(),
		Hash:  "", // Empty hash -> won't reuse, falls through to re-hash.
	}))

	local, encHash := s.resolveLocalState("empty-hash.md")
	require.NotNil(t, local)
	assert.Equal(t, sha256Hex(content), local.Hash)
	assert.NotEmpty(t, encHash)
}

// --- retryBackoff ---

func TestRetryBackoff_InitiallyNone(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	_, shouldSkip := s.checkRetryBackoff("test.md")
	assert.False(t, shouldSkip)
}

func TestRetryBackoff_RecordAndCheck(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	s.recordRetryBackoff("fail.md")

	_, shouldSkip := s.checkRetryBackoff("fail.md")
	assert.True(t, shouldSkip, "should be in backoff after recording")
}

func TestRetryBackoff_ClearResetsBackoff(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	s.recordRetryBackoff("fail.md")
	s.clearRetryBackoff("fail.md")

	_, shouldSkip := s.checkRetryBackoff("fail.md")
	assert.False(t, shouldSkip, "should not be in backoff after clear")
}

// --- persistServerFile ---

func TestPersistServerFile_SavesEntry(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)

	push := PushMessage{
		UID:    42,
		Hash:   "server-hash",
		MTime:  1000,
		CTime:  900,
		Size:   100,
		Folder: false,
		Device: "dev-1",
	}
	s.persistServerFile("saved.md", push, false)

	sf, err := appState.GetServerFile(testSyncVaultID, "saved.md")
	require.NoError(t, err)
	require.NotNil(t, sf)
	assert.Equal(t, int64(42), sf.UID)
	assert.Equal(t, "server-hash", sf.Hash)
	assert.Equal(t, "dev-1", sf.Device)
}

func TestPersistServerFile_DeletedRemovesEntry(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)

	// First save, then delete.
	s.persistServerFile("temp.md", PushMessage{UID: 1}, false)
	s.persistServerFile("temp.md", PushMessage{UID: 1}, true)

	sf, err := appState.GetServerFile(testSyncVaultID, "temp.md")
	require.NoError(t, err)
	assert.Nil(t, sf, "deleted entry should be removed")
}

// --- decryptPush ---

func TestDecryptPush_RoundTrip(t *testing.T) {
	s, _, _, cipher := fullSyncClient(t)

	encPath := encryptPath(t, cipher, "notes/hello.md")
	push := PushMessage{Path: encPath, UID: 99}

	sp, err := s.decryptPush(push)
	require.NoError(t, err)
	assert.Equal(t, "notes/hello.md", sp.Path)
	assert.Equal(t, int64(99), sp.Msg.UID)
}

func TestDecryptPush_InvalidPath(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)

	push := PushMessage{Path: "not-valid-hex"}
	_, err := s.decryptPush(push)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decrypting path")
}

// --- hashCache ---

func TestContentHash_EmptyByDefault(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	assert.Empty(t, s.ContentHash("anything.md"))
}

func TestContentHash_SetAndGet(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)

	s.hashCacheMu.Lock()
	s.hashCache["test.md"] = hashEntry{encHash: "enc", contentHash: "plain"}
	s.hashCacheMu.Unlock()

	assert.Equal(t, "plain", s.ContentHash("test.md"))
}

func TestRemoveHashCache(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)

	s.hashCacheMu.Lock()
	s.hashCache["remove-me.md"] = hashEntry{contentHash: "x"}
	s.hashCacheMu.Unlock()

	s.removeHashCache("remove-me.md")
	assert.Empty(t, s.ContentHash("remove-me.md"))
}

// --- resolveLocalState: additional branches ---

func TestResolveLocalState_StatError_NonENOENT(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)
	// Create a file then remove the parent directory to cause a non-ENOENT
	// stat error (ENOTDIR when the parent is gone).
	require.NoError(t, vault.WriteFile("sub/file.md", []byte("x"), time.Time{}))
	// Remove the directory out from under the vault by manipulating the
	// filesystem directly. Stat on "sub/file.md" will fail because "sub"
	// is gone, but the error is not os.IsNotExist on the file itself.
	require.NoError(t, os.RemoveAll(filepath.Join(vault.Dir(), "sub")))

	lf, enc := s.resolveLocalState("sub/file.md")
	// Non-ENOENT stat error should return nil, "".
	assert.Nil(t, lf)
	assert.Empty(t, enc)
}

func TestResolveLocalState_ReadFileError_WithPersistedState(t *testing.T) {
	s, vault, appState, _ := fullSyncClient(t)
	// Write a real file so Stat succeeds.
	require.NoError(t, vault.WriteFile("readable.md", []byte("hello"), time.Time{}))

	// Persist a local file state.
	persisted := state.LocalFile{
		Path:     "readable.md",
		MTime:    1,   // mtime won't match the real file, forcing re-hash
		Size:     999, // size won't match either
		Hash:     "oldhash",
		SyncHash: "synchash",
		SyncTime: 42,
	}
	require.NoError(t, appState.SetLocalFile(testSyncVaultID, persisted))

	// Make the file unreadable so ReadFile fails after Stat succeeds.
	realPath := filepath.Join(vault.Dir(), "readable.md")
	require.NoError(t, os.Chmod(realPath, 0o000))
	t.Cleanup(func() { _ = os.Chmod(realPath, 0o644) })

	lf, enc := s.resolveLocalState("readable.md")
	require.NotNil(t, lf)
	// Should return the persisted state as fallback.
	assert.Equal(t, "oldhash", lf.Hash)
	assert.Empty(t, enc)
}

func TestResolveLocalState_ReadFileError_NoPersistedState(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)
	// Write a real file so Stat succeeds.
	require.NoError(t, vault.WriteFile("nostate.md", []byte("data"), time.Time{}))

	// Make the file unreadable so ReadFile fails.
	realPath := filepath.Join(vault.Dir(), "nostate.md")
	require.NoError(t, os.Chmod(realPath, 0o000))
	t.Cleanup(func() { _ = os.Chmod(realPath, 0o644) })

	lf, enc := s.resolveLocalState("nostate.md")
	require.NotNil(t, lf)
	// No persisted state: returns a barebones LocalFile with mtime/size from stat.
	assert.Equal(t, "nostate.md", lf.Path)
	assert.Empty(t, lf.Hash, "hash should be empty when ReadFile fails")
	assert.Empty(t, enc)
}

// --- persistPushedFile: stat error fallback ---

func TestPersistPushedFile_StatError_UsesFallbackValues(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)
	// Don't create the file on disk, so Stat will fail.
	// persistPushedFile should fall back to len(content) and mtime arg.
	content := []byte("orphan-content")
	s.persistPushedFile("gone.md", content, "enchash", 5000, 3000)

	lf, err := appState.GetLocalFile(testSyncVaultID, "gone.md")
	require.NoError(t, err)
	require.NotNil(t, lf)
	assert.Equal(t, int64(len(content)), lf.Size)
	assert.Equal(t, int64(5000), lf.MTime)
	// CTime should be zero when stat fails (no fileCt assignment).
	assert.Equal(t, int64(0), lf.CTime)
}

// --- persistVersionIfDirty: SetVault error ---

func TestPersistVersionIfDirty_SetVaultError(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)
	s.versionDirty = true
	s.version = 999

	// Close the state DB to force SetVault to fail.
	appState.Close()

	// Should not panic; logs a warning and returns.
	s.persistVersionIfDirty()
	// versionDirty was reset to false before the error check.
	assert.False(t, s.versionDirty)
}

// --- persist* bbolt error branches ---
// These functions only log errors (no return), so we close the DB to trigger
// errors and verify the functions don't panic.

func TestPersistServerFile_SetError(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)
	appState.Close()

	// Should log warning but not panic.
	push := PushMessage{Hash: "h", UID: 1}
	s.persistServerFile("test.md", push, false)
}

func TestPersistServerFile_DeleteError(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)
	appState.Close()

	// Deleted path: calls DeleteServerFile which will fail.
	push := PushMessage{Hash: "h", UID: 1}
	s.persistServerFile("test.md", push, true)
}

func TestPersistLocalFileAfterWrite_SetLocalFileError(t *testing.T) {
	s, vault, appState, _ := fullSyncClient(t)
	// Write a real file so Stat succeeds.
	require.NoError(t, vault.WriteFile("written.md", []byte("data"), time.Time{}))
	appState.Close()

	// Stat succeeds but SetLocalFile fails. Should log, not panic.
	s.persistLocalFileAfterWrite("written.md", "hash")
}

func TestPersistLocalFolder_SetLocalFileError(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)
	appState.Close()

	// Should log warning but not panic.
	s.persistLocalFolder("folder")
}

func TestPersistPushedFolder_SetLocalFileError(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)
	appState.Close()

	// Both SetLocalFile and SetServerFile will fail. Neither should panic.
	s.persistPushedFolder("folder")
}

func TestPersistPushedDelete_DeleteServerFileError(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)
	appState.Close()

	// DeleteServerFile and DeleteLocalFile will both fail. No panic.
	s.persistPushedDelete("gone.md")
}

func TestDeleteLocalState_Error(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)
	appState.Close()

	// Should log warning but not panic.
	s.deleteLocalState("gone.md")
}

func TestServerFileState_Error(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)
	appState.Close()

	// GetServerFile fails, should return nil and log.
	sf := s.ServerFileState("test.md")
	assert.Nil(t, sf)
}

func TestPersistPushedFile_SetLocalFileError(t *testing.T) {
	s, vault, appState, _ := fullSyncClient(t)
	// Write a real file so Stat succeeds.
	require.NoError(t, vault.WriteFile("pushed.md", []byte("content"), time.Time{}))
	appState.Close()

	// Stat succeeds, SetLocalFile fails. Should log, not panic.
	s.persistPushedFile("pushed.md", []byte("content"), "enchash", 1000, 500)
}

// --- Connected ---

func TestConnected_FalseByDefault(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	assert.False(t, s.Connected())
}

func TestSetConnected(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)

	s.setConnected(true)
	assert.True(t, s.Connected())

	s.setConnected(false)
	assert.False(t, s.Connected())
}
