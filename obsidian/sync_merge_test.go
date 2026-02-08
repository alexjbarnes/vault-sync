package obsidian

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- liveMergeMD ---

func TestLiveMergeMD_EchoSkip(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("echo.md", []byte("local"), time.Time{}))

	// SyncHash matches the server push hash when encrypted.
	plainHash := "some-content-hash"
	encHash := encryptPath(t, cipher, plainHash)

	local := &state.LocalFile{
		Path:     "echo.md",
		SyncHash: plainHash,
	}

	push := PushMessage{UID: 1, Hash: encHash}

	err := s.liveMergeMD(ctx, "echo.md", push, local, nil, nil)
	require.NoError(t, err)

	// File should not be changed.
	data, _ := vault.ReadFile("echo.md")
	assert.Equal(t, []byte("local"), data)
}

func TestLiveMergeMD_ServerDeletedReturnsNil(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("del.md", []byte("local"), time.Time{}))
	push := PushMessage{UID: 2}

	err := s.liveMergeMD(ctx, "del.md", push, nil, nil, fakePullDeleted())
	require.NoError(t, err)
}

func TestLiveMergeMD_ServerEqualsLocal(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	content := []byte("identical content")
	require.NoError(t, vault.WriteFile("same.md", content, time.Time{}))

	encContent := encryptContent(t, cipher, content)
	push := PushMessage{UID: 3}

	err := s.liveMergeMD(ctx, "same.md", push, nil, nil, fakePull(encContent))
	require.NoError(t, err)

	// File should remain unchanged.
	data, _ := vault.ReadFile("same.md")
	assert.Equal(t, content, data)
}

func TestLiveMergeMD_ServerEqualsBase(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	baseContent := []byte("base version")
	localContent := []byte("local edited version")
	require.NoError(t, vault.WriteFile("base-eq.md", localContent, time.Time{}))

	encBase := encryptContent(t, cipher, baseContent)
	encServer := encryptContent(t, cipher, baseContent) // server == base

	prev := &state.ServerFile{UID: 10}
	push := PushMessage{UID: 20}

	callCount := 0
	pull := func(ctx context.Context, uid int64) ([]byte, error) {
		callCount++
		if uid == 10 {
			return encBase, nil
		}
		return encServer, nil
	}

	err := s.liveMergeMD(ctx, "base-eq.md", push, nil, prev, pull)
	require.NoError(t, err)

	// base == server, so no change needed. Local content preserved.
	data, _ := vault.ReadFile("base-eq.md")
	assert.Equal(t, localContent, data)
}

func TestLiveMergeMD_NoBaseServerWinsByMtime(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	localContent := []byte("old local")
	serverContent := []byte("newer server")
	require.NoError(t, vault.WriteFile("mtime.md", localContent, time.Time{}))

	encServer := encryptContent(t, cipher, serverContent)
	push := PushMessage{UID: 5, MTime: time.Now().UnixMilli() + 10000} // Future mtime.

	local := &state.LocalFile{MTime: 1000}

	err := s.liveMergeMD(ctx, "mtime.md", push, local, nil, fakePull(encServer))
	require.NoError(t, err)

	// Server should win.
	data, _ := vault.ReadFile("mtime.md")
	assert.Equal(t, serverContent, data)
}

func TestLiveMergeMD_NoBaseLocalWinsByMtime(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	localContent := []byte("newer local")
	serverContent := []byte("old server")
	require.NoError(t, vault.WriteFile("local-wins.md", localContent, time.Time{}))

	encServer := encryptContent(t, cipher, serverContent)
	push := PushMessage{UID: 6, MTime: 1000} // Old mtime.

	local := &state.LocalFile{MTime: time.Now().UnixMilli() + 10000}

	err := s.liveMergeMD(ctx, "local-wins.md", push, local, nil, fakePull(encServer))
	require.NoError(t, err)

	// Local should win -- file unchanged.
	data, _ := vault.ReadFile("local-wins.md")
	assert.Equal(t, localContent, data)
}

func TestLiveMergeMD_ThreeWayMerge(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	// Base: "line1\nline2\nline3"
	// Local: "line1\nlocal-edit\nline3" (changed line2)
	// Server: "line1\nline2\nserver-edit" (changed line3)
	// Merged should have both changes.
	base := "line1\nline2\nline3"
	local := "line1\nlocal-edit\nline3"
	server := "line1\nline2\nserver-edit"

	require.NoError(t, vault.WriteFile("merge.md", []byte(local), time.Time{}))

	encBase := encryptContent(t, cipher, []byte(base))
	encServer := encryptContent(t, cipher, []byte(server))

	prev := &state.ServerFile{UID: 100}
	push := PushMessage{UID: 200}

	pull := func(ctx context.Context, uid int64) ([]byte, error) {
		if uid == 100 {
			return encBase, nil
		}
		return encServer, nil
	}

	err := s.liveMergeMD(ctx, "merge.md", push, nil, prev, pull)
	require.NoError(t, err)

	data, _ := vault.ReadFile("merge.md")
	merged := string(data)
	// Both edits should be present.
	assert.Contains(t, merged, "local-edit")
	assert.Contains(t, merged, "server-edit")
	assert.NotContains(t, merged, "line2\n")
	assert.NotContains(t, merged, "\nline3")
}

func TestLiveMergeMD_PullBaseError_FallsBackToDownload(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("fallback.md", []byte("local"), time.Time{}))

	serverContent := []byte("server wins on fallback")
	encServer := encryptContent(t, cipher, serverContent)

	prev := &state.ServerFile{UID: 50}
	push := PushMessage{UID: 60}

	callCount := 0
	pull := func(ctx context.Context, uid int64) ([]byte, error) {
		callCount++
		if uid == 50 {
			return nil, fmt.Errorf("base unavailable")
		}
		return encServer, nil
	}

	err := s.liveMergeMD(ctx, "fallback.md", push, nil, prev, pull)
	require.NoError(t, err)

	// Should fall back to liveDownload, writing server content.
	data, _ := vault.ReadFile("fallback.md")
	assert.Equal(t, serverContent, data)
}

func TestLiveMergeMD_ServerEmptyString(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	localContent := []byte("local has content")
	require.NoError(t, vault.WriteFile("empty-server.md", localContent, time.Time{}))

	// Server content is empty string.
	encServer := encryptContent(t, cipher, []byte{})
	push := PushMessage{UID: 7}

	err := s.liveMergeMD(ctx, "empty-server.md", push, nil, nil, fakePull(encServer))
	require.NoError(t, err)

	// Empty server -> persist server state, keep local.
	data, _ := vault.ReadFile("empty-server.md")
	assert.Equal(t, localContent, data)
}

// --- liveMergeJSON ---

func TestLiveMergeJSON_ShallowMerge(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	localJSON := `{"localKey":"localVal","shared":"local"}`
	require.NoError(t, vault.WriteFile(".obsidian/app.json", []byte(localJSON), time.Time{}))

	serverJSON := `{"serverKey":"serverVal","shared":"server"}`
	encServer := encryptContent(t, cipher, []byte(serverJSON))

	push := PushMessage{UID: 10}
	err := s.liveMergeJSON(ctx, ".obsidian/app.json", push, fakePull(encServer))
	require.NoError(t, err)

	data, _ := vault.ReadFile(".obsidian/app.json")
	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &result))

	// Local key preserved.
	assert.Contains(t, result, "localKey")
	// Server key added.
	assert.Contains(t, result, "serverKey")
	// Shared key: server wins (overwrites local).
	assert.JSONEq(t, `"server"`, string(result["shared"]))
}

func TestLiveMergeJSON_InvalidLocalJSON_FallsBackToDownload(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile(".obsidian/bad.json", []byte("not json"), time.Time{}))

	serverContent := []byte(`{"valid":"json"}`)
	encServer := encryptContent(t, cipher, serverContent)

	push := PushMessage{UID: 20}
	err := s.liveMergeJSON(ctx, ".obsidian/bad.json", push, fakePull(encServer))
	require.NoError(t, err)

	// Falls back to liveDownload, writing server content.
	data, _ := vault.ReadFile(".obsidian/bad.json")
	assert.Equal(t, serverContent, data)
}

func TestLiveMergeJSON_ServerDeleted(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile(".obsidian/del.json", []byte(`{}`), time.Time{}))

	push := PushMessage{UID: 30}
	err := s.liveMergeJSON(ctx, ".obsidian/del.json", push, fakePullDeleted())
	require.NoError(t, err)
}

func TestLiveMergeJSON_InvalidServerJSON_WritesRaw(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile(".obsidian/srv-bad.json", []byte(`{"local":"ok"}`), time.Time{}))

	serverContent := []byte("not valid json from server")
	encServer := encryptContent(t, cipher, serverContent)

	push := PushMessage{UID: 40}
	err := s.liveMergeJSON(ctx, ".obsidian/srv-bad.json", push, fakePull(encServer))
	require.NoError(t, err)

	// Falls back to liveWriteContent with server's raw plaintext.
	data, _ := vault.ReadFile(".obsidian/srv-bad.json")
	assert.Equal(t, serverContent, data)
}

// --- liveTypeConflict ---

func TestLiveTypeConflict_LocalFolder(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	// Local is a folder, server wants a file.
	require.NoError(t, vault.MkdirAll("conflict"))

	serverContent := []byte("server file content")
	encServer := encryptContent(t, cipher, serverContent)

	local := &state.LocalFile{Path: "conflict", Folder: true}
	push := PushMessage{UID: 50, MTime: 1000}

	err := s.liveTypeConflict(ctx, "conflict", push, local, fakePull(encServer))
	require.NoError(t, err)

	// Original path should now have server file content.
	data, _ := vault.ReadFile("conflict")
	assert.Equal(t, serverContent, data)

	// A conflict copy directory should exist.
	// conflictCopyPath for a folder with no extension appends a timestamp suffix.
}

func TestLiveTypeConflict_LocalFile(t *testing.T) {
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	localContent := []byte("local file content")
	require.NoError(t, vault.WriteFile("conflict.md", localContent, time.Time{}))

	serverContent := []byte("server folder content")
	encServer := encryptContent(t, cipher, serverContent)

	local := &state.LocalFile{Path: "conflict.md", Folder: false}
	push := PushMessage{UID: 60, Folder: true, MTime: 1000}

	err := s.liveTypeConflict(ctx, "conflict.md", push, local, fakePull(encServer))
	require.NoError(t, err)

	// Server content should be at the original path (folder download).
	// The local file should be renamed to a conflict copy.
	// Original path is now a directory from liveDownload.
	info, err := vault.Stat("conflict.md")
	require.NoError(t, err)
	assert.True(t, info.IsDir(), "should be a directory now")
}

func TestLiveTypeConflict_LocalFile_ServerDeleted(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)
	ctx := context.Background()

	localContent := []byte("local stays")
	require.NoError(t, vault.WriteFile("del-conflict.md", localContent, time.Time{}))

	local := &state.LocalFile{Path: "del-conflict.md", Folder: false}
	push := PushMessage{UID: 70, Deleted: true}

	err := s.liveTypeConflict(ctx, "del-conflict.md", push, local, nil)
	require.NoError(t, err)
}

// --- liveWriteContent ---

func TestLiveWriteContent_WritesAndPersists(t *testing.T) {
	s, vault, appState, _ := fullSyncClient(t)

	content := []byte("written content")
	push := PushMessage{UID: 100, Hash: "enc-hash", MTime: 5000}

	err := s.liveWriteContent("written.md", push, content)
	require.NoError(t, err)

	data, _ := vault.ReadFile("written.md")
	assert.Equal(t, content, data)

	// Hash cache populated.
	assert.Equal(t, sha256Hex(content), s.ContentHash("written.md"))

	// Server state persisted.
	sf, _ := appState.GetServerFile(testSyncVaultID, "written.md")
	require.NotNil(t, sf)
	assert.Equal(t, int64(100), sf.UID)

	// Local state persisted.
	lf, _ := appState.GetLocalFile(testSyncVaultID, "written.md")
	require.NotNil(t, lf)
	assert.Equal(t, sha256Hex(content), lf.Hash)
}

// --- persistPushedFile ---

func TestPersistPushedFile(t *testing.T) {
	s, vault, appState, _ := fullSyncClient(t)

	content := []byte("pushed content")
	require.NoError(t, vault.WriteFile("pushed.md", content, time.Time{}))

	s.persistPushedFile("pushed.md", content, "enc-hash-xyz", 1000, 900)

	lf, err := appState.GetLocalFile(testSyncVaultID, "pushed.md")
	require.NoError(t, err)
	require.NotNil(t, lf)
	assert.Equal(t, sha256Hex(content), lf.Hash)
	assert.Equal(t, sha256Hex(content), lf.SyncHash)
}

// --- persistPushedFolder ---

func TestPersistPushedFolder(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)

	s.persistPushedFolder("pushed-dir")

	lf, _ := appState.GetLocalFile(testSyncVaultID, "pushed-dir")
	require.NotNil(t, lf)
	assert.True(t, lf.Folder)

	sf, _ := appState.GetServerFile(testSyncVaultID, "pushed-dir")
	require.NotNil(t, sf)
	assert.True(t, sf.Folder)
}

// --- persistPushedDelete ---

func TestPersistPushedDelete(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)

	// Set up state to delete.
	require.NoError(t, appState.SetLocalFile(testSyncVaultID, state.LocalFile{Path: "del.md"}))
	require.NoError(t, appState.SetServerFile(testSyncVaultID, state.ServerFile{Path: "del.md"}))

	s.persistPushedDelete("del.md")

	lf, _ := appState.GetLocalFile(testSyncVaultID, "del.md")
	assert.Nil(t, lf)
	sf, _ := appState.GetServerFile(testSyncVaultID, "del.md")
	assert.Nil(t, sf)
}

// --- persistVersionIfDirty ---

func TestPersistVersionIfDirty_NotDirty(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)
	s.version = 42
	s.versionDirty = false

	s.persistVersionIfDirty()

	vs, _ := appState.GetVault(testSyncVaultID)
	assert.Equal(t, int64(0), vs.Version) // Not persisted.
}

func TestPersistVersionIfDirty_Dirty(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)
	s.version = 42
	s.initial = false
	s.versionDirty = true

	s.persistVersionIfDirty()

	vs, _ := appState.GetVault(testSyncVaultID)
	assert.Equal(t, int64(42), vs.Version)
	assert.False(t, vs.Initial)
	assert.False(t, s.versionDirty, "should be cleared after persist")
}

// --- isPermanentError ---

func TestIsPermanentError(t *testing.T) {
	assert.False(t, isPermanentError(nil))
	assert.True(t, isPermanentError(fmt.Errorf("auth failed")))
	assert.True(t, isPermanentError(fmt.Errorf("subscription expired")))
	assert.True(t, isPermanentError(fmt.Errorf("Vault not found")))
	assert.False(t, isPermanentError(fmt.Errorf("connection reset")))
	assert.False(t, isPermanentError(fmt.Errorf("timeout")))
}

// --- isOperationError ---

func TestIsOperationError(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	assert.True(t, s.isOperationError(fmt.Errorf("encrypting path: bad")))
	assert.True(t, s.isOperationError(fmt.Errorf("encrypting content: bad")))
	assert.True(t, s.isOperationError(fmt.Errorf("encrypting hash: bad")))
	assert.False(t, s.isOperationError(fmt.Errorf("connection reset")))
	assert.False(t, s.isOperationError(fmt.Errorf("timeout")))
}

// --- handlePushWhileBusy ---

func TestHandlePushWhileBusy_SkipDecision(t *testing.T) {
	s, _, appState, cipher := fullSyncClient(t)
	ctx := context.Background()

	// Push a file that doesn't exist locally -> DecisionDownload.
	// But first test DecisionSkip: push deleted, no local.
	encPath := encryptPath(t, cipher, "busy-skip.md")
	push := PushMessage{
		Op:      "push",
		UID:     500,
		Path:    encPath,
		Deleted: true,
	}
	data, _ := json.Marshal(push)
	s.handlePushWhileBusy(ctx, data)

	// Should persist server state as deleted (removed).
	sf, _ := appState.GetServerFile(testSyncVaultID, "busy-skip.md")
	assert.Nil(t, sf) // Deleted entries are removed.
}

func TestHandlePushWhileBusy_QueuesPendingPull(t *testing.T) {
	s, _, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	// Push a new file -> DecisionDownload -> needs pull -> queued.
	encPath := encryptPath(t, cipher, "busy-download.md")
	push := PushMessage{
		Op:   "push",
		UID:  600,
		Path: encPath,
		Hash: "some-hash",
		Size: 100,
	}
	data, _ := json.Marshal(push)
	s.handlePushWhileBusy(ctx, data)

	s.pendingPullsMu.Lock()
	assert.Len(t, s.pendingPulls, 1)
	assert.Equal(t, "busy-download.md", s.pendingPulls[0].path)
	s.pendingPullsMu.Unlock()
}

func TestHandlePushWhileBusy_UpdatesVersion(t *testing.T) {
	s, _, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	s.version = 100
	encPath := encryptPath(t, cipher, "ver.md")
	push := PushMessage{
		Op:      "push",
		UID:     200,
		Path:    encPath,
		Deleted: true,
	}
	data, _ := json.Marshal(push)
	s.handlePushWhileBusy(ctx, data)

	assert.Equal(t, int64(200), s.version)
	assert.True(t, s.versionDirty)
}

func TestHandlePushWhileBusy_BadJSON(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	ctx := context.Background()

	// Should not panic on bad JSON.
	s.handlePushWhileBusy(ctx, []byte(`{bad json`))
}
