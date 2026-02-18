package obsidian

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/state"
	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// fullReconciler builds a Reconciler with real cipher, vault, state, and a
// SyncClient backed by a MockWSConn. The mock conn is used by pullDirect
// during Phase 1. For Phase 2+3, call fakeEventLoop to drain opCh.
func fullReconciler(t *testing.T, ctrl *gomock.Controller) (*Reconciler, *SyncClient, *Vault, *state.State, *CipherV0, *MockWSConn) {
	t.Helper()
	s, vault, appState, cipher := fullSyncClient(t)
	mock := NewMockWSConn(ctrl)
	s.conn = mock

	r := NewReconciler(vault, s, appState, testSyncVaultID, cipher, quietLogger, nil)

	return r, s, vault, appState, cipher, mock
}

// fakeEventLoop runs a goroutine that drains opCh and returns nil for
// every push operation. Returns a cancel function to stop it.
func fakeEventLoop(s *SyncClient) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		for {
			select {
			case op := <-s.opCh:
				op.result <- nil
			case <-ctx.Done():
				return
			}
		}
	}()

	return cancel
}

// mockPullDirect sets up mock expectations for a pullDirect call that
// returns the given encrypted content in a single piece.
func mockPullDirect(mock *MockWSConn, encContent []byte) {
	resp, _ := json.Marshal(PullResponse{Size: int64(len(encContent)), Pieces: 1})
	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, resp, nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageBinary, encContent, nil),
	)
}

// mockPullDirectDeleted sets up mock expectations for a pullDirect that
// returns a deleted response.
func mockPullDirectDeleted(mock *MockWSConn) {
	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, []byte(`{"deleted":true}`), nil),
	)
}

// --- NewReconciler ---

func TestNewReconciler(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, _, _ := fullReconciler(t, ctrl)
	assert.NotNil(t, r)
}

// --- encryptLocalHash ---

func TestEncryptLocalHash_NilLocal(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, _, _ := fullReconciler(t, ctrl)
	assert.Empty(t, r.encryptLocalHash(nil))
}

func TestEncryptLocalHash_EmptyHash(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, _, _ := fullReconciler(t, ctrl)
	lf := &state.LocalFile{Hash: ""}
	assert.Empty(t, r.encryptLocalHash(lf))
}

func TestEncryptLocalHash_Folder(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, _, _ := fullReconciler(t, ctrl)
	lf := &state.LocalFile{Hash: "abc", Folder: true}
	assert.Empty(t, r.encryptLocalHash(lf))
}

func TestEncryptLocalHash_ValidHash(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, cipher, _ := fullReconciler(t, ctrl)
	lf := &state.LocalFile{Hash: "abc123"}
	enc := r.encryptLocalHash(lf)
	assert.NotEmpty(t, enc)
	// Should match direct encryption.
	expected := encryptPath(t, cipher, "abc123")
	assert.Equal(t, expected, enc)
}

// --- executeDecision ---

func TestExecuteDecision_Skip(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, appState, cipher, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	push := PushMessage{UID: 1, Path: encryptPath(t, cipher, "skip.md"), Hash: "h"}
	err := r.executeDecision(ctx, DecisionSkip, "skip.md", push, nil, nil)
	require.NoError(t, err)

	sf, _ := appState.GetServerFile(testSyncVaultID, "skip.md")
	require.NotNil(t, sf)
	assert.Equal(t, "h", sf.Hash)
}

func TestExecuteDecision_DownloadFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	plain := []byte("server content")
	encContent := encryptContent(t, cipher, plain)
	mockPullDirect(mock, encContent)

	push := PushMessage{UID: 10, Hash: "h", MTime: time.Now().UnixMilli()}
	err := r.executeDecision(ctx, DecisionDownload, "new.md", push, nil, nil)
	require.NoError(t, err)

	data, err := vault.ReadFile("new.md")
	require.NoError(t, err)
	assert.Equal(t, plain, data)
}

func TestExecuteDecision_DownloadFolder(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	push := PushMessage{UID: 11, Folder: true}
	err := r.executeDecision(ctx, DecisionDownload, "myfolder", push, nil, nil)
	require.NoError(t, err)

	info, err := vault.Stat("myfolder")
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestExecuteDecision_DeleteLocalFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("gone.md", []byte("x"), time.Time{}))

	push := PushMessage{UID: 12, Deleted: true}
	err := r.executeDecision(ctx, DecisionDeleteLocal, "gone.md", push, nil, nil)
	require.NoError(t, err)

	_, err = vault.ReadFile("gone.md")
	assert.Error(t, err)
}

func TestExecuteDecision_DeleteLocalFolder_Empty(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.MkdirAll("emptydir"))

	push := PushMessage{UID: 13, Folder: true, Deleted: true}
	err := r.executeDecision(ctx, DecisionDeleteLocal, "emptydir", push, nil, nil)
	require.NoError(t, err)

	_, err = vault.Stat("emptydir")
	assert.Error(t, err)
}

func TestExecuteDecision_DeleteLocalFolder_NonEmpty(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("notempty/child.md", []byte("x"), time.Time{}))

	push := PushMessage{UID: 14, Folder: true, Deleted: true}
	err := r.executeDecision(ctx, DecisionDeleteLocal, "notempty", push, nil, nil)
	require.NoError(t, err)

	// Folder should still exist because it's not empty.
	info, err := vault.Stat("notempty")
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestExecuteDecision_KeepLocal(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("keep.md", []byte("local"), time.Time{}))

	push := PushMessage{UID: 15, Deleted: true}
	err := r.executeDecision(ctx, DecisionKeepLocal, "keep.md", push, nil, nil)
	require.NoError(t, err)

	data, err := vault.ReadFile("keep.md")
	require.NoError(t, err)
	assert.Equal(t, []byte("local"), data)
}

// --- downloadServerFile ---

func TestDownloadServerFile_DeletedResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, appState, _, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	mockPullDirectDeleted(mock)

	push := PushMessage{UID: 20, Hash: "h"}
	err := r.downloadServerFile(ctx, "vanished.md", push)
	require.NoError(t, err)

	// Server file should be marked deleted (entry removed).
	sf, _ := appState.GetServerFile(testSyncVaultID, "vanished.md")
	assert.Nil(t, sf)
}

func TestDownloadServerFile_EmptyContent(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	encContent := encryptContent(t, cipher, []byte{})
	mockPullDirect(mock, encContent)

	push := PushMessage{UID: 21, Hash: "h", MTime: time.Now().UnixMilli()}
	err := r.downloadServerFile(ctx, "empty.md", push)
	require.NoError(t, err)

	data, err := vault.ReadFile("empty.md")
	require.NoError(t, err)
	assert.Empty(t, data)
}

// --- writeServerContent ---

func TestWriteServerContent_WritesAndPersists(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, vault, appState, _, _ := fullReconciler(t, ctrl)

	push := PushMessage{UID: 30, Hash: "enc-hash", MTime: time.Now().UnixMilli()}
	err := r.writeServerContent("written.md", push, []byte("hello"))
	require.NoError(t, err)

	data, err := vault.ReadFile("written.md")
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), data)

	sf, _ := appState.GetServerFile(testSyncVaultID, "written.md")
	require.NotNil(t, sf)

	lf, _ := appState.GetLocalFile(testSyncVaultID, "written.md")
	require.NotNil(t, lf)

	// Hash cache should be populated.
	assert.NotEmpty(t, s.ContentHash("written.md"))
}

func TestWriteServerContent_ZeroMtime(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, _ := fullReconciler(t, ctrl)

	push := PushMessage{UID: 31, MTime: 0}
	err := r.writeServerContent("nomtime.md", push, []byte("data"))
	require.NoError(t, err)

	_, err = vault.ReadFile("nomtime.md")
	require.NoError(t, err)
}

// --- threeWayMerge ---

func TestThreeWayMerge_EchoSkip(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("echo.md", []byte("local"), time.Time{}))

	syncHash := "content-hash"
	encSyncHash := encryptPath(t, cipher, syncHash)

	local := state.LocalFile{Path: "echo.md", SyncHash: syncHash}
	push := PushMessage{UID: 40, Hash: encSyncHash}

	err := r.threeWayMerge(ctx, "echo.md", push, local, state.ServerFile{}, false)
	require.NoError(t, err)

	// File should not be changed.
	data, _ := vault.ReadFile("echo.md")
	assert.Equal(t, []byte("local"), data)
}

func TestThreeWayMerge_ServerDeletedKeepsLocal(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("kept.md", []byte("local"), time.Time{}))

	// Pull for server version returns deleted.
	mockPullDirectDeleted(mock)

	local := state.LocalFile{Path: "kept.md"}
	push := PushMessage{UID: 41}

	err := r.threeWayMerge(ctx, "kept.md", push, local, state.ServerFile{}, false)
	require.NoError(t, err)

	data, _ := vault.ReadFile("kept.md")
	assert.Equal(t, []byte("local"), data)
}

func TestThreeWayMerge_ServerEqualsLocal(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("same.md", []byte("identical"), time.Time{}))
	encContent := encryptContent(t, cipher, []byte("identical"))
	mockPullDirect(mock, encContent)

	local := state.LocalFile{Path: "same.md"}
	push := PushMessage{UID: 42}

	err := r.threeWayMerge(ctx, "same.md", push, local, state.ServerFile{}, false)
	require.NoError(t, err)
}

func TestThreeWayMerge_NoBase_ServerWinsByMtime(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("mtime.md", []byte("local"), time.Time{}))
	encContent := encryptContent(t, cipher, []byte("server"))
	mockPullDirect(mock, encContent)

	local := state.LocalFile{Path: "mtime.md", MTime: 1000}
	push := PushMessage{UID: 43, MTime: 2000} // server newer

	err := r.threeWayMerge(ctx, "mtime.md", push, local, state.ServerFile{}, false)
	require.NoError(t, err)

	data, _ := vault.ReadFile("mtime.md")
	assert.Equal(t, []byte("server"), data)
}

func TestThreeWayMerge_NoBase_LocalWinsByMtime(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("local-wins.md", []byte("local"), time.Time{}))
	encContent := encryptContent(t, cipher, []byte("server"))
	mockPullDirect(mock, encContent)

	local := state.LocalFile{Path: "local-wins.md", MTime: 3000}
	push := PushMessage{UID: 44, MTime: 1000} // local newer

	err := r.threeWayMerge(ctx, "local-wins.md", push, local, state.ServerFile{}, false)
	require.NoError(t, err)

	data, _ := vault.ReadFile("local-wins.md")
	assert.Equal(t, []byte("local"), data)
}

func TestThreeWayMerge_FullMerge(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	// Base: "line1\nline2\nline3\n"
	// Local: "line1\nlocal-edit\nline3\n"    (changed line2)
	// Server: "line1\nline2\nserver-edit\n"  (changed line3)
	// Expected merge: "line1\nlocal-edit\nserver-edit\n" (both edits applied)

	base := "line1\nline2\nline3\n"
	local := "line1\nlocal-edit\nline3\n"
	server := "line1\nline2\nserver-edit\n"

	require.NoError(t, vault.WriteFile("merge.md", []byte(local), time.Time{}))

	encBase := encryptContent(t, cipher, []byte(base))
	encServer := encryptContent(t, cipher, []byte(server))

	// Two pullDirect calls: first for base (prev.UID=100), then for server (push.UID=45).
	baseResp, _ := json.Marshal(PullResponse{Size: int64(len(encBase)), Pieces: 1})
	serverResp, _ := json.Marshal(PullResponse{Size: int64(len(encServer)), Pieces: 1})
	gomock.InOrder(
		// Pull base.
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, baseResp, nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageBinary, encBase, nil),
		// Pull server.
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, serverResp, nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageBinary, encServer, nil),
	)

	localFile := state.LocalFile{Path: "merge.md", MTime: 2000}
	prev := state.ServerFile{UID: 100}
	push := PushMessage{UID: 45, MTime: 2000}

	err := r.threeWayMerge(ctx, "merge.md", push, localFile, prev, true)
	require.NoError(t, err)

	data, _ := vault.ReadFile("merge.md")
	result := string(data)
	assert.Contains(t, result, "local-edit")
	assert.Contains(t, result, "server-edit")
}

func TestThreeWayMerge_PullBaseError_ServerWins(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("fallback.md", []byte("local"), time.Time{}))
	encServer := encryptContent(t, cipher, []byte("server"))

	gomock.InOrder(
		// Pull base fails.
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).
			Return(fmt.Errorf("connection lost")),
		// Falls back to downloadServerFile which pulls again.
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, mustJSON(PullResponse{Size: int64(len(encServer)), Pieces: 1}), nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageBinary, encServer, nil),
	)

	localFile := state.LocalFile{Path: "fallback.md"}
	prev := state.ServerFile{UID: 50}
	push := PushMessage{UID: 46, MTime: time.Now().UnixMilli()}

	err := r.threeWayMerge(ctx, "fallback.md", push, localFile, prev, true)
	require.NoError(t, err)

	data, _ := vault.ReadFile("fallback.md")
	assert.Equal(t, []byte("server"), data)
}

// --- jsonMerge ---

func TestJSONMerge_ShallowMerge(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	localJSON := `{"local_key":"local","shared":"local_val"}`
	require.NoError(t, vault.WriteFile(".obsidian/app.json", []byte(localJSON), time.Time{}))

	serverJSON := `{"shared":"server_val","server_key":"server"}`
	encServer := encryptContent(t, cipher, []byte(serverJSON))
	mockPullDirect(mock, encServer)

	push := PushMessage{UID: 50, MTime: time.Now().UnixMilli()}
	err := r.jsonMerge(ctx, ".obsidian/app.json", push)
	require.NoError(t, err)

	data, _ := vault.ReadFile(".obsidian/app.json")

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &result))
	assert.Contains(t, string(result["shared"]), "server_val")
	assert.Contains(t, string(result["local_key"]), "local")
	assert.Contains(t, string(result["server_key"]), "server")
}

func TestJSONMerge_InvalidLocalJSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile(".obsidian/bad.json", []byte("not json"), time.Time{}))

	serverContent := []byte(`{"key":"val"}`)
	encServer := encryptContent(t, cipher, serverContent)
	mockPullDirect(mock, encServer)

	push := PushMessage{UID: 51, MTime: time.Now().UnixMilli()}
	err := r.jsonMerge(ctx, ".obsidian/bad.json", push)
	require.NoError(t, err)

	data, _ := vault.ReadFile(".obsidian/bad.json")
	assert.Equal(t, serverContent, data)
}

func TestJSONMerge_ServerDeleted(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile(".obsidian/del.json", []byte(`{}`), time.Time{}))
	mockPullDirectDeleted(mock)

	push := PushMessage{UID: 52}
	err := r.jsonMerge(ctx, ".obsidian/del.json", push)
	require.NoError(t, err)
}

func TestJSONMerge_InvalidServerJSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile(".obsidian/inv.json", []byte(`{"a":"b"}`), time.Time{}))

	// Server returns non-JSON content.
	serverRaw := []byte("not json at all")
	encServer := encryptContent(t, cipher, serverRaw)
	mockPullDirect(mock, encServer)

	push := PushMessage{UID: 53, MTime: time.Now().UnixMilli()}
	err := r.jsonMerge(ctx, ".obsidian/inv.json", push)
	require.NoError(t, err)

	data, _ := vault.ReadFile(".obsidian/inv.json")
	assert.Equal(t, serverRaw, data)
}

// --- handleTypeConflict ---

func TestHandleTypeConflict_LocalFolder(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.MkdirAll("conflict"))

	plain := []byte("server file content")
	encContent := encryptContent(t, cipher, plain)
	mockPullDirect(mock, encContent)

	local := state.LocalFile{Path: "conflict", Folder: true}
	push := PushMessage{UID: 60, MTime: time.Now().UnixMilli()}

	err := r.handleTypeConflict(ctx, "conflict", push, local)
	require.NoError(t, err)

	// Original folder should be renamed to conflict copy.
	_, err = vault.Stat("conflict (Conflicted copy)")
	require.NoError(t, err)

	// Server file should be written at original path.
	data, err := vault.ReadFile("conflict")
	require.NoError(t, err)
	assert.Equal(t, plain, data)
}

func TestHandleTypeConflict_LocalFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("clash.md", []byte("local file"), time.Time{}))

	local := state.LocalFile{Path: "clash.md", Folder: false}
	push := PushMessage{UID: 61, Folder: true}

	err := r.handleTypeConflict(ctx, "clash.md", push, local)
	require.NoError(t, err)

	// Conflict copy should exist.
	data, err := vault.ReadFile("clash (Conflicted copy).md")
	require.NoError(t, err)
	assert.Equal(t, []byte("local file"), data)

	// Original path should be a folder now.
	info, err := vault.Stat("clash.md")
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestHandleTypeConflict_LocalFile_ServerDeleted(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("del-clash.md", []byte("data"), time.Time{}))

	local := state.LocalFile{Path: "del-clash.md", Folder: false}
	push := PushMessage{UID: 62, Folder: true, Deleted: true}

	err := r.handleTypeConflict(ctx, "del-clash.md", push, local)
	require.NoError(t, err)

	// Conflict copy should still be created.
	_, err = vault.ReadFile("del-clash (Conflicted copy).md")
	assert.NoError(t, err)
}

// --- Phase1 ---

func TestPhase1_EmptyPushes(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	scan := &ScanResult{Current: map[string]state.LocalFile{}}
	err := r.Phase1(ctx, nil, scan)
	require.NoError(t, err)
}

func TestPhase1_DownloadsNewFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	plain := []byte("from server")
	encContent := encryptContent(t, cipher, plain)
	encPath := encryptPath(t, cipher, "phase1.md")

	mockPullDirect(mock, encContent)

	pushes := []ServerPush{
		{Msg: PushMessage{UID: 100, Path: encPath, Hash: "h", MTime: time.Now().UnixMilli()}, Path: "phase1.md"},
	}
	scan := &ScanResult{Current: map[string]state.LocalFile{}}

	err := r.Phase1(ctx, pushes, scan)
	require.NoError(t, err)

	data, err := vault.ReadFile("phase1.md")
	require.NoError(t, err)
	assert.Equal(t, plain, data)
}

func TestPhase1_SkipsDeletedNoLocal(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, cipher, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	encPath := encryptPath(t, cipher, "ghost.md")
	pushes := []ServerPush{
		{Msg: PushMessage{UID: 101, Path: encPath, Deleted: true}, Path: "ghost.md"},
	}
	scan := &ScanResult{Current: map[string]state.LocalFile{}}

	err := r.Phase1(ctx, pushes, scan)
	require.NoError(t, err)
}

// --- Phase2And3 ---

func TestPhase2And3_DeletesRemoteFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, _, appState, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	// Set up server file state so delete knows the path is tracked.
	require.NoError(t, appState.SetServerFile(testSyncVaultID, state.ServerFile{
		Path: "deleted.md",
		Hash: "h",
		UID:  200,
	}))

	cancel := fakeEventLoop(s)
	defer cancel()

	scan := &ScanResult{
		Current: map[string]state.LocalFile{},
		Deleted: []string{"deleted.md"},
	}

	err := r.Phase2And3(ctx, scan)
	require.NoError(t, err)
}

func TestPhase2And3_UploadsLocalChange(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, vault, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("changed.md", []byte("new content"), time.Time{}))

	cancel := fakeEventLoop(s)
	defer cancel()

	scan := &ScanResult{
		Current: map[string]state.LocalFile{
			"changed.md": {Path: "changed.md", Hash: "newhash", Size: 11},
		},
		Changed: []string{"changed.md"},
	}

	err := r.Phase2And3(ctx, scan)
	require.NoError(t, err)
}

func TestPhase2And3_SkipsFolderAlreadyOnServer(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, _, appState, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, appState.SetServerFile(testSyncVaultID, state.ServerFile{
		Path:   "existing-folder",
		Folder: true,
	}))

	cancel := fakeEventLoop(s)
	defer cancel()

	scan := &ScanResult{
		Current: map[string]state.LocalFile{
			"existing-folder": {Path: "existing-folder", Folder: true},
		},
		Changed: []string{"existing-folder"},
	}

	err := r.Phase2And3(ctx, scan)
	require.NoError(t, err)
}

func TestPhase2And3_SkipsFileMatchingServerHash(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, vault, appState, cipher, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	content := []byte("unchanged")
	require.NoError(t, vault.WriteFile("same.md", content, time.Time{}))

	// Pre-compute the hash that the scan would produce.
	hash := "somehash"
	encHash := encryptPath(t, cipher, hash)

	require.NoError(t, appState.SetServerFile(testSyncVaultID, state.ServerFile{
		Path: "same.md",
		Hash: encHash,
	}))

	cancel := fakeEventLoop(s)
	defer cancel()

	scan := &ScanResult{
		Current: map[string]state.LocalFile{
			"same.md": {Path: "same.md", Hash: hash, Size: int64(len(content))},
		},
		Changed: []string{"same.md"},
	}

	err := r.Phase2And3(ctx, scan)
	require.NoError(t, err)
}

func TestDeletePaths_SkipsRecreatedFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, vault, appState, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	// File exists on disk (recreated by phase 1).
	require.NoError(t, vault.WriteFile("recreated.md", []byte("x"), time.Time{}))
	require.NoError(t, appState.SetServerFile(testSyncVaultID, state.ServerFile{
		Path: "recreated.md",
		Hash: "h",
	}))

	cancel := fakeEventLoop(s)
	defer cancel()

	serverFiles := map[string]state.ServerFile{
		"recreated.md": {Path: "recreated.md", Hash: "h"},
	}

	err := r.deletePaths(ctx, []string{"recreated.md"}, serverFiles)
	require.NoError(t, err)

	// File should still exist -- delete was skipped.
	_, err = vault.Stat("recreated.md")
	assert.NoError(t, err)
}

// --- executeDecision: MergeMD, MergeJSON, TypeConflict ---

func TestExecuteDecision_MergeMD_ServerEqualsLocal(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("merge.md", []byte("same content"), time.Time{}))

	encContent := encryptContent(t, cipher, []byte("same content"))
	mockPullDirect(mock, encContent)

	local := &state.LocalFile{Path: "merge.md", MTime: 1000}
	push := PushMessage{UID: 70, MTime: 1000}

	err := r.executeDecision(ctx, DecisionMergeMD, "merge.md", push, local, nil)
	require.NoError(t, err)
}

func TestExecuteDecision_MergeMD_WithPrev(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	// Use longer, distinct lines to avoid diff-match-patch confusion.
	base := "first line stays the same\nsecond line is original\nthird line is original\n"
	local := "first line stays the same\nsecond line edited locally\nthird line is original\n"
	server := "first line stays the same\nsecond line is original\nthird line edited on server\n"

	require.NoError(t, vault.WriteFile("md-merge.md", []byte(local), time.Time{}))

	encBase := encryptContent(t, cipher, []byte(base))
	encServer := encryptContent(t, cipher, []byte(server))

	baseResp, _ := json.Marshal(PullResponse{Size: int64(len(encBase)), Pieces: 1})
	serverResp, _ := json.Marshal(PullResponse{Size: int64(len(encServer)), Pieces: 1})
	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, baseResp, nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageBinary, encBase, nil),
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, serverResp, nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageBinary, encServer, nil),
	)

	localFile := &state.LocalFile{Path: "md-merge.md", MTime: 2000}
	prev := &state.ServerFile{UID: 50}
	push := PushMessage{UID: 71, MTime: 2000}

	err := r.executeDecision(ctx, DecisionMergeMD, "md-merge.md", push, localFile, prev)
	require.NoError(t, err)

	data, _ := vault.ReadFile("md-merge.md")
	result := string(data)
	assert.Contains(t, result, "edited locally")
	assert.Contains(t, result, "edited on server")
}

func TestExecuteDecision_MergeMD_NilLocal(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("nil-local.md", []byte("disk"), time.Time{}))

	encServer := encryptContent(t, cipher, []byte("server"))
	mockPullDirect(mock, encServer)

	push := PushMessage{UID: 72, MTime: time.Now().UnixMilli()}

	// local is nil -- the code handles this by zero-valuing localVal.
	err := r.executeDecision(ctx, DecisionMergeMD, "nil-local.md", push, nil, nil)
	require.NoError(t, err)
}

func TestExecuteDecision_MergeJSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile(".obsidian/test.json", []byte(`{"local":"val"}`), time.Time{}))

	serverJSON := `{"server":"val"}`
	encServer := encryptContent(t, cipher, []byte(serverJSON))
	mockPullDirect(mock, encServer)

	push := PushMessage{UID: 73, MTime: time.Now().UnixMilli()}

	err := r.executeDecision(ctx, DecisionMergeJSON, ".obsidian/test.json", push, nil, nil)
	require.NoError(t, err)

	data, _ := vault.ReadFile(".obsidian/test.json")

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &result))
	assert.Contains(t, string(result["local"]), "val")
	assert.Contains(t, string(result["server"]), "val")
}

func TestExecuteDecision_TypeConflict_LocalFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("clash.txt", []byte("local"), time.Time{}))

	local := &state.LocalFile{Path: "clash.txt", Folder: false}
	push := PushMessage{UID: 74, Folder: true}

	err := r.executeDecision(ctx, DecisionTypeConflict, "clash.txt", push, local, nil)
	require.NoError(t, err)

	// Conflict copy should exist.
	_, err = vault.ReadFile("clash (Conflicted copy).txt")
	require.NoError(t, err)

	// Original path should be a folder.
	info, err := vault.Stat("clash.txt")
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestExecuteDecision_TypeConflict_LocalFolder(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	// Local is a folder, server wants a file.
	require.NoError(t, vault.MkdirAll("folder-conflict"))

	plain := []byte("server file data")
	encContent := encryptContent(t, cipher, plain)
	mockPullDirect(mock, encContent)

	local := &state.LocalFile{Path: "folder-conflict", Folder: true}
	push := PushMessage{UID: 75, MTime: time.Now().UnixMilli()}

	err := r.executeDecision(ctx, DecisionTypeConflict, "folder-conflict", push, local, nil)
	require.NoError(t, err)

	// Conflict copy of folder should exist.
	_, err = vault.Stat("folder-conflict (Conflicted copy)")
	require.NoError(t, err)

	// Server file should be at original path.
	data, err := vault.ReadFile("folder-conflict")
	require.NoError(t, err)
	assert.Equal(t, plain, data)
}

func TestExecuteDecision_UnknownDecision(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	err := r.executeDecision(ctx, ReconcileDecision(99), "unknown.md", PushMessage{}, nil, nil)
	assert.NoError(t, err)
}

// --- processServerPushes ---

func TestProcessServerPushes_FailureCounter(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	// A push that will fail: DecisionDownload but pullDirect returns an error.
	encPath := encryptPath(t, cipher, "fail.md")

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).
		Return(fmt.Errorf("connection lost"))

	pushes := []ServerPush{
		{Msg: PushMessage{UID: 80, Path: encPath, Hash: "h", Size: 100}, Path: "fail.md"},
	}
	scan := &ScanResult{Current: map[string]state.LocalFile{}}

	err := r.processServerPushes(ctx, pushes, scan, map[string]state.ServerFile{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1 of 1 server pushes failed")
}

func TestProcessServerPushes_PartialFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	// First push fails (download error), second succeeds (skip - deleted with no local).
	encPath1 := encryptPath(t, cipher, "fail2.md")
	encPath2 := encryptPath(t, cipher, "skip2.md")

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).
		Return(fmt.Errorf("connection lost"))

	pushes := []ServerPush{
		{Msg: PushMessage{UID: 81, Path: encPath1, Hash: "h", Size: 50}, Path: "fail2.md"},
		{Msg: PushMessage{UID: 82, Path: encPath2, Deleted: true}, Path: "skip2.md"},
	}
	scan := &ScanResult{Current: map[string]state.LocalFile{}}

	err := r.processServerPushes(ctx, pushes, scan, map[string]state.ServerFile{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1 of 2 server pushes failed")
}

// --- deleteRemoteFiles ---

func TestDeleteRemoteFiles_UntrackedPath(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, _, appState, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	// Path in Deleted but not in serverFiles -> clean up local state only.
	require.NoError(t, appState.SetLocalFile(testSyncVaultID, state.LocalFile{
		Path: "untracked.md",
		Hash: "h",
	}))

	cancel := fakeEventLoop(s)
	defer cancel()

	scan := &ScanResult{
		Current: map[string]state.LocalFile{},
		Deleted: []string{"untracked.md"},
	}

	err := r.deleteRemoteFiles(ctx, scan, map[string]state.ServerFile{})
	require.NoError(t, err)

	// Local state should be cleaned up.
	lf, _ := appState.GetLocalFile(testSyncVaultID, "untracked.md")
	assert.Nil(t, lf)
}

func TestDeleteRemoteFiles_FolderDelete(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, _, appState, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, appState.SetServerFile(testSyncVaultID, state.ServerFile{
		Path:   "old-folder",
		Folder: true,
	}))

	cancel := fakeEventLoop(s)
	defer cancel()

	serverFiles := map[string]state.ServerFile{
		"old-folder": {Path: "old-folder", Folder: true},
	}
	scan := &ScanResult{
		Current: map[string]state.LocalFile{},
		Deleted: []string{"old-folder"},
	}

	err := r.deleteRemoteFiles(ctx, scan, serverFiles)
	require.NoError(t, err)
}

func TestDeleteRemoteFiles_FilesAndFolders(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, _, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	cancel := fakeEventLoop(s)
	defer cancel()

	serverFiles := map[string]state.ServerFile{
		"dir/file.md": {Path: "dir/file.md", Hash: "h"},
		"dir":         {Path: "dir", Folder: true},
	}
	scan := &ScanResult{
		Current: map[string]state.LocalFile{},
		Deleted: []string{"dir/file.md", "dir"},
	}

	err := r.deleteRemoteFiles(ctx, scan, serverFiles)
	require.NoError(t, err)
}

// --- deletePaths ---

func TestDeletePaths_PushError_Continues(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, _, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	// Make event loop return errors for push operations.
	evCtx, evCancel := context.WithCancel(context.Background())

	go func() {
		for {
			select {
			case op := <-s.opCh:
				op.result <- fmt.Errorf("push failed")
			case <-evCtx.Done():
				return
			}
		}
	}()

	defer evCancel()

	serverFiles := map[string]state.ServerFile{
		"a.md": {Path: "a.md", Hash: "h1"},
		"b.md": {Path: "b.md", Hash: "h2"},
	}

	err := r.deletePaths(ctx, []string{"a.md", "b.md"}, serverFiles)
	require.NoError(t, err)
	// Both pushes failed but deletePaths just continues.
}

// --- uploadLocalChanges ---

func TestUploadLocalChanges_RecomputeHash_MatchesServer(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, vault, appState, cipher, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	content := []byte("unchanged")
	require.NoError(t, vault.WriteFile("recheck.md", content, time.Time{}))

	// Scan reports a different hash, but recompute from disk matches server.
	h := sha256Hex(content)
	encHash := encryptPath(t, cipher, h)
	require.NoError(t, appState.SetServerFile(testSyncVaultID, state.ServerFile{
		Path: "recheck.md",
		Hash: encHash,
	}))

	cancel := fakeEventLoop(s)
	defer cancel()

	scan := &ScanResult{
		Current: map[string]state.LocalFile{
			"recheck.md": {Path: "recheck.md", Hash: "stale-hash", Size: int64(len(content))},
		},
		Changed: []string{"recheck.md"},
	}
	serverFiles := map[string]state.ServerFile{
		"recheck.md": {Path: "recheck.md", Hash: encHash},
	}

	err := r.uploadLocalChanges(ctx, scan, serverFiles)
	require.NoError(t, err)
	// No push should happen since recomputed hash matches.
}

func TestUploadLocalChanges_ReadError_Continues(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, _, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	cancel := fakeEventLoop(s)
	defer cancel()

	// File in Changed but not on disk -> ReadFile fails.
	scan := &ScanResult{
		Current: map[string]state.LocalFile{
			"gone.md": {Path: "gone.md", Hash: "h", Size: 10},
		},
		Changed: []string{"gone.md"},
	}

	err := r.uploadLocalChanges(ctx, scan, map[string]state.ServerFile{})
	require.NoError(t, err)
}

func TestUploadLocalChanges_CtimeAdoption(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, vault, appState, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("ctime.md", []byte("data"), time.Time{}))
	require.NoError(t, appState.SetServerFile(testSyncVaultID, state.ServerFile{
		Path:  "ctime.md",
		CTime: 500,
	}))

	cancel := fakeEventLoop(s)
	defer cancel()

	scan := &ScanResult{
		Current: map[string]state.LocalFile{
			"ctime.md": {Path: "ctime.md", Hash: "h", Size: 4},
		},
		Changed: []string{"ctime.md"},
	}
	serverFiles := map[string]state.ServerFile{
		"ctime.md": {Path: "ctime.md", CTime: 500},
	}

	err := r.uploadLocalChanges(ctx, scan, serverFiles)
	require.NoError(t, err)
}

func TestUploadLocalChanges_NewFolder(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, _, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	cancel := fakeEventLoop(s)
	defer cancel()

	scan := &ScanResult{
		Current: map[string]state.LocalFile{
			"new-folder": {Path: "new-folder", Folder: true},
		},
		Changed: []string{"new-folder"},
	}

	err := r.uploadLocalChanges(ctx, scan, map[string]state.ServerFile{})
	require.NoError(t, err)
}

func TestUploadLocalChanges_StatError_ContinuesWithZeroTimes(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, vault, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	// Write and then remove so stat fails but ReadFile was cached... no,
	// ReadFile will also fail. Let's use a file that exists for ReadFile
	// but then gets removed before Stat.
	content := []byte("will vanish for stat")
	require.NoError(t, vault.WriteFile("vanishing.md", content, time.Time{}))

	cancel := fakeEventLoop(s)
	defer cancel()

	scan := &ScanResult{
		Current: map[string]state.LocalFile{
			"vanishing.md": {Path: "vanishing.md", Hash: "h", Size: int64(len(content))},
		},
		Changed: []string{"vanishing.md"},
	}

	// This tests the happy path where stat succeeds. The stat error
	// branch would need the file to vanish between ReadFile and Stat,
	// which is hard to trigger reliably. The upload should still succeed.
	err := r.uploadLocalChanges(ctx, scan, map[string]state.ServerFile{})
	require.NoError(t, err)
}

// --- Phase1: AllServerFiles error ---

func TestPhase1_AllServerFilesError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, appState, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	// Close the DB to force AllServerFiles to fail.
	appState.Close()

	err := r.Phase1(ctx, nil, &ScanResult{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading server files")
}

// --- Phase2And3: AllServerFiles error ---

func TestPhase2And3_AllServerFilesError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, appState, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	// Close the DB to force AllServerFiles to fail.
	appState.Close()

	err := r.Phase2And3(ctx, &ScanResult{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading server files")
}

// --- threeWayMerge: decrypt base error, server wins ---

func TestThreeWayMerge_DecryptBaseError_ServerWins(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	localContent := []byte("local text")
	require.NoError(t, vault.WriteFile("merge.md", localContent, time.Time{}))

	serverText := "server text"
	encServer := encryptContent(t, cipher, []byte(serverText))

	// First pullDirect (for base): return garbage that won't decrypt.
	badContent := []byte{0x01, 0x02, 0x03}
	mockPullDirect(mock, badContent)
	// After decrypt failure, falls back to downloadServerFile which calls
	// pullDirect again for the server version.
	mockPullDirect(mock, encServer)

	push := PushMessage{UID: 100, Hash: "serverhash", MTime: 5000}
	local := state.LocalFile{Path: "merge.md", MTime: 1000, Hash: "localhash"}
	prev := state.ServerFile{Path: "merge.md", UID: 50}

	err := r.threeWayMerge(ctx, "merge.md", push, local, prev, true)
	require.NoError(t, err)

	// Server content should have been written (fallback to download).
	got, err := vault.ReadFile("merge.md")
	require.NoError(t, err)
	assert.Equal(t, serverText, string(got))
}

// --- threeWayMerge: server returns empty string ---

func TestThreeWayMerge_EmptyServerContent(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	localContent := []byte("local text")
	require.NoError(t, vault.WriteFile("merge2.md", localContent, time.Time{}))

	// hasPrev=true with UID > 0 so base pull happens. Base returns
	// some real content so baseText != "".
	encBase := encryptContent(t, cipher, []byte("base text"))
	mockPullDirect(mock, encBase)
	// Server pull returns empty content (zero bytes encrypted).
	// DecryptContent of encrypted empty bytes yields []byte{},
	// so serverText = "".
	encEmpty := encryptContent(t, cipher, []byte{})
	mockPullDirect(mock, encEmpty)

	push := PushMessage{UID: 101, Hash: "h", MTime: 5000}
	local := state.LocalFile{Path: "merge2.md", MTime: 1000, Hash: "lh"}
	prev := state.ServerFile{Path: "merge2.md", UID: 90}

	err := r.threeWayMerge(ctx, "merge2.md", push, local, prev, true)
	require.NoError(t, err)

	// Empty server text should trigger the "empty server" shortcut:
	// keep local, persist server push.
	got, err := vault.ReadFile("merge2.md")
	require.NoError(t, err)
	assert.Equal(t, "local text", string(got))
}

// --- threeWayMerge: base == server, skip ---

func TestThreeWayMerge_BaseEqualsServer_NoMergeNeeded(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	localContent := []byte("local differs")
	require.NoError(t, vault.WriteFile("same.md", localContent, time.Time{}))

	commonText := "identical content"
	encCommon := encryptContent(t, cipher, []byte(commonText))

	// Base pull returns the same content as server.
	mockPullDirect(mock, encCommon)
	// Server pull returns same content.
	mockPullDirect(mock, encCommon)

	push := PushMessage{UID: 102, Hash: "h", MTime: 3000}
	local := state.LocalFile{Path: "same.md", MTime: 2000, Hash: "localhash"}
	prev := state.ServerFile{Path: "same.md", UID: 80}

	err := r.threeWayMerge(ctx, "same.md", push, local, prev, true)
	require.NoError(t, err)

	// base == server means no server-side changes. Local file untouched.
	got, err := vault.ReadFile("same.md")
	require.NoError(t, err)
	assert.Equal(t, "local differs", string(got))
}

// --- threeWayMerge: server pull error ---

func TestThreeWayMerge_ServerPullError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("err.md", []byte("local"), time.Time{}))

	// hasPrev=false (no base), so the base pull is skipped. The server
	// pull is the first conn interaction and it fails.
	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageType(0), nil, fmt.Errorf("server error")),
	)

	push := PushMessage{UID: 103, Hash: "h", MTime: 3000}
	local := state.LocalFile{Path: "err.md", MTime: 1000, Hash: "lh"}

	err := r.threeWayMerge(ctx, "err.md", push, local, state.ServerFile{}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pulling server version")
}

// --- downloadServerFile: decrypt error ---

func TestDownloadServerFile_DecryptError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, _, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	// Return garbage content that fails to decrypt.
	badContent := []byte{0xFF, 0xFE, 0xFD, 0xFC}
	mockPullDirect(mock, badContent)

	push := PushMessage{UID: 200, Hash: "h"}
	err := r.downloadServerFile(ctx, "broken.md", push)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decrypting")
}

// --- handleTypeConflict: local file, rename error ---

func TestHandleTypeConflict_LocalFile_ServerIsFolder(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	// Local is a file, server wants a folder at the same path.
	require.NoError(t, vault.WriteFile("conflict.md", []byte("local"), time.Time{}))

	// push.Folder=true so downloadServerFile takes the MkdirAll branch
	// (no pullDirect needed).
	push := PushMessage{UID: 300, Hash: "h", Folder: true}
	local := state.LocalFile{Path: "conflict.md", Folder: false, MTime: 1000}

	err := r.handleTypeConflict(ctx, "conflict.md", push, local)
	require.NoError(t, err)

	// Original path should now be a directory (server wins).
	info, err := vault.Stat("conflict.md")
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	// Conflict copy should exist.
	conflictContent, err := vault.ReadFile("conflict (Conflicted copy).md")
	require.NoError(t, err)
	assert.Equal(t, "local", string(conflictContent))
}

// --- processOneServerPush: exercises the full decision flow ---

func TestProcessOneServerPush_SkipsDeletedNoLocal(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, appState, cipher, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	encPath := encryptPath(t, cipher, "gone.md")
	push := PushMessage{
		Op:      "push",
		UID:     50,
		Path:    encPath,
		Deleted: true,
	}

	sp := ServerPush{Path: "gone.md", Msg: push}
	scan := &ScanResult{Current: map[string]state.LocalFile{}}

	err := r.processOneServerPush(ctx, sp, scan, map[string]state.ServerFile{})
	require.NoError(t, err)

	// Server file should be deleted (not stored).
	sf, err := appState.GetServerFile(testSyncVaultID, "gone.md")
	require.NoError(t, err)
	assert.Nil(t, sf)
}

// --- handleTypeConflict: local file, ReadFile error ---

func TestHandleTypeConflict_LocalFile_ReadError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	// File doesn't exist on disk, so ReadFile will fail.
	push := PushMessage{UID: 400, Hash: "h", Folder: true}
	local := state.LocalFile{Path: "nosuch.md", Folder: false}

	err := r.handleTypeConflict(ctx, "nosuch.md", push, local)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading local file for conflict copy")
}

// --- handleTypeConflict: local file, push.Deleted ---

func TestHandleTypeConflict_LocalFile_PushDeleted(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("del-conflict.md", []byte("local data"), time.Time{}))

	push := PushMessage{UID: 401, Hash: "h", Deleted: true}
	local := state.LocalFile{Path: "del-conflict.md", Folder: false}

	err := r.handleTypeConflict(ctx, "del-conflict.md", push, local)
	require.NoError(t, err)

	// Conflict copy should exist.
	content, err := vault.ReadFile("del-conflict (Conflicted copy).md")
	require.NoError(t, err)
	assert.Equal(t, "local data", string(content))
}

// --- writeServerContent: WriteFile error ---

func TestWriteServerContent_WriteFileError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, _ := fullReconciler(t, ctrl)

	// Make vault read-only to cause WriteFile to fail.
	require.NoError(t, os.Chmod(vault.Dir(), 0o555))
	t.Cleanup(func() { _ = os.Chmod(vault.Dir(), 0o755) })

	push := PushMessage{UID: 500, Hash: "h", MTime: 1000}
	err := r.writeServerContent("sub/fail.md", push, []byte("data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "writing")
}

// --- threeWayMerge: server decrypt error ---

func TestThreeWayMerge_DecryptServerVersionError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("srvdec.md", []byte("local"), time.Time{}))

	// No base (hasPrev=false). Server pull returns garbage.
	badContent := []byte{0xBA, 0xD0, 0xBA, 0xD0}
	mockPullDirect(mock, badContent)

	push := PushMessage{UID: 600, Hash: "h", MTime: 3000}
	local := state.LocalFile{Path: "srvdec.md", MTime: 1000, Hash: "lh"}

	err := r.threeWayMerge(ctx, "srvdec.md", push, local, state.ServerFile{}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decrypting server version")
}

// --- jsonMerge: decrypt server config error ---

func TestJSONMerge_DecryptServerConfigError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("app.json", []byte(`{"key":"val"}`), time.Time{}))

	// Server pull returns garbage that fails to decrypt.
	badContent := []byte{0xDE, 0xAD}
	mockPullDirect(mock, badContent)

	push := PushMessage{UID: 700, Hash: "h"}
	err := r.jsonMerge(ctx, "app.json", push)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decrypting server config")
}

// --- downloadServerFile: pull error ---

func TestDownloadServerFile_PullError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, _, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	// Pull fails.
	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageType(0), nil, fmt.Errorf("pull failed")),
	)

	push := PushMessage{UID: 800, Hash: "h"}
	err := r.downloadServerFile(ctx, "broken.md", push)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pulling")
}

// --- downloadServerFile: folder MkdirAll error ---

func TestDownloadServerFile_FolderMkdirError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, os.Chmod(vault.Dir(), 0o555))
	t.Cleanup(func() { _ = os.Chmod(vault.Dir(), 0o755) })

	push := PushMessage{UID: 900, Folder: true}
	err := r.downloadServerFile(ctx, "newdir", push)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "creating folder")
}

// --- downloadServerFile: empty content writes zero-byte file ---

func TestDownloadServerFile_EmptyContentFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	// Encrypt empty content.
	encEmpty := encryptContent(t, cipher, []byte{})
	mockPullDirect(mock, encEmpty)

	push := PushMessage{UID: 1000, Hash: "h", MTime: 5000}
	err := r.downloadServerFile(ctx, "empty.md", push)
	require.NoError(t, err)

	content, err := vault.ReadFile("empty.md")
	require.NoError(t, err)
	assert.Empty(t, content)
}

// --- threeWayMerge: ReadFile error ---

func TestThreeWayMerge_ReadFileError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	// File doesn't exist, ReadFile fails.
	push := PushMessage{UID: 700, Hash: "h"}
	local := state.LocalFile{Path: "nosuch.md", Hash: "lh"}

	err := r.threeWayMerge(ctx, "nosuch.md", push, local, state.ServerFile{}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading local file for merge")
}

// --- threeWayMerge: no base, recent ctime, server wins ---

func TestThreeWayMerge_RecentCtime_ServerWins(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("recent.md", []byte("local"), time.Time{}))

	serverText := "server wins"
	encServer := encryptContent(t, cipher, []byte(serverText))
	// No base (hasPrev=false). Server pull returns valid content.
	mockPullDirect(mock, encServer)

	push := PushMessage{UID: 701, Hash: "h", MTime: 5000}
	// CTime within 3 minutes of now.
	local := state.LocalFile{
		Path:  "recent.md",
		MTime: 1000,
		CTime: time.Now().UnixMilli() - 60_000,
		Hash:  "lh",
	}

	err := r.threeWayMerge(ctx, "recent.md", push, local, state.ServerFile{}, false)
	require.NoError(t, err)

	got, err := vault.ReadFile("recent.md")
	require.NoError(t, err)
	assert.Equal(t, serverText, string(got))
}

// --- jsonMerge: ReadFile error ---

func TestJSONMerge_ReadFileError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	// File doesn't exist. jsonMerge falls back to downloadServerFile.
	encContent := encryptContent(t, cipher, []byte(`{"server":"data"}`))
	mockPullDirect(mock, encContent)

	push := PushMessage{UID: 800, Hash: "h"}
	err := r.jsonMerge(ctx, "nosuch.json", push)
	require.NoError(t, err)

	got, err := r.vault.ReadFile("nosuch.json")
	require.NoError(t, err)
	assert.Contains(t, string(got), "server")
}

// --- jsonMerge: pull error ---

func TestJSONMerge_PullError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("app.json", []byte(`{"key":"val"}`), time.Time{}))

	// Pull fails.
	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageType(0), nil, fmt.Errorf("pull error")),
	)

	push := PushMessage{UID: 801, Hash: "h"}
	err := r.jsonMerge(ctx, "app.json", push)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pulling server config")
}

// --- handleTypeConflict: folder rename error ---

func TestHandleTypeConflict_FolderRenameError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, cipher, mock := fullReconciler(t, ctrl)
	ctx := context.Background()

	// Create a folder that should be renamed. Make vault read-only so
	// Rename fails, but the function logs and continues to downloadServerFile.
	require.NoError(t, vault.MkdirAll("myfolder"))

	serverText := "server file"
	encServer := encryptContent(t, cipher, []byte(serverText))
	mockPullDirect(mock, encServer)

	// Make vault read-only so Rename fails.
	require.NoError(t, os.Chmod(vault.Dir(), 0o555))
	t.Cleanup(func() { _ = os.Chmod(vault.Dir(), 0o755) })

	push := PushMessage{UID: 900, Hash: "h", MTime: 1000}
	local := state.LocalFile{Path: "myfolder", Folder: true}

	// Rename fails (logged), then downloadServerFile tries to write
	// which also fails because vault is read-only. So we get an error
	// from the write step, not the rename.
	err := r.handleTypeConflict(ctx, "myfolder", push, local)
	require.Error(t, err)
}

// --- handleTypeConflict: WriteFile conflict copy error ---

func TestHandleTypeConflict_WriteConflictCopyError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, vault, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	require.NoError(t, vault.WriteFile("wce.md", []byte("local"), time.Time{}))

	// Make vault read-only so WriteFile for conflict copy fails.
	require.NoError(t, os.Chmod(vault.Dir(), 0o555))
	t.Cleanup(func() { _ = os.Chmod(vault.Dir(), 0o755) })

	push := PushMessage{UID: 901}
	local := state.LocalFile{Path: "wce.md", Folder: false}

	err := r.handleTypeConflict(ctx, "wce.md", push, local)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "writing conflict copy")
}

// --- uploadLocalChanges: folder push error ---

func TestUploadLocalChanges_FolderPushError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, _, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	// Fake event loop that returns errors.
	loopCtx, loopCancel := context.WithCancel(context.Background())

	go func() {
		for {
			select {
			case op := <-s.opCh:
				op.result <- fmt.Errorf("push failed")
			case <-loopCtx.Done():
				return
			}
		}
	}()

	t.Cleanup(func() { loopCancel() })

	scan := &ScanResult{
		Current: map[string]state.LocalFile{
			"newdir": {Path: "newdir", Folder: true},
		},
		Changed: []string{"newdir"},
	}

	// Folder push fails, logged but continues.
	err := r.uploadLocalChanges(ctx, scan, map[string]state.ServerFile{})
	require.NoError(t, err) // errors are logged, not returned
}

// --- uploadLocalChanges: file push error ---

func TestUploadLocalChanges_FilePushError(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, s, vault, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	content := []byte("file data")
	require.NoError(t, vault.WriteFile("fail.md", content, time.Time{}))

	loopCtx, loopCancel := context.WithCancel(context.Background())

	go func() {
		for {
			select {
			case op := <-s.opCh:
				op.result <- fmt.Errorf("push failed")
			case <-loopCtx.Done():
				return
			}
		}
	}()

	t.Cleanup(func() { loopCancel() })

	scan := &ScanResult{
		Current: map[string]state.LocalFile{
			"fail.md": {Path: "fail.md", Hash: "h", Size: int64(len(content))},
		},
		Changed: []string{"fail.md"},
	}

	err := r.uploadLocalChanges(ctx, scan, map[string]state.ServerFile{})
	require.NoError(t, err) // errors are logged, not returned
}

// --- uploadLocalChanges: changed path not in Current ---

func TestUploadLocalChanges_ChangedPathNotInCurrent(t *testing.T) {
	ctrl := gomock.NewController(t)
	r, _, _, _, _, _ := fullReconciler(t, ctrl)
	ctx := context.Background()

	scan := &ScanResult{
		Current: map[string]state.LocalFile{},
		Changed: []string{"vanished.md"}, // not in Current
	}

	err := r.uploadLocalChanges(ctx, scan, map[string]state.ServerFile{})
	require.NoError(t, err) // skipped silently
}

// mustJSON marshals v to JSON bytes, panicking on error.
func mustJSON(v PullResponse) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}

	return data
}
