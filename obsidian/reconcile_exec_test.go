package obsidian

import (
	"context"
	"encoding/json"
	"fmt"
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

	r := NewReconciler(vault, s, appState, testSyncVaultID, cipher, quietLogger)
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
	resp, _ := json.Marshal(PullResponse{Size: len(encContent), Pieces: 1})
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
	baseResp, _ := json.Marshal(PullResponse{Size: len(encBase), Pieces: 1})
	serverResp, _ := json.Marshal(PullResponse{Size: len(encServer), Pieces: 1})
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
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, mustJSON(PullResponse{Size: len(encServer), Pieces: 1}), nil),
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
	assert.NoError(t, err)

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

// mustJSON marshals v to JSON bytes, panicking on error.
func mustJSON(v PullResponse) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
