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

// --- handlePushOp ---

func TestHandlePushOp_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	// Folder push: single write + single response.
	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)
	feedResponse(s, `{"op":"ok"}`)

	op := syncOp{
		path:     "folder",
		isFolder: true,
		result:   make(chan error, 1),
	}

	err := s.handlePushOp(ctx, op)
	assert.NoError(t, err, "handlePushOp should return nil on success")

	select {
	case opErr := <-op.result:
		assert.NoError(t, opErr, "op.result should be nil on success")
	default:
		t.Fatal("op.result should have a value")
	}
}

func TestHandlePushOp_ConnectionError(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	writeErr := fmt.Errorf("connection reset")
	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(writeErr)

	op := syncOp{
		path:     "folder",
		isFolder: true,
		result:   make(chan error, 1),
	}

	err := s.handlePushOp(ctx, op)
	assert.ErrorContains(t, err, "connection reset", "connection errors propagate")

	select {
	case opErr := <-op.result:
		assert.ErrorContains(t, opErr, "connection reset", "op.result gets the error too")
	default:
		t.Fatal("op.result should have a value")
	}
}

func TestHandlePushOp_OperationError_ReturnsNil(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	// Write succeeds for the metadata message, then server returns an error
	// containing "encrypting path" which isOperationError matches.
	// Actually, the error must come from executePush itself. The simplest
	// way to get an operation error: write succeeds, response is an error
	// from the server that records retry backoff. But that's not an
	// isOperationError. Let's use a different approach: set cipher to nil
	// won't work (panic). Instead, test that a backoff-skipped push (returns
	// nil) makes handlePushOp return nil.
	//
	// For a true operation error test, we need executePush to return an
	// error whose message contains "encrypting". We can achieve this by
	// injecting a mock Write that fails with that exact message.
	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).
		Return(fmt.Errorf("encrypting path: bad key"))

	op := syncOp{
		path:     "test.md",
		isFolder: false,
		result:   make(chan error, 1),
	}

	err := s.handlePushOp(ctx, op)
	assert.NoError(t, err, "operation errors do not propagate as return value")

	select {
	case opErr := <-op.result:
		assert.ErrorContains(t, opErr, "encrypting path")
	default:
		t.Fatal("op.result should have a value")
	}
}

// --- processPushDirect ---

func TestProcessPushDirect_SkipsDeletedNoLocal(t *testing.T) {
	s, _, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	push := PushMessage{
		UID:     100,
		Path:    encryptPath(t, cipher, "gone.md"),
		Deleted: true,
	}

	err := s.processPushDirect(ctx, push)
	require.NoError(t, err)

	// Server state should have been deleted (no entry).
	sf := s.ServerFileState("gone.md")
	assert.Nil(t, sf)
}

func TestProcessPushDirect_DownloadsNewFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, vault, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	// Set up mock conn for pullDirect (writes pull request, reads response).
	mock := NewMockWSConn(ctrl)
	s.conn = mock

	plainContent := []byte("hello from server")
	encContent := encryptContent(t, cipher, plainContent)
	encHash := encryptPath(t, cipher, "abc123")

	push := PushMessage{
		UID:   200,
		Path:  encryptPath(t, cipher, "new.md"),
		Hash:  encHash,
		Size:  int64(len(encContent)),
		MTime: time.Now().UnixMilli(),
	}

	// pullDirect sequence: write pull request, then read text response, then binary piece.
	pullResp, _ := json.Marshal(PullResponse{Size: len(encContent), Pieces: 1})
	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, pullResp, nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageBinary, encContent, nil),
	)

	err := s.processPushDirect(ctx, push)
	require.NoError(t, err)

	data, err := vault.ReadFile("new.md")
	require.NoError(t, err)
	assert.Equal(t, plainContent, data)
}

func TestProcessPushDirect_DecryptPathError(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	ctx := context.Background()

	push := PushMessage{
		UID:  300,
		Path: "not-valid-hex",
	}

	err := s.processPushDirect(ctx, push)
	assert.ErrorContains(t, err, "decrypting path")
}

// --- drainPendingPulls ---

func TestDrainPendingPulls_EmptyQueue(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	ctx := context.Background()

	// Should be a no-op.
	s.drainPendingPulls(ctx)
	assert.Empty(t, s.pendingPulls)
}

func TestDrainPendingPulls_ProcessesEntries(t *testing.T) {
	s, _, appState, cipher := fullSyncClient(t)
	ctx := context.Background()

	// Queue two skip-decision pushes (deleted files, no local).
	encPath1 := encryptPath(t, cipher, "a.md")
	encPath2 := encryptPath(t, cipher, "b.md")

	s.pendingPulls = []pendingPull{
		{push: PushMessage{UID: 10, Path: encPath1, Deleted: true}, path: "a.md"},
		{push: PushMessage{UID: 11, Path: encPath2, Deleted: true}, path: "b.md"},
	}

	s.drainPendingPulls(ctx)

	assert.Nil(t, s.pendingPulls, "queue should be cleared")

	// Server state should reflect the deletes (entries removed).
	sf1, _ := appState.GetServerFile(testSyncVaultID, "a.md")
	sf2, _ := appState.GetServerFile(testSyncVaultID, "b.md")
	assert.Nil(t, sf1)
	assert.Nil(t, sf2)
}

func TestDrainPendingPulls_ErrorsContinueProcessing(t *testing.T) {
	s, _, _, cipher := fullSyncClient(t)
	ctx := context.Background()

	encPathGood := encryptPath(t, cipher, "ok.md")

	s.pendingPulls = []pendingPull{
		// First entry: invalid encrypted path, will fail decrypt.
		{push: PushMessage{UID: 20, Path: "bad-hex"}, path: "bad.md"},
		// Second entry: valid skip decision.
		{push: PushMessage{UID: 21, Path: encPathGood, Deleted: true}, path: "ok.md"},
	}

	s.drainPendingPulls(ctx)
	assert.Nil(t, s.pendingPulls, "queue should be cleared even with errors")
}

// --- pull (via inboundCh) ---

func TestPull_SinglePiece(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	encContent := encryptContent(t, s.cipher, []byte("payload"))

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	go func() {
		time.Sleep(5 * time.Millisecond)
		resp, _ := json.Marshal(PullResponse{Size: len(encContent), Pieces: 1})
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: resp}
		s.inboundCh <- inboundMsg{typ: websocket.MessageBinary, data: encContent}
	}()

	data, err := s.pull(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, encContent, data)
}

func TestPull_MultiplePieces(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	chunk1 := []byte("aaaa")
	chunk2 := []byte("bbbb")
	totalSize := len(chunk1) + len(chunk2)

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	// Size must be large enough for validation: maxPieces = size/chunkSize + 1.
	// Use a declared size of chunkSize+1 so maxPieces = 2, allowing 2 pieces.
	// The actual data is smaller, but the server controls the declared size.
	declaredSize := chunkSize + 1

	go func() {
		time.Sleep(5 * time.Millisecond)
		resp, _ := json.Marshal(PullResponse{Size: declaredSize, Pieces: 2})
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: resp}
		s.inboundCh <- inboundMsg{typ: websocket.MessageBinary, data: chunk1}
		s.inboundCh <- inboundMsg{typ: websocket.MessageBinary, data: chunk2}
	}()

	data, err := s.pull(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, data, totalSize)
	assert.Equal(t, append(chunk1, chunk2...), data)
}

func TestPull_DeletedResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	go func() {
		time.Sleep(5 * time.Millisecond)
		s.inboundCh <- inboundMsg{
			typ:  websocket.MessageText,
			data: []byte(`{"deleted":true}`),
		}
	}()

	data, err := s.pull(ctx, 1)
	require.NoError(t, err)
	assert.Nil(t, data)
}

func TestPull_PongSkippedBeforeResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	encContent := encryptContent(t, s.cipher, []byte("data"))

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	go func() {
		time.Sleep(5 * time.Millisecond)
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(`{"op":"pong"}`)}
		resp, _ := json.Marshal(PullResponse{Size: len(encContent), Pieces: 1})
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: resp}
		s.inboundCh <- inboundMsg{typ: websocket.MessageBinary, data: encContent}
	}()

	data, err := s.pull(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, encContent, data)
}

func TestPull_PongSkippedBetweenPieces(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	chunk := []byte("chunk")
	declaredSize := chunkSize + 1 // allows 2 pieces in validation

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	go func() {
		time.Sleep(5 * time.Millisecond)
		resp, _ := json.Marshal(PullResponse{Size: declaredSize, Pieces: 2})
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: resp}
		s.inboundCh <- inboundMsg{typ: websocket.MessageBinary, data: chunk}
		// Pong between pieces.
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(`{"op":"pong"}`)}
		s.inboundCh <- inboundMsg{typ: websocket.MessageBinary, data: chunk}
	}()

	data, err := s.pull(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, append(chunk, chunk...), data)
}

func TestPull_PushHandledBetweenPieces(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	chunk := []byte("chunk")

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	// Push with invalid hex path will fail decrypt and be logged, but
	// handlePushWhileBusy still runs (it queues if needed).
	pushJSON := `{"op":"push","uid":500,"path":"not-hex","deleted":false}`

	go func() {
		time.Sleep(5 * time.Millisecond)
		resp, _ := json.Marshal(PullResponse{Size: len(chunk), Pieces: 1})
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: resp}
		// Push arrives between response and piece.
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(pushJSON)}
		s.inboundCh <- inboundMsg{typ: websocket.MessageBinary, data: chunk}
	}()

	data, err := s.pull(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, chunk, data)
}

func TestPull_WriteError(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).
		Return(fmt.Errorf("broken pipe"))

	_, err := s.pull(ctx, 1)
	assert.ErrorContains(t, err, "sending pull request")
}

func TestPull_ReadErrorDuringResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	go func() {
		time.Sleep(5 * time.Millisecond)
		s.inboundCh <- inboundMsg{err: fmt.Errorf("read failed")}
	}()

	_, err := s.pull(ctx, 1)
	assert.ErrorContains(t, err, "reading pull response")
}

func TestPull_ReadErrorDuringPieces(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	declaredSize := chunkSize + 1 // allows 2 pieces

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	go func() {
		time.Sleep(5 * time.Millisecond)
		resp, _ := json.Marshal(PullResponse{Size: declaredSize, Pieces: 2})
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: resp}
		s.inboundCh <- inboundMsg{typ: websocket.MessageBinary, data: []byte("a")}
		s.inboundCh <- inboundMsg{err: fmt.Errorf("read failed")}
	}()

	_, err := s.pull(ctx, 1)
	assert.ErrorContains(t, err, "reading piece")
}

func TestPull_OversizedResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	// perFileMax defaults to 208MB in fullSyncClient. Set a small limit.
	s.perFileMax = 100

	go func() {
		time.Sleep(5 * time.Millisecond)
		resp, _ := json.Marshal(PullResponse{Size: 999, Pieces: 1})
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: resp}
	}()

	_, err := s.pull(ctx, 1)
	assert.ErrorContains(t, err, "exceeds limit")
}

func TestPull_BadPiecesCount(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	go func() {
		time.Sleep(5 * time.Millisecond)
		resp, _ := json.Marshal(PullResponse{Size: 10, Pieces: -1})
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: resp}
	}()

	_, err := s.pull(ctx, 1)
	assert.ErrorContains(t, err, "out of range")
}

func TestPull_ZeroPieces(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	go func() {
		time.Sleep(5 * time.Millisecond)
		resp, _ := json.Marshal(PullResponse{Size: 0, Pieces: 0})
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: resp}
	}()

	data, err := s.pull(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, data)
}

func TestPull_UnexpectedTextDuringPieces(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	go func() {
		time.Sleep(5 * time.Millisecond)
		resp, _ := json.Marshal(PullResponse{Size: 10, Pieces: 1})
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: resp}
		// Unexpected text that is not pong or push.
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(`{"op":"unknown"}`)}
	}()

	_, err := s.pull(ctx, 1)
	assert.ErrorContains(t, err, "expected binary frame")
}

// --- ServerFileState ---

func TestServerFileState_NilWhenNoEntry(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	sf := s.ServerFileState("nonexistent.md")
	assert.Nil(t, sf)
}

func TestServerFileState_ReturnsPersistedEntry(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)

	require.NoError(t, appState.SetServerFile(testSyncVaultID, state.ServerFile{
		Path: "exists.md",
		Hash: "abc",
		UID:  42,
	}))

	sf := s.ServerFileState("exists.md")
	require.NotNil(t, sf)
	assert.Equal(t, "abc", sf.Hash)
	assert.Equal(t, int64(42), sf.UID)
}

// --- deleteLocalState ---

func TestDeleteLocalState_RemovesEntry(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)

	require.NoError(t, appState.SetLocalFile(testSyncVaultID, state.LocalFile{
		Path: "del.md",
		Hash: "hash",
	}))

	s.deleteLocalState("del.md")

	lf, err := appState.GetLocalFile(testSyncVaultID, "del.md")
	require.NoError(t, err)
	assert.Nil(t, lf)
}

func TestDeleteLocalState_DoesNotTouchHashCache(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)

	s.hashCacheMu.Lock()
	s.hashCache["cached.md"] = hashEntry{encHash: "e", contentHash: "c"}
	s.hashCacheMu.Unlock()

	// deleteLocalState only removes from bbolt, not hash cache.
	// Hash cache cleanup is done by the caller (removeHashCache).
	s.deleteLocalState("cached.md")
	assert.Equal(t, "c", s.ContentHash("cached.md"))
}

func TestDeleteLocalState_NonexistentIsNoOp(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	// Should not panic or error.
	s.deleteLocalState("nothing.md")
}

// --- persistLocalFileAfterWrite ---

func TestPersistLocalFileAfterWrite_WritesCorrectState(t *testing.T) {
	s, vault, appState, _ := fullSyncClient(t)

	require.NoError(t, vault.WriteFile("written.md", []byte("content"), time.Time{}))

	s.persistLocalFileAfterWrite("written.md", "hash123")

	lf, err := appState.GetLocalFile(testSyncVaultID, "written.md")
	require.NoError(t, err)
	require.NotNil(t, lf)
	assert.Equal(t, "written.md", lf.Path)
	assert.Equal(t, "hash123", lf.Hash)
	assert.Equal(t, "hash123", lf.SyncHash)
	assert.False(t, lf.Folder)
	assert.Greater(t, lf.Size, int64(0))
	assert.Greater(t, lf.MTime, int64(0))
	assert.Greater(t, lf.SyncTime, int64(0))
}

func TestPersistLocalFileAfterWrite_StatErrorLogsOnly(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)

	// File doesn't exist on disk; stat will fail. Should not panic.
	s.persistLocalFileAfterWrite("missing.md", "hash")

	lf, err := appState.GetLocalFile(testSyncVaultID, "missing.md")
	require.NoError(t, err)
	assert.Nil(t, lf, "should not persist if stat fails")
}

// --- persistLocalFolder ---

func TestPersistLocalFolder_WritesCorrectState(t *testing.T) {
	s, _, appState, _ := fullSyncClient(t)

	s.persistLocalFolder("notes")

	lf, err := appState.GetLocalFile(testSyncVaultID, "notes")
	require.NoError(t, err)
	require.NotNil(t, lf)
	assert.Equal(t, "notes", lf.Path)
	assert.True(t, lf.Folder)
	assert.Equal(t, int64(0), lf.Size)
	assert.Greater(t, lf.SyncTime, int64(0))
}

// --- checkFileChangedDuringDownload ---

func TestCheckFileChanged_NilPrePullInfo(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)

	err := s.checkFileChangedDuringDownload("any.md", nil)
	assert.NoError(t, err, "nil prePullInfo should skip check")
}

func TestCheckFileChanged_Unchanged(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)

	require.NoError(t, vault.WriteFile("stable.md", []byte("data"), time.Time{}))
	info, err := vault.Stat("stable.md")
	require.NoError(t, err)

	err = s.checkFileChangedDuringDownload("stable.md", info)
	assert.NoError(t, err)
}

func TestCheckFileChanged_MtimeChanged(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)

	require.NoError(t, vault.WriteFile("changing.md", []byte("data"), time.Time{}))
	info, err := vault.Stat("changing.md")
	require.NoError(t, err)

	// Write again to change mtime.
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, vault.WriteFile("changing.md", []byte("data"), time.Time{}))

	err = s.checkFileChangedDuringDownload("changing.md", info)
	assert.ErrorContains(t, err, "changed locally during download")
}

func TestCheckFileChanged_SizeChanged(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)

	mtime := time.Now().Truncate(time.Second)
	require.NoError(t, vault.WriteFile("grow.md", []byte("a"), mtime))
	info, err := vault.Stat("grow.md")
	require.NoError(t, err)

	// Write different size with same mtime.
	require.NoError(t, vault.WriteFile("grow.md", []byte("abcdef"), mtime))

	err = s.checkFileChangedDuringDownload("grow.md", info)
	assert.ErrorContains(t, err, "changed locally during download")
}

func TestCheckFileChanged_FileDeleted(t *testing.T) {
	s, vault, _, _ := fullSyncClient(t)

	require.NoError(t, vault.WriteFile("ephemeral.md", []byte("data"), time.Time{}))
	info, err := vault.Stat("ephemeral.md")
	require.NoError(t, err)

	require.NoError(t, vault.DeleteFile("ephemeral.md"))

	err = s.checkFileChangedDuringDownload("ephemeral.md", info)
	assert.NoError(t, err, "deleted file should not block download")
}

func TestCheckFileChanged_StatError(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)

	// Use a fake os.FileInfo so prePullInfo is non-nil but the path
	// doesn't exist and is invalid enough to cause a non-IsNotExist error.
	// Actually vault.Stat on a nonexistent file returns os.IsNotExist,
	// which returns nil. We need a path that causes a different error.
	// Path traversal attempts return "path escapes vault root" errors.
	info := fakeFileInfo{name: "x", size: 1, mtime: time.Now()}
	err := s.checkFileChangedDuringDownload("../escape", info)
	assert.Error(t, err, "non-existence errors other than NotExist should propagate")
}

// fakeFileInfo implements os.FileInfo for testing.
type fakeFileInfo struct {
	name  string
	size  int64
	mtime time.Time
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return 0644 }
func (f fakeFileInfo) ModTime() time.Time { return f.mtime }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() interface{}   { return nil }
