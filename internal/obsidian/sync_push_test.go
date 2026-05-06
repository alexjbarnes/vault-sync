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

// withMockConn sets up a SyncClient with a MockWSConn and inboundCh for
// testing methods that do write+readResponse sequences (executePush).
func withMockConn(t *testing.T, ctrl *gomock.Controller) (*SyncClient, *MockWSConn) {
	t.Helper()
	s, _, _, _ := fullSyncClient(t)
	mock := NewMockWSConn(ctrl)
	s.conn = mock
	s.inboundCh = make(chan inboundMsg, 16)

	return s, mock
}

// feedResponse sends a text response on inboundCh in a goroutine.
func feedResponse(s *SyncClient, data string) {
	go func() {
		s.inboundCh <- inboundMsg{
			typ:  websocket.MessageText,
			data: []byte(data),
		}
	}()
}

// feedResponses sends multiple text responses with a small delay between.
func feedResponses(s *SyncClient, responses ...string) {
	go func() {
		for _, r := range responses {
			time.Sleep(5 * time.Millisecond)

			s.inboundCh <- inboundMsg{
				typ:  websocket.MessageText,
				data: []byte(r),
			}
		}
	}()
}

// --- executePush: folder ---

func TestExecutePush_Folder(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).
		DoAndReturn(func(ctx context.Context, typ websocket.MessageType, data []byte) error {
			var msg ClientPushMessage
			require.NoError(t, json.Unmarshal(data, &msg))
			assert.Equal(t, "push", msg.Op)
			assert.True(t, msg.Folder)
			assert.False(t, msg.Deleted)
			assert.Empty(t, msg.Extension)

			return nil
		})

	feedResponse(s, `{"res":"ok"}`)

	op := syncOp{
		path:     "new-folder",
		isFolder: true,
	}
	err := s.executePush(ctx, op)
	require.NoError(t, err)
}

// --- executePush: delete ---

func TestExecutePush_Delete(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	feedResponse(s, `{"res":"ok"}`)

	op := syncOp{
		path:      "gone.md",
		isDeleted: true,
	}
	err := s.executePush(ctx, op)
	require.NoError(t, err)
}

// --- executePush: file with content ---

func TestExecutePush_FileContent(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	content := []byte("hello world")
	// Write the file so persistPushedFile can stat it.
	require.NoError(t, s.vault.WriteFile("test.md", content, time.Time{}))

	writeCount := 0

	mock.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, typ websocket.MessageType, data []byte) error {
			writeCount++
			if writeCount == 1 {
				// First write: push metadata (text)
				assert.Equal(t, websocket.MessageText, typ)

				var msg ClientPushMessage
				require.NoError(t, json.Unmarshal(data, &msg))
				assert.Equal(t, "push", msg.Op)
				assert.Equal(t, "md", msg.Extension)
				assert.False(t, msg.Folder)
				assert.False(t, msg.Deleted)
				assert.Positive(t, msg.Size)
				assert.Positive(t, msg.Pieces)
			} else {
				// Second write: binary chunk
				assert.Equal(t, websocket.MessageBinary, typ)
			}

			return nil
		}).Times(2)

	// Feed response for metadata, then ack for the chunk.
	feedResponses(s, `{"res":"next"}`, `{"res":"next"}`)

	op := syncOp{
		path:    "test.md",
		content: content,
		mtime:   time.Now().UnixMilli(),
		ctime:   time.Now().UnixMilli(),
	}
	err := s.executePush(ctx, op)
	require.NoError(t, err)

	// Hash cache should be populated.
	assert.NotEmpty(t, s.ContentHash("test.md"))
}

// --- executePush: server says "ok" (unchanged) ---

func TestExecutePush_ServerOkSkipsUpload(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	content := []byte("unchanged content")

	// Only one Write (metadata), no binary chunk since server says ok.
	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	feedResponse(s, `{"res":"ok"}`)

	op := syncOp{
		path:    "unchanged.md",
		content: content,
	}
	err := s.executePush(ctx, op)
	require.NoError(t, err)
}

// --- executePush: server error ---

func TestExecutePush_ServerError(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	content := []byte("will be rejected")

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	feedResponse(s, `{"res":"err","msg":"file too large"}`)

	op := syncOp{
		path:    "rejected.md",
		content: content,
	}
	err := s.executePush(ctx, op)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file too large")

	// Should be in retry backoff.
	_, inBackoff := s.checkRetryBackoff("rejected.md")
	assert.True(t, inBackoff)
}

// --- executePush: oversized file ---

func TestExecutePush_OversizedFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, _ := withMockConn(t, ctrl)
	ctx := context.Background()

	s.perFileMax = 100 // Very small limit.
	content := make([]byte, 200)

	// No Write calls expected -- skipped before sending.
	op := syncOp{
		path:    "huge.bin",
		content: content,
	}
	err := s.executePush(ctx, op)
	require.NoError(t, err) // Not an error, just skipped.
}

// --- executePush: retry backoff ---

func TestExecutePush_SkippedInBackoff(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, _ := withMockConn(t, ctrl)
	ctx := context.Background()

	s.recordRetryBackoff("backoff.md")

	// No Write calls expected.
	op := syncOp{path: "backoff.md", content: []byte("x")}
	err := s.executePush(ctx, op)
	require.NoError(t, err) // Silently skipped.
}

// --- executePush: write error ---

func TestExecutePush_WriteError(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).
		Return(fmt.Errorf("connection reset"))

	op := syncOp{path: "fail-folder", isFolder: true}
	err := s.executePush(ctx, op)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sending push metadata")
}

// --- executePush: folder readResponse error ---

func TestExecutePush_FolderReadResponseError(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	// readResponse times out or gets an error via inboundCh.
	go func() {
		time.Sleep(5 * time.Millisecond)

		s.inboundCh <- inboundMsg{err: fmt.Errorf("read failed")}
	}()

	op := syncOp{path: "folder", isFolder: true}
	err := s.executePush(ctx, op)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read failed")

	_, inBackoff := s.checkRetryBackoff("folder")
	assert.True(t, inBackoff)
}

// --- executePush: content metadata readResponse error ---

func TestExecutePush_ContentMetadataReadResponseError(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	content := []byte("some file content")

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	// readResponse after metadata write fails.
	go func() {
		time.Sleep(5 * time.Millisecond)

		s.inboundCh <- inboundMsg{err: fmt.Errorf("connection lost")}
	}()

	op := syncOp{path: "fail.md", content: content}
	err := s.executePush(ctx, op)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection lost")

	// Hash cache should be cleaned up.
	assert.Empty(t, s.ContentHash("fail.md"))
}

// --- executePush: malformed JSON response ---

func TestExecutePush_MalformedResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	content := []byte("data")

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	feedResponse(s, `not valid json`)

	op := syncOp{path: "bad-resp.md", content: content}
	err := s.executePush(ctx, op)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding push response")
}

// --- executePush: binary chunk write error ---

func TestExecutePush_BinaryChunkWriteError(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	content := []byte("chunk data")

	writeCount := 0

	mock.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, typ websocket.MessageType, data []byte) error {
			writeCount++
			if writeCount == 1 {
				// Metadata write succeeds.
				return nil
			}
			// Binary chunk write fails.
			return fmt.Errorf("broken pipe")
		}).Times(2)

	// Response to metadata: "next" (proceed to send chunks).
	feedResponse(s, `{"res":"next"}`)

	op := syncOp{path: "chunk-fail.md", content: content}
	err := s.executePush(ctx, op)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sending chunk")

	// Hash cache should be cleaned up.
	assert.Empty(t, s.ContentHash("chunk-fail.md"))
}

// --- executePush: chunk ack readResponse error ---

func TestExecutePush_ChunkAckReadResponseError(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	content := []byte("ack fails")

	writeCount := 0

	mock.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, typ websocket.MessageType, data []byte) error {
			writeCount++
			return nil
		}).Times(2)

	// Response to metadata: "next". Then chunk ack fails.
	go func() {
		time.Sleep(5 * time.Millisecond)

		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(`{"res":"next"}`)}

		time.Sleep(5 * time.Millisecond)

		s.inboundCh <- inboundMsg{err: fmt.Errorf("ack lost")}
	}()

	op := syncOp{path: "ack-fail.md", content: content}
	err := s.executePush(ctx, op)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ack lost")

	// Hash cache should be cleaned up.
	assert.Empty(t, s.ContentHash("ack-fail.md"))
}

// --- executePush: delete readResponse error ---

func TestExecutePush_DeleteReadResponseError(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	go func() {
		time.Sleep(5 * time.Millisecond)

		s.inboundCh <- inboundMsg{err: fmt.Errorf("read failed")}
	}()

	op := syncOp{path: "del-fail.md", isDeleted: true}
	err := s.executePush(ctx, op)
	require.Error(t, err)

	_, inBackoff := s.checkRetryBackoff("del-fail.md")
	assert.True(t, inBackoff)
}

// --- executePush: multi-piece upload ---

func TestExecutePush_MultiPieceUpload(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	// Create content larger than chunkSize (2MB) to force multi-piece.
	// Use 2*chunkSize + 100 so we get 3 pieces.
	bigContent := make([]byte, 2*chunkSize+100)
	for i := range bigContent {
		bigContent[i] = byte(i % 256)
	}

	var writeCount int

	mock.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, typ websocket.MessageType, data []byte) error {
			writeCount++
			return nil
		}).Times(4) // 1 metadata + 3 binary chunks

	// Feed responses: 1 for metadata "ready" + 3 chunk acks.
	feedResponses(s,
		`{"res":"next"}`,
		`{"res":"next"}`,
		`{"res":"next"}`,
		`{"res":"next"}`,
	)

	op := syncOp{
		path:    "big-file.bin",
		content: bigContent,
		mtime:   1000,
		ctime:   500,
	}
	err := s.executePush(ctx, op)
	require.NoError(t, err)

	// 4 writes: 1 JSON metadata + 3 binary chunks.
	assert.Equal(t, 4, writeCount)
}

// --- executePush: empty content file ---

func TestExecutePush_EmptyContentFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	// Empty content: pieces=0, so no binary chunks are sent.
	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).
		DoAndReturn(func(ctx context.Context, typ websocket.MessageType, data []byte) error {
			var msg ClientPushMessage
			require.NoError(t, json.Unmarshal(data, &msg))
			assert.Equal(t, int64(0), msg.Size)
			assert.Equal(t, 0, msg.Pieces)

			return nil
		})

	// Server returns "ok" (file unchanged).
	feedResponse(s, `{"res":"ok"}`)

	op := syncOp{
		path:    "empty.md",
		content: []byte{},
	}
	err := s.executePush(ctx, op)
	require.NoError(t, err)
}

// --- executePush: server "ok" persists local + synthetic server state ---

func TestExecutePush_OkResponsePersistsState(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, _, appState, cipher := fullSyncClient(t)
	mock := NewMockWSConn(ctrl)
	s.conn = mock
	s.inboundCh = make(chan inboundMsg, 16)
	ctx := context.Background()

	content := []byte("ok-branch content")
	require.NoError(t, s.vault.WriteFile("ok.md", content, time.Time{}))

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)
	feedResponse(s, `{"res":"ok"}`)

	const (
		opMtime = int64(1_700_000_000_000)
		opCtime = int64(1_700_000_000_000)
	)

	op := syncOp{
		path:    "ok.md",
		content: content,
		mtime:   opMtime,
		ctime:   opCtime,
	}
	err := s.executePush(ctx, op)
	require.NoError(t, err)

	expectedHash := sha256Hex(content)
	encExpectedHash, err := cipher.EncryptPath(expectedHash)
	require.NoError(t, err)

	lf, err := appState.GetLocalFile(testSyncVaultID, "ok.md")
	require.NoError(t, err)
	require.NotNil(t, lf)
	assert.Equal(t, expectedHash, lf.Hash)
	assert.Equal(t, expectedHash, lf.SyncHash)
	// Persisted snapshot must come from the op, not a fresh stat.
	assert.Equal(t, opMtime, lf.MTime)
	assert.Equal(t, opCtime, lf.CTime)
	assert.Equal(t, int64(len(content)), lf.Size)
	assert.Positive(t, lf.SyncTime)
	assert.False(t, lf.Folder)

	sf, err := appState.GetServerFile(testSyncVaultID, "ok.md")
	require.NoError(t, err)
	require.NotNil(t, sf)
	assert.Equal(t, int64(0), sf.UID)
	assert.Equal(t, encExpectedHash, sf.Hash)
	assert.False(t, sf.Folder)
}

func TestExecutePush_OkResponseSnapshotSurvivesDiskChange(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, _, appState, _ := fullSyncClient(t)
	mock := NewMockWSConn(ctrl)
	s.conn = mock
	s.inboundCh = make(chan inboundMsg, 16)
	ctx := context.Background()

	// Op captures old content + a known old mtime.
	const oldMtime = int64(1_600_000_000_000)

	oldContent := []byte("old captured content")
	require.NoError(t, s.vault.WriteFile("racey.md", oldContent, time.UnixMilli(oldMtime)))

	op := syncOp{
		path:    "racey.md",
		content: oldContent,
		mtime:   oldMtime,
		ctime:   oldMtime,
	}

	// Simulate a concurrent local edit *before* the server replies "ok".
	newContent := []byte("local just edited this much later, with a different size entirely")
	require.NoError(t, s.vault.WriteFile("racey.md", newContent, time.Time{}))

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)
	feedResponse(s, `{"res":"ok"}`)

	require.NoError(t, s.executePush(ctx, op))

	lf, err := appState.GetLocalFile(testSyncVaultID, "racey.md")
	require.NoError(t, err)
	require.NotNil(t, lf)
	// Persisted state must reflect the OP snapshot, not the post-edit disk.
	assert.Equal(t, oldMtime, lf.MTime, "must persist op.mtime, not the post-edit disk mtime")
	assert.Equal(t, int64(len(oldContent)), lf.Size, "must persist op size, not the post-edit disk size")
	assert.Equal(t, sha256Hex(oldContent), lf.Hash)

	// The next scan must still flag this path as Changed because the
	// disk's (mtime, size) now diverges from the persisted snapshot.
	scan, err := ScanLocal(s.vault, appState, testSyncVaultID, quietLogger, nil)
	require.NoError(t, err)
	assert.Contains(t, scan.Changed, "racey.md", "next scan must re-flag concurrently-edited file")
}

func TestExecutePush_OkResponsePreservesRealServerUID(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, _, appState, cipher := fullSyncClient(t)
	mock := NewMockWSConn(ctrl)
	s.conn = mock
	s.inboundCh = make(chan inboundMsg, 16)
	ctx := context.Background()

	content := []byte("preserve-uid content")
	require.NoError(t, s.vault.WriteFile("preserve.md", content, time.Time{}))

	contentHash := sha256Hex(content)
	encHash, err := cipher.EncryptPath(contentHash)
	require.NoError(t, err)

	// Pre-populate a real server record with a non-zero UID and a Device.
	require.NoError(t, appState.SetServerFile(testSyncVaultID, state.ServerFile{
		Path:   "preserve.md",
		Hash:   encHash,
		UID:    123,
		MTime:  9000,
		Device: "other-device",
	}))

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)
	feedResponse(s, `{"res":"ok"}`)

	op := syncOp{
		path:    "preserve.md",
		content: content,
		mtime:   time.Now().UnixMilli(),
		ctime:   time.Now().UnixMilli(),
	}
	require.NoError(t, s.executePush(ctx, op))

	sf, err := appState.GetServerFile(testSyncVaultID, "preserve.md")
	require.NoError(t, err)
	require.NotNil(t, sf)
	assert.Equal(t, int64(123), sf.UID, "must preserve real UID, not overwrite with synthetic 0")
	assert.Equal(t, "other-device", sf.Device, "must preserve existing Device")
	assert.Equal(t, int64(9000), sf.MTime, "must preserve existing server MTime")
}

// --- executePush: extension extraction ---

func TestExecutePush_ExtensionExtracted(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).
		DoAndReturn(func(ctx context.Context, typ websocket.MessageType, data []byte) error {
			var msg ClientPushMessage
			require.NoError(t, json.Unmarshal(data, &msg))
			assert.Equal(t, "json", msg.Extension)

			return nil
		})

	feedResponse(s, `{"res":"ok"}`)

	op := syncOp{
		path:    ".obsidian/app.json",
		content: []byte(`{}`),
	}
	err := s.executePush(ctx, op)
	require.NoError(t, err)
}
