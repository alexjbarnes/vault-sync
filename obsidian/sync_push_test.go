package obsidian

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

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
				assert.Greater(t, msg.Size, 0)
				assert.Greater(t, msg.Pieces, 0)
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

	feedResponse(s, `{"err":"file too large"}`)

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
