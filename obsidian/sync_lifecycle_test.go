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

// --- Close ---

func TestClose_NilConn(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	// conn is nil by default from fullSyncClient.
	err := s.Close()
	assert.NoError(t, err)
}

func TestClose_WithConn(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)

	mock.EXPECT().Close(websocket.StatusNormalClosure, "bye").Return(nil)

	err := s.Close()
	assert.NoError(t, err)
}

func TestClose_CancelsConnContext(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)

	ctx, cancel := context.WithCancel(context.Background())
	s.connCancel = cancel

	mock.EXPECT().Close(websocket.StatusNormalClosure, "bye").Return(nil)

	err := s.Close()
	assert.NoError(t, err)
	assert.Error(t, ctx.Err(), "connCancel should have been called")
}

func TestClose_ConnCloseError(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)

	mock.EXPECT().Close(websocket.StatusNormalClosure, "bye").
		Return(fmt.Errorf("already closed"))

	err := s.Close()
	assert.ErrorContains(t, err, "already closed")
}

// --- Push ---

func TestPush_SubmitsToEventLoop(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Simulate an event loop draining opCh and returning success.
	go func() {
		op := <-s.opCh
		assert.Equal(t, "test.md", op.path)
		assert.Equal(t, []byte("data"), op.content)
		assert.True(t, op.isFolder)
		assert.True(t, op.isDeleted)
		assert.Equal(t, int64(100), op.mtime)
		assert.Equal(t, int64(50), op.ctime)
		op.result <- nil
	}()

	err := s.Push(ctx, "test.md", []byte("data"), 100, 50, true, true)
	assert.NoError(t, err)
}

func TestPush_PropagatesError(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		op := <-s.opCh
		op.result <- fmt.Errorf("server rejected")
	}()

	err := s.Push(ctx, "test.md", nil, 0, 0, false, false)
	assert.ErrorContains(t, err, "server rejected")
}

func TestPush_ContextCancelledBeforeSend(t *testing.T) {
	s, _, _, _ := fullSyncClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	// opCh has capacity 64, so it might or might not be sent.
	// But ctx is already cancelled, so Push should return quickly.
	err := s.Push(ctx, "test.md", nil, 0, 0, false, false)
	// Either the op was sent and ctx cancelled while waiting for result,
	// or ctx was cancelled before sending. Both return ctx.Err().
	assert.Error(t, err)
}

// --- startReader ---

func TestStartReader_FeedsInboundCh(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	payload := []byte(`{"op":"pong"}`)
	gomock.InOrder(
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, payload, nil),
		mock.EXPECT().Read(gomock.Any()).DoAndReturn(
			func(ctx context.Context) (websocket.MessageType, []byte, error) {
				// Block until cancelled so the goroutine exits cleanly.
				<-ctx.Done()
				return 0, nil, ctx.Err()
			},
		),
	)

	s.startReader(ctx)

	select {
	case msg := <-s.inboundCh:
		assert.Equal(t, websocket.MessageText, msg.typ)
		assert.Equal(t, payload, msg.data)
		assert.NoError(t, msg.err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for inbound message")
	}
}

func TestStartReader_DeliverReadError(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageType(0), nil, fmt.Errorf("conn died"))

	s.startReader(ctx)

	select {
	case msg := <-s.inboundCh:
		assert.Error(t, msg.err)
		assert.ErrorContains(t, msg.err, "conn died")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for error message")
	}
}

func TestStartReader_NewChannelPerCall(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx1, cancel1 := context.WithCancel(context.Background())

	// First reader blocks forever.
	mock.EXPECT().Read(gomock.Any()).DoAndReturn(
		func(ctx context.Context) (websocket.MessageType, []byte, error) {
			<-ctx.Done()
			return 0, nil, ctx.Err()
		},
	).AnyTimes()

	s.startReader(ctx1)
	ch1 := s.inboundCh

	cancel1()
	time.Sleep(10 * time.Millisecond) // let goroutine exit

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	s.startReader(ctx2)
	ch2 := s.inboundCh

	// Channels should be different instances.
	assert.NotEqual(t, fmt.Sprintf("%p", ch1), fmt.Sprintf("%p", ch2))
}

// --- eventLoop ---

func TestEventLoop_InboundPush(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, _ := withMockConn(t, ctrl)
	ctx, cancel := context.WithCancel(context.Background())

	// Encrypt a path for a push that Reconcile will skip (deleted, no local).
	encPath := encryptPath(t, s.cipher, "remote.md")
	pushJSON, _ := json.Marshal(PushMessage{
		Op:      "push",
		UID:     500,
		Path:    encPath,
		Deleted: true,
	})

	go func() {
		time.Sleep(10 * time.Millisecond)
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: pushJSON}
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	err := s.eventLoop(ctx, connCtx)
	assert.ErrorIs(t, err, context.Canceled)

	// Version should have been updated.
	assert.Equal(t, int64(500), s.version)
}

func TestEventLoop_InboundReadError(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, _ := withMockConn(t, ctrl)
	ctx := context.Background()
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	go func() {
		time.Sleep(10 * time.Millisecond)
		s.inboundCh <- inboundMsg{err: fmt.Errorf("connection lost")}
	}()

	err := s.eventLoop(ctx, connCtx)
	assert.ErrorContains(t, err, "connection lost")
}

func TestEventLoop_OpChannelPush(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx, cancel := context.WithCancel(context.Background())

	// Folder push: write succeeds, response is "ok".
	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil)

	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	op := syncOp{
		path:     "folder",
		isFolder: true,
		result:   make(chan error, 1),
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		s.opCh <- op
		// Feed the response after a brief delay.
		time.Sleep(5 * time.Millisecond)
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(`{"op":"ok"}`)}
		// Wait for the push to complete, then cancel.
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	err := s.eventLoop(ctx, connCtx)
	assert.ErrorIs(t, err, context.Canceled)

	select {
	case opErr := <-op.result:
		assert.NoError(t, opErr)
	default:
		t.Fatal("op.result should have a value")
	}
}

func TestEventLoop_OpConnectionError(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)
	ctx := context.Background()
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).
		Return(fmt.Errorf("broken pipe"))

	op := syncOp{
		path:     "folder",
		isFolder: true,
		result:   make(chan error, 1),
	}

	go func() {
		time.Sleep(10 * time.Millisecond)
		s.opCh <- op
	}()

	err := s.eventLoop(ctx, connCtx)
	assert.ErrorContains(t, err, "broken pipe")
}

func TestEventLoop_ConnCtxCancelled(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, _ := withMockConn(t, ctrl)
	ctx := context.Background()
	connCtx, connCancel := context.WithCancel(ctx)

	go func() {
		time.Sleep(10 * time.Millisecond)
		connCancel()
	}()

	err := s.eventLoop(ctx, connCtx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestEventLoop_BinaryFrameSkipped(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, _ := withMockConn(t, ctrl)
	ctx, cancel := context.WithCancel(context.Background())
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	go func() {
		time.Sleep(10 * time.Millisecond)
		// Binary frame should be skipped.
		s.inboundCh <- inboundMsg{typ: websocket.MessageBinary, data: []byte("binary")}
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	err := s.eventLoop(ctx, connCtx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestEventLoop_PongHandled(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, _ := withMockConn(t, ctrl)
	ctx, cancel := context.WithCancel(context.Background())
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()

	go func() {
		time.Sleep(10 * time.Millisecond)
		s.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(`{"op":"pong"}`)}
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	err := s.eventLoop(ctx, connCtx)
	assert.ErrorIs(t, err, context.Canceled)
}

// --- Listen ---

func TestListen_ContextCancelled(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)

	// startReader will call Read. Block it until cancelled.
	mock.EXPECT().Read(gomock.Any()).DoAndReturn(
		func(ctx context.Context) (websocket.MessageType, []byte, error) {
			<-ctx.Done()
			return 0, nil, ctx.Err()
		},
	).AnyTimes()

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := s.Listen(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestListen_PermanentError(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, mock := withMockConn(t, ctrl)

	// Reader delivers a permanent error message.
	mock.EXPECT().Read(gomock.Any()).DoAndReturn(
		func(ctx context.Context) (websocket.MessageType, []byte, error) {
			return 0, nil, fmt.Errorf("auth failed")
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.Listen(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permanent error")
}

// --- Pull (public wrapper) ---

func TestPull_Public_DelegatesToPullDirect(t *testing.T) {
	ctrl := gomock.NewController(t)
	s, _, _, cipher := fullSyncClient(t)
	mock := NewMockWSConn(ctrl)
	s.conn = mock

	plainContent := []byte("via-pull-public")
	encContent := encryptContent(t, cipher, plainContent)

	pullResp, _ := json.Marshal(PullResponse{Size: len(encContent), Pieces: 1})
	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, pullResp, nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageBinary, encContent, nil),
	)

	data, err := s.Pull(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, encContent, data)
}
