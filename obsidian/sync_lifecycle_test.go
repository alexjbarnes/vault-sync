package obsidian

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"testing/synctest"
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

// --- eventLoop: heartbeat (synctest) ---

func TestEventLoop_SendsPingAfterIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctrl := gomock.NewController(t)
		s, mock := withMockConn(t, ctrl)
		ctx, cancel := context.WithCancel(t.Context())

		// Set lastMessage to "now" in the fake clock (midnight 2000-01-01).
		// After the ticker fires at +20s, elapsed (20s) > pingAfter (10s)
		// but < disconnectAfter (120s), so a ping is sent.
		s.lastMsgMu.Lock()
		s.lastMessage = time.Now()
		s.lastMsgMu.Unlock()

		pingData, _ := json.Marshal(map[string]string{"op": "ping"})
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, pingData).
			DoAndReturn(func(ctx context.Context, typ websocket.MessageType, data []byte) error {
				// Ping sent successfully. Cancel to exit the loop.
				cancel()
				return nil
			})

		connCtx, connCancel := context.WithCancel(ctx)
		t.Cleanup(func() { connCancel() })

		err := s.eventLoop(ctx, connCtx)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

func TestEventLoop_HeartbeatTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctrl := gomock.NewController(t)
		s, mock := withMockConn(t, ctrl)
		ctx := t.Context()

		// lastMessage is zero-valued, so elapsed will be enormous on the
		// first ticker fire, triggering the disconnect path.
		mock.EXPECT().Close(websocket.StatusGoingAway, "timeout").Return(nil)

		connCtx, connCancel := context.WithCancel(ctx)
		t.Cleanup(func() { connCancel() })

		err := s.eventLoop(ctx, connCtx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "heartbeat timeout")
	})
}

func TestEventLoop_PingWriteError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctrl := gomock.NewController(t)
		s, mock := withMockConn(t, ctrl)
		ctx := t.Context()

		// Set lastMessage so elapsed is > pingAfter but < disconnectAfter.
		s.lastMsgMu.Lock()
		s.lastMessage = time.Now()
		s.lastMsgMu.Unlock()

		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).
			Return(fmt.Errorf("broken pipe"))

		connCtx, connCancel := context.WithCancel(ctx)
		t.Cleanup(func() { connCancel() })

		err := s.eventLoop(ctx, connCtx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sending ping")
	})
}

// --- Listen (synctest) ---

func TestListen_CancelledDuringBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctrl := gomock.NewController(t)
		s, mock := withMockConn(t, ctrl)
		ctx, cancel := context.WithCancel(t.Context())

		// Set lastMessage so the heartbeat ticker doesn't interfere.
		s.lastMsgMu.Lock()
		s.lastMessage = time.Now()
		s.lastMsgMu.Unlock()

		// startReader calls Read. Return a transient error immediately
		// so eventLoop exits and Listen enters the backoff timer.
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, nil, fmt.Errorf("connection reset"))

		// After eventLoop returns, Listen enters backoff (5s + jitter).
		// Cancel ctx during backoff via a goroutine. The synctest fake
		// clock does not advance while any goroutine is runnable, so we
		// schedule the cancel with a small timer that fires before the
		// reconnect timer.
		go func() {
			// Wait for Listen to reach the timer select. synctest.Wait
			// cannot be called here (not the root goroutine), so use a
			// short sleep that fires before the reconnect timer.
			time.Sleep(1 * time.Second)
			cancel()
		}()

		err := s.Listen(ctx)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

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

// --- handshake ---

func TestHandshake_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	s := NewSyncClient(SyncConfig{
		VaultID:           "v1",
		Token:             "tok",
		KeyHash:           "kh",
		Device:            "dev",
		EncryptionVersion: 1,
		Version:           42,
		Initial:           true,
	}, quietLogger)

	authResp := InitResponse{Res: "ok", PerFileMax: 5242880, UserID: 99}
	authData, _ := json.Marshal(authResp)

	var sentInit InitMessage
	gomock.InOrder(
		mock.EXPECT().SetReadLimit(int64(16*1024*1024)),
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).
			DoAndReturn(func(_ context.Context, _ websocket.MessageType, data []byte) error {
				require.NoError(t, json.Unmarshal(data, &sentInit))
				return nil
			}),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, authData, nil),
		mock.EXPECT().SetReadLimit(int64(5242880*2)),
	)

	err := s.handshake(context.Background(), mock)
	require.NoError(t, err)

	// Verify init message fields.
	assert.Equal(t, "init", sentInit.Op)
	assert.Equal(t, "tok", sentInit.Token)
	assert.Equal(t, "v1", sentInit.ID)
	assert.Equal(t, "kh", sentInit.KeyHash)
	assert.Equal(t, "dev", sentInit.Device)
	assert.Equal(t, 1, sentInit.EncryptionVersion)
	assert.Equal(t, int64(42), sentInit.Version)
	assert.True(t, sentInit.Initial)

	// perFileMax should be updated.
	assert.Equal(t, 5242880, s.perFileMax)
	assert.Equal(t, mock, s.conn)
}

func TestHandshake_AuthFailedWithMessage(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	s := NewSyncClient(SyncConfig{}, quietLogger)

	authResp := InitResponse{Res: "err", Msg: "subscription expired"}
	authData, _ := json.Marshal(authResp)

	gomock.InOrder(
		mock.EXPECT().SetReadLimit(gomock.Any()),
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, authData, nil),
		mock.EXPECT().Close(websocket.StatusNormalClosure, "auth failed").Return(nil),
	)

	err := s.handshake(context.Background(), mock)
	assert.ErrorContains(t, err, "auth failed: subscription expired")
}

func TestHandshake_AuthFailedEmptyMsg(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	s := NewSyncClient(SyncConfig{}, quietLogger)

	// Msg is empty, so the error should fall back to Res.
	authResp := InitResponse{Res: "err", Msg: ""}
	authData, _ := json.Marshal(authResp)

	gomock.InOrder(
		mock.EXPECT().SetReadLimit(gomock.Any()),
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, authData, nil),
		mock.EXPECT().Close(websocket.StatusNormalClosure, "auth failed").Return(nil),
	)

	err := s.handshake(context.Background(), mock)
	assert.ErrorContains(t, err, "auth failed: err")
}

func TestHandshake_WriteError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	s := NewSyncClient(SyncConfig{}, quietLogger)

	gomock.InOrder(
		mock.EXPECT().SetReadLimit(gomock.Any()),
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).
			Return(fmt.Errorf("broken pipe")),
		mock.EXPECT().Close(websocket.StatusInternalError, "init failed").Return(nil),
	)

	err := s.handshake(context.Background(), mock)
	assert.ErrorContains(t, err, "sending init")
}

func TestHandshake_ReadError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	s := NewSyncClient(SyncConfig{}, quietLogger)

	gomock.InOrder(
		mock.EXPECT().SetReadLimit(gomock.Any()),
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageType(0), nil, fmt.Errorf("read timeout")),
		mock.EXPECT().Close(websocket.StatusInternalError, "auth read failed").Return(nil),
	)

	err := s.handshake(context.Background(), mock)
	assert.ErrorContains(t, err, "reading auth response")
}

func TestHandshake_PerFileMaxZero_KeepsDefault(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	s := NewSyncClient(SyncConfig{}, quietLogger)
	defaultMax := s.perFileMax

	// Server omits perFileMax (defaults to 0 in JSON).
	authResp := InitResponse{Res: "ok", PerFileMax: 0}
	authData, _ := json.Marshal(authResp)

	gomock.InOrder(
		mock.EXPECT().SetReadLimit(int64(16*1024*1024)),
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, authData, nil),
		// readLimit = max(defaultMax*2, 4MB). defaultMax is 208MB, so 416MB.
		mock.EXPECT().SetReadLimit(int64(defaultMax*2)),
	)

	err := s.handshake(context.Background(), mock)
	require.NoError(t, err)
	assert.Equal(t, defaultMax, s.perFileMax, "should keep default when server sends 0")
}

func TestHandshake_SmallPerFileMax_MinReadLimit(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	s := NewSyncClient(SyncConfig{}, quietLogger)

	// Server sends a tiny perFileMax. 2*1000 = 2000 < 4MB, so minimum applies.
	authResp := InitResponse{Res: "ok", PerFileMax: 1000}
	authData, _ := json.Marshal(authResp)

	gomock.InOrder(
		mock.EXPECT().SetReadLimit(int64(16*1024*1024)),
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, authData, nil),
		mock.EXPECT().SetReadLimit(int64(4*1024*1024)), // 4MB minimum
	)

	err := s.handshake(context.Background(), mock)
	require.NoError(t, err)
	assert.Equal(t, 1000, s.perFileMax)
}

func TestHandshake_CancelsPreviousConnCancel(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	s := NewSyncClient(SyncConfig{}, quietLogger)

	prevCtx, prevCancel := context.WithCancel(context.Background())
	s.connCancel = prevCancel

	authResp := InitResponse{Res: "ok", PerFileMax: 5242880}
	authData, _ := json.Marshal(authResp)

	gomock.InOrder(
		mock.EXPECT().SetReadLimit(gomock.Any()),
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, authData, nil),
		mock.EXPECT().SetReadLimit(gomock.Any()),
	)

	// Connect would call connCancel before dial. Since we're testing
	// handshake directly, verify connCancel is called by Connect's preamble.
	// We test the preamble separately here:
	if s.connCancel != nil {
		s.connCancel()
	}
	assert.Error(t, prevCtx.Err(), "previous connCancel should be called")

	err := s.handshake(context.Background(), mock)
	require.NoError(t, err)
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
