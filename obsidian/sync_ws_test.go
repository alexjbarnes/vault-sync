package obsidian

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"testing/synctest"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// newTestSyncClient creates a SyncClient with the mock connection injected
// and no cipher, vault, or state. Suitable for testing transport-level
// behavior where decryption is expected to fail (and be logged/skipped).
func newTestSyncClient(t *testing.T, conn wsConn) *SyncClient {
	t.Helper()

	return &SyncClient{
		conn:         conn,
		logger:       slog.Default(),
		perFileMax:   5 * 1024 * 1024,
		hashCache:    make(map[string]hashEntry),
		retryBackoff: make(map[string]retryEntry),
	}
}

// --- writeJSON tests ---

func TestWriteJSON_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	msg := map[string]string{"op": "ping"}
	expected, _ := json.Marshal(msg)

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, expected).Return(nil)

	err := sc.writeJSON(context.Background(), msg)
	assert.NoError(t, err)
}

func TestWriteJSON_WriteError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).
		Return(fmt.Errorf("connection reset"))

	err := sc.writeJSON(context.Background(), map[string]string{"op": "ping"})
	assert.ErrorContains(t, err, "connection reset")
}

func TestWriteJSON_MarshalError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// Channels cannot be marshalled to JSON.
	err := sc.writeJSON(context.Background(), make(chan int))
	assert.ErrorContains(t, err, "marshalling message")
}

// --- readJSON tests ---

func TestReadJSON_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	resp := InitResponse{Res: "ok", PerFileMax: 5242880, UserID: 1}
	data, _ := json.Marshal(resp)
	mock.EXPECT().Read(gomock.Any()).
		Return(websocket.MessageText, data, nil)

	var got InitResponse

	err := sc.readJSON(context.Background(), &got)
	require.NoError(t, err)
	assert.Equal(t, "ok", got.Res)
	assert.Equal(t, 5242880, got.PerFileMax)
}

func TestReadJSON_ReadError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	mock.EXPECT().Read(gomock.Any()).
		Return(websocket.MessageType(0), nil, fmt.Errorf("EOF"))

	var got InitResponse

	err := sc.readJSON(context.Background(), &got)
	assert.ErrorContains(t, err, "reading message")
}

func TestReadJSON_MalformedJSON(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	mock.EXPECT().Read(gomock.Any()).
		Return(websocket.MessageText, []byte(`{broken`), nil)

	var got InitResponse

	err := sc.readJSON(context.Background(), &got)
	assert.Error(t, err)
}

// --- WaitForReady tests ---

func TestWaitForReady_ImmediateReady(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)
	sc.version = 100

	ready := `{"op":"ready","version":200}`
	mock.EXPECT().Read(gomock.Any()).
		Return(websocket.MessageText, []byte(ready), nil)

	var pushes []ServerPush

	err := sc.WaitForReady(context.Background(), &pushes)
	require.NoError(t, err)
	assert.Equal(t, int64(200), sc.version)
	assert.Empty(t, pushes)
	assert.False(t, sc.initial)
}

func TestWaitForReady_ReadyDoesNotDowngradeVersion(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)
	sc.version = 500

	// Server sends a ready with a lower version than we already have.
	// This can happen if we received pushes during the catch-up window
	// that advanced our version beyond the ready message.
	ready := `{"op":"ready","version":300}`
	mock.EXPECT().Read(gomock.Any()).
		Return(websocket.MessageText, []byte(ready), nil)

	var pushes []ServerPush

	err := sc.WaitForReady(context.Background(), &pushes)
	require.NoError(t, err)
	assert.Equal(t, int64(500), sc.version, "version should not be downgraded")
}

func TestWaitForReady_BinaryFrameSkipped(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// Binary frame arrives before ready -- should be skipped.
	gomock.InOrder(
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageBinary, []byte{0x01, 0x02}, nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"ready","version":1}`), nil),
	)

	var pushes []ServerPush

	err := sc.WaitForReady(context.Background(), &pushes)
	require.NoError(t, err)
}

func TestWaitForReady_PongSkipped(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	gomock.InOrder(
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"pong"}`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"ready","version":10}`), nil),
	)

	var pushes []ServerPush

	err := sc.WaitForReady(context.Background(), &pushes)
	require.NoError(t, err)
}

func TestWaitForReady_UnknownOpSkipped(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	gomock.InOrder(
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"something_new"}`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"ready","version":5}`), nil),
	)

	var pushes []ServerPush

	err := sc.WaitForReady(context.Background(), &pushes)
	require.NoError(t, err)
}

func TestWaitForReady_MalformedTextSkipped(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// Unparseable JSON should be skipped, not fatal.
	gomock.InOrder(
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`not json at all`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"ready","version":1}`), nil),
	)

	var pushes []ServerPush

	err := sc.WaitForReady(context.Background(), &pushes)
	require.NoError(t, err)
}

func TestWaitForReady_MalformedReadyIsFatal(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// The op field parses fine but the full ready message is broken.
	// This should be a fatal error since we can't extract the version.
	ready := `{"op":"ready","version":"not_a_number"}`
	mock.EXPECT().Read(gomock.Any()).
		Return(websocket.MessageText, []byte(ready), nil)

	var pushes []ServerPush

	err := sc.WaitForReady(context.Background(), &pushes)
	assert.ErrorContains(t, err, "decoding ready message")
}

func TestWaitForReady_ReadErrorIsFatal(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	mock.EXPECT().Read(gomock.Any()).
		Return(websocket.MessageType(0), nil, fmt.Errorf("connection closed"))

	var pushes []ServerPush

	err := sc.WaitForReady(context.Background(), &pushes)
	assert.ErrorContains(t, err, "reading message")
	assert.ErrorContains(t, err, "connection closed")
}

func TestWaitForReady_ReadErrorAfterPushes(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// Server sends a push (which will fail decryption since we have no
	// cipher), then the connection dies. The push should be skipped due
	// to decryption failure, and the read error should be returned.
	gomock.InOrder(
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"push","uid":100,"path":"enc"}`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageType(0), nil, fmt.Errorf("unexpected EOF")),
	)

	var pushes []ServerPush

	err := sc.WaitForReady(context.Background(), &pushes)
	assert.ErrorContains(t, err, "unexpected EOF")
	// Push should not have been appended (decryption failed, no cipher).
	assert.Empty(t, pushes)
}

func TestWaitForReady_PushWithBadJSONSkipped(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// The op field says "push" but the rest is not valid PushMessage JSON.
	// GenericMessage will parse fine, but PushMessage unmarshal may fail
	// or produce zero values. Either way, the push decryption will fail
	// and the message should be skipped.
	gomock.InOrder(
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"push","uid":"not_a_number"}`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"ready","version":1}`), nil),
	)

	var pushes []ServerPush

	err := sc.WaitForReady(context.Background(), &pushes)
	require.NoError(t, err)
	assert.Empty(t, pushes)
}

func TestWaitForReady_PushAdvancesVersion(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)
	sc.version = 50

	// Push with UID 200 should advance version even though decryption
	// will fail (no cipher). The version update happens before decryption.
	gomock.InOrder(
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"push","uid":200,"path":"enc"}`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"ready","version":150}`), nil),
	)

	var pushes []ServerPush

	err := sc.WaitForReady(context.Background(), &pushes)
	require.NoError(t, err)
	// Version should be 200 from the push, not 150 from ready (200 > 150).
	assert.Equal(t, int64(200), sc.version)
}

func TestWaitForReady_MultipleMessagesBeforeReady(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// Simulate a realistic init->ready window: binary garbage, pong,
	// malformed text, unknown op, push (fails decrypt), then ready.
	gomock.InOrder(
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageBinary, []byte{0xFF}, nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"pong"}`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`garbage`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"unknown_future_op"}`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"push","uid":10,"path":"x"}`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"ready","version":10}`), nil),
	)

	var pushes []ServerPush

	err := sc.WaitForReady(context.Background(), &pushes)
	require.NoError(t, err)
	assert.Equal(t, int64(10), sc.version)
}

func TestWaitForReady_ContextCancelled(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mock.EXPECT().Read(gomock.Any()).
		Return(websocket.MessageType(0), nil, ctx.Err())

	var pushes []ServerPush

	err := sc.WaitForReady(ctx, &pushes)
	assert.Error(t, err)
}

// --- pullDirect tests ---

func TestPullDirect_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	pullReq, _ := json.Marshal(PullRequest{Op: "pull", UID: 42})
	pullResp := `{"size":10,"pieces":1,"deleted":false}`
	binaryData := []byte("0123456789")

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, pullReq).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(pullResp), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageBinary, binaryData, nil),
	)

	content, err := sc.pullDirect(context.Background(), 42)
	require.NoError(t, err)
	assert.Equal(t, binaryData, content)
}

func TestPullDirect_MultipleChunks(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	pullReq, _ := json.Marshal(PullRequest{Op: "pull", UID: 1})
	// Size must be large enough that pieces=2 passes validation.
	// maxPieces = size/chunkSize + 1 = 3000000/2097152 + 1 = 2.
	pullResp := `{"size":3000000,"pieces":2,"deleted":false}`
	chunk1 := []byte("abc")
	chunk2 := []byte("def")

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, pullReq).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(pullResp), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageBinary, chunk1, nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageBinary, chunk2, nil),
	)

	content, err := sc.pullDirect(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("abcdef"), content)
}

func TestPullDirect_DeletedResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	pullReq, _ := json.Marshal(PullRequest{Op: "pull", UID: 99})

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, pullReq).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"size":0,"pieces":0,"deleted":true}`), nil),
	)

	content, err := sc.pullDirect(context.Background(), 99)
	assert.NoError(t, err)
	assert.Nil(t, content)
}

func TestPullDirect_WriteError(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).
		Return(fmt.Errorf("broken pipe"))

	_, err := sc.pullDirect(context.Background(), 1)
	assert.ErrorContains(t, err, "sending pull request")
}

func TestPullDirect_ReadErrorDuringResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageType(0), nil, fmt.Errorf("connection reset")),
	)

	_, err := sc.pullDirect(context.Background(), 1)
	assert.ErrorContains(t, err, "reading pull response")
}

func TestPullDirect_ReadErrorDuringPieces(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// Size must justify 3 pieces: maxPieces = 5000000/2097152 + 1 = 3.
	pullResp := `{"size":5000000,"pieces":3,"deleted":false}`

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(pullResp), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageBinary, []byte("chunk1"), nil),
		// Connection dies during second piece.
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageType(0), nil, fmt.Errorf("EOF")),
	)

	_, err := sc.pullDirect(context.Background(), 1)
	assert.ErrorContains(t, err, "reading piece 2/3")
}

func TestPullDirect_OversizedResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)
	sc.perFileMax = 1024

	// Server claims a size far exceeding the per-file limit.
	pullResp := `{"size":999999,"pieces":1,"deleted":false}`

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(pullResp), nil),
	)

	_, err := sc.pullDirect(context.Background(), 1)
	assert.ErrorContains(t, err, "exceeds limit")
}

func TestPullDirect_BadPiecesCount(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// Size is 10, so max pieces = 10/2097152 + 1 = 1. Claiming 5 is invalid.
	pullResp := `{"size":10,"pieces":5,"deleted":false}`

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(pullResp), nil),
	)

	_, err := sc.pullDirect(context.Background(), 1)
	assert.ErrorContains(t, err, "out of range")
}

func TestPullDirect_NegativePiecesCount(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	pullResp := `{"size":10,"pieces":-1,"deleted":false}`

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(pullResp), nil),
	)

	_, err := sc.pullDirect(context.Background(), 1)
	assert.ErrorContains(t, err, "out of range")
}

func TestPullDirect_MalformedPullResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"size":"not_int"}`), nil),
	)

	_, err := sc.pullDirect(context.Background(), 1)
	assert.ErrorContains(t, err, "decoding pull response")
}

func TestPullDirect_PongBeforeResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// Protocol doc: pong can arrive at any time. During pull response
	// wait, pongs should be silently consumed.
	pullReq, _ := json.Marshal(PullRequest{Op: "pull", UID: 1})
	pullResp := `{"size":5,"pieces":1,"deleted":false}`

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, pullReq).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"pong"}`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(pullResp), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageBinary, []byte("hello"), nil),
	)

	content, err := sc.pullDirect(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), content)
}

func TestPullDirect_PushBeforeResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// A server push can arrive while we're waiting for the pull response.
	// Per protocol doc, pushes are processed inline (handlePushWhileBusy)
	// and the pull continues. The push will fail to decode without cipher
	// but should not break the pull flow.
	pullResp := `{"size":3,"pieces":1,"deleted":false}`

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"push","uid":500,"path":"enc"}`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(pullResp), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageBinary, []byte("abc"), nil),
	)

	content, err := sc.pullDirect(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("abc"), content)
}

func TestPullDirect_BinaryFrameBeforeResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// Binary frame arriving before the text pull response is unexpected
	// but should be skipped (logged at debug).
	pullResp := `{"size":2,"pieces":1,"deleted":false}`

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageBinary, []byte{0xFF, 0xFE}, nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(pullResp), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageBinary, []byte("ab"), nil),
	)

	content, err := sc.pullDirect(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("ab"), content)
}

func TestPullDirect_PongBetweenPieces(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// Protocol doc line 972: "pings bypass this queue and are sent
	// directly on the socket via setInterval. The server tolerates pings
	// arriving between binary chunks during a push sequence." The same
	// applies to pong responses arriving between binary chunks during pull.
	// Size must justify 2 pieces: maxPieces = 3000000/2097152 + 1 = 2.
	pullResp := `{"size":3000000,"pieces":2,"deleted":false}`

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(pullResp), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageBinary, []byte("abc"), nil),
		// Pong arrives between piece 1 and piece 2.
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"pong"}`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageBinary, []byte("def"), nil),
	)

	content, err := sc.pullDirect(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("abcdef"), content)
}

func TestPullDirect_PushBetweenPieces(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// A server push can arrive between binary pieces. It should be
	// processed via handlePushWhileBusy and the piece counter retried.
	// Path "x" fails hex decode, so decryption fails gracefully.
	// Size must justify 2 pieces: maxPieces = 3000000/2097152 + 1 = 2.
	pullResp := `{"size":3000000,"pieces":2,"deleted":false}`

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(pullResp), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageBinary, []byte("abc"), nil),
		// Push arrives between pieces.
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"push","uid":999,"path":"x"}`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageBinary, []byte("def"), nil),
	)

	content, err := sc.pullDirect(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("abcdef"), content)
}

func TestPullDirect_UnexpectedTextDuringPieces(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// A text frame that is not a pong or push during binary piece reading
	// is a protocol violation and should be fatal.
	pullResp := `{"size":10,"pieces":1,"deleted":false}`

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(pullResp), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"something_unexpected"}`), nil),
	)

	_, err := sc.pullDirect(context.Background(), 1)
	assert.ErrorContains(t, err, "expected binary frame, got text")
}

func TestPullDirect_ZeroPieces(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// Zero pieces, zero size -- empty file. No binary reads should happen.
	pullResp := `{"size":0,"pieces":0,"deleted":false}`

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(pullResp), nil),
	)

	content, err := sc.pullDirect(context.Background(), 1)
	require.NoError(t, err)
	assert.Empty(t, content)
}

func TestPullDirect_MultiplePongsAndPushesInterleaved(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)

	// Stress test: multiple pongs and pushes interleaved throughout the
	// entire pull sequence. This verifies the retry counter (i--) works
	// correctly across multiple interleaved messages.
	pullResp := `{"size":3,"pieces":1,"deleted":false}`

	gomock.InOrder(
		mock.EXPECT().Write(gomock.Any(), websocket.MessageText, gomock.Any()).Return(nil),
		// Before response: 2 pongs and a push.
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"pong"}`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"push","uid":1,"path":"a"}`), nil),
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"pong"}`), nil),
		// Actual response.
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(pullResp), nil),
		// Between response and binary: pong.
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"pong"}`), nil),
		// Another push between.
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageText, []byte(`{"op":"push","uid":2,"path":"b"}`), nil),
		// The actual binary data.
		mock.EXPECT().Read(gomock.Any()).
			Return(websocket.MessageBinary, []byte("xyz"), nil),
	)

	content, err := sc.pullDirect(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("xyz"), content)
}

// --- readResponse tests (operates via inboundCh) ---

func TestReadResponse_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	_ = ctrl
	sc := newTestSyncClient(t, nil)
	sc.inboundCh = make(chan inboundMsg, 1)

	resp := `{"res":"ok"}`
	sc.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(resp)}

	got, err := sc.readResponse(context.Background())
	require.NoError(t, err)
	assert.JSONEq(t, resp, string(got))
}

func TestReadResponse_BinaryFrameSkipped(t *testing.T) {
	sc := newTestSyncClient(t, nil)
	sc.inboundCh = make(chan inboundMsg, 2)

	sc.inboundCh <- inboundMsg{typ: websocket.MessageBinary, data: []byte{0x01}}

	sc.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(`{"res":"ok"}`)}

	got, err := sc.readResponse(context.Background())
	require.NoError(t, err)
	assert.JSONEq(t, `{"res":"ok"}`, string(got))
}

func TestReadResponse_PongSkipped(t *testing.T) {
	sc := newTestSyncClient(t, nil)
	sc.inboundCh = make(chan inboundMsg, 2)

	sc.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(`{"op":"pong"}`)}

	sc.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(`{"res":"ok"}`)}

	got, err := sc.readResponse(context.Background())
	require.NoError(t, err)
	assert.JSONEq(t, `{"res":"ok"}`, string(got))
}

func TestReadResponse_PushProcessedInline(t *testing.T) {
	sc := newTestSyncClient(t, nil)
	sc.inboundCh = make(chan inboundMsg, 2)

	// Push arrives while waiting for a response. handlePushWhileBusy will
	// be called (and will fail to decrypt without cipher, but that's fine --
	// the point is the push doesn't break the response loop).
	// Path "x" is not valid hex, so DecryptPath fails before reaching the nil cipher.
	sc.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(`{"op":"push","uid":1,"path":"x"}`)}

	sc.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(`{"res":"ok"}`)}

	got, err := sc.readResponse(context.Background())
	require.NoError(t, err)
	assert.JSONEq(t, `{"res":"ok"}`, string(got))
}

func TestReadResponse_ReadError(t *testing.T) {
	sc := newTestSyncClient(t, nil)
	sc.inboundCh = make(chan inboundMsg, 1)

	sc.inboundCh <- inboundMsg{err: fmt.Errorf("connection lost")}

	_, err := sc.readResponse(context.Background())
	assert.ErrorContains(t, err, "reading response")
	assert.ErrorContains(t, err, "connection lost")
}

func TestReadResponse_ContextCancelled(t *testing.T) {
	sc := newTestSyncClient(t, nil)
	sc.inboundCh = make(chan inboundMsg) // unbuffered, will block

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := sc.readResponse(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestReadResponse_MultiplePongsAndPushesThenResponse(t *testing.T) {
	sc := newTestSyncClient(t, nil)
	sc.inboundCh = make(chan inboundMsg, 5)

	sc.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(`{"op":"pong"}`)}

	sc.inboundCh <- inboundMsg{typ: websocket.MessageBinary, data: []byte{0xFF}}

	sc.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(`{"op":"push","uid":1,"path":"x"}`)}

	sc.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(`{"op":"pong"}`)}

	sc.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte(`{"res":"next"}`)}

	got, err := sc.readResponse(context.Background())
	require.NoError(t, err)
	assert.JSONEq(t, `{"res":"next"}`, string(got))
}

// --- readInbound tests ---

func TestReadInbound_Success(t *testing.T) {
	sc := newTestSyncClient(t, nil)
	sc.inboundCh = make(chan inboundMsg, 1)

	sc.inboundCh <- inboundMsg{typ: websocket.MessageText, data: []byte("hello")}

	msg, err := sc.readInbound(context.Background())
	require.NoError(t, err)
	assert.Equal(t, websocket.MessageText, msg.typ)
	assert.Equal(t, []byte("hello"), msg.data)
}

func TestReadInbound_Error(t *testing.T) {
	sc := newTestSyncClient(t, nil)
	sc.inboundCh = make(chan inboundMsg, 1)

	sc.inboundCh <- inboundMsg{err: fmt.Errorf("read failed")}

	_, err := sc.readInbound(context.Background())
	assert.ErrorContains(t, err, "read failed")
}

func TestReadInbound_ContextCancelled(t *testing.T) {
	sc := newTestSyncClient(t, nil)
	sc.inboundCh = make(chan inboundMsg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := sc.readInbound(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

// --- handleInbound tests ---

func TestHandleInbound_PongReturnsNil(t *testing.T) {
	sc := newTestSyncClient(t, nil)

	err := sc.handleInbound(context.Background(), []byte(`{"op":"pong"}`))
	assert.NoError(t, err)
}

func TestHandleInbound_UnknownOpReturnsNil(t *testing.T) {
	sc := newTestSyncClient(t, nil)

	err := sc.handleInbound(context.Background(), []byte(`{"op":"future_op"}`))
	assert.NoError(t, err)
}

func TestHandleInbound_MalformedJSONReturnsNil(t *testing.T) {
	sc := newTestSyncClient(t, nil)

	// Malformed JSON should be logged but not return an error.
	// handleInbound swallows parse errors to avoid killing the event loop.
	err := sc.handleInbound(context.Background(), []byte(`not json`))
	assert.NoError(t, err)
}

func TestHandleInbound_PushUpdatesVersion(t *testing.T) {
	sc := newTestSyncClient(t, nil)
	sc.version = 10

	// Push with higher UID should update version. processPush will fail
	// without cipher, but the version update happens before processPush.
	err := sc.handleInbound(context.Background(), []byte(`{"op":"push","uid":50,"path":"enc"}`))
	assert.NoError(t, err)
	assert.Equal(t, int64(50), sc.version)
	assert.True(t, sc.versionDirty)
}

func TestHandleInbound_PushDoesNotDowngradeVersion(t *testing.T) {
	sc := newTestSyncClient(t, nil)
	sc.version = 100

	err := sc.handleInbound(context.Background(), []byte(`{"op":"push","uid":50,"path":"enc"}`))
	assert.NoError(t, err)
	assert.Equal(t, int64(100), sc.version)
}

func TestHandleInbound_PushWithBadJSONReturnsNil(t *testing.T) {
	sc := newTestSyncClient(t, nil)

	// The op parses as "push" via GenericMessage, but PushMessage decode
	// fails. Should log a warning but not return an error.
	err := sc.handleInbound(context.Background(), []byte(`{"op":"push","uid":"bad"}`))
	assert.NoError(t, err)
}

// --- readResponse: timeout (synctest) ---

func TestReadResponse_Timeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sc := newTestSyncClient(t, nil)
		sc.inboundCh = make(chan inboundMsg) // unbuffered, will block

		_, err := sc.readResponse(t.Context())
		assert.ErrorIs(t, err, errResponseTimeout)
	})
}

// --- WaitForReady: onReady callback ---

func TestWaitForReady_CallsOnReady(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	sc := newTestSyncClient(t, mock)
	sc.version = 0

	var calledWith int64

	sc.onReady = func(v int64) { calledWith = v }

	ready := `{"op":"ready","version":42}`
	mock.EXPECT().Read(gomock.Any()).
		Return(websocket.MessageText, []byte(ready), nil)

	var pushes []ServerPush

	err := sc.WaitForReady(context.Background(), &pushes)
	require.NoError(t, err)
	assert.Equal(t, int64(42), calledWith)
}

// --- WaitForReady: decrypt error on push is logged and skipped ---

func TestWaitForReady_DecryptPushError_Skipped(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockWSConn(ctrl)
	// Use newTestSyncClient which has no cipher, so decryptPush will fail.
	sc := newTestSyncClient(t, mock)

	// Send a push with valid JSON but undecryptable path, then ready.
	push := `{"op":"push","uid":10,"path":"validhexbutbadcipher"}`
	ready := `{"op":"ready","version":10}`
	gomock.InOrder(
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, []byte(push), nil),
		mock.EXPECT().Read(gomock.Any()).Return(websocket.MessageText, []byte(ready), nil),
	)

	var pushes []ServerPush

	err := sc.WaitForReady(context.Background(), &pushes)
	require.NoError(t, err)
	// Push should be skipped (decryption fails), not appended.
	assert.Empty(t, pushes)
	// Version should still be updated from the push.
	assert.Equal(t, int64(10), sc.version)
}

// --- readInbound: timeout (synctest) ---

func TestReadInbound_Timeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sc := newTestSyncClient(t, nil)
		sc.inboundCh = make(chan inboundMsg) // unbuffered, will block

		_, err := sc.readInbound(t.Context())
		assert.ErrorIs(t, err, errResponseTimeout)
	})
}
