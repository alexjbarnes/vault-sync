package obsidian

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/state"
	"github.com/coder/websocket"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/tidwall/gjson"
)

const (
	pingAfter        = 10 * time.Second
	disconnectAfter  = 120 * time.Second
	heartbeatCheckAt = 20 * time.Second
	chunkSize        = 2097152 // 2MB

	reconnectMin    = 5 * time.Second
	reconnectMax    = 5 * time.Minute
	responseTimeout = 60 * time.Second
)

var errResponseTimeout = fmt.Errorf("timed out waiting for server response")

// inboundMsg wraps a message read from the WebSocket by the reader goroutine.
type inboundMsg struct {
	typ  websocket.MessageType
	data []byte
	err  error
}

// syncOp is an operation submitted to the event loop by the watcher.
type syncOp struct {
	path      string
	content   []byte
	mtime     int64
	ctime     int64
	isFolder  bool
	isDeleted bool
	result    chan error
}

// wsConn abstracts the WebSocket connection so SyncClient can be tested
// without a real server. *websocket.Conn satisfies this interface.
type wsConn interface {
	Read(ctx context.Context) (websocket.MessageType, []byte, error)
	Write(ctx context.Context, typ websocket.MessageType, p []byte) error
	Close(code websocket.StatusCode, reason string) error
	SetReadLimit(n int64)
}

// SyncClient manages a WebSocket connection to an Obsidian Sync server.
//
// Architecture: a reader goroutine feeds inboundCh with raw WebSocket
// messages. A single event loop goroutine (Listen) processes inbound
// messages, watcher operations (opCh), and heartbeat ticks. All writes
// to the connection happen from the event loop, eliminating the need
// for a write mutex and preventing deadlocks between push and pull.
type SyncClient struct {
	conn   wsConn
	logger *slog.Logger

	host              string
	token             string
	vaultID           string
	keyHash           string
	device            string
	encryptionVersion int
	version           int64
	initial           bool

	cipher     *CipherV0
	vault      *Vault
	state      *state.State
	perFileMax int

	onReady func(version int64)

	// opCh receives push operations from the watcher goroutine.
	// The event loop processes them one at a time.
	opCh chan syncOp

	// inboundCh receives messages from the reader goroutine.
	inboundCh chan inboundMsg

	// Hash cache for deduplication. Keyed by relative path.
	// encHash: encrypted hash from the wire (for outbound echo comparison).
	// contentHash: hex(SHA-256(plaintext)) (for inbound echo from watcher).
	hashCache   map[string]hashEntry
	hashCacheMu sync.Mutex

	lastMessage time.Time
	lastMsgMu   sync.Mutex

	// connCancel cancels the per-connection context. Used to stop the
	// reader goroutine when the connection drops before reconnecting.
	connCancel context.CancelFunc

	// connected signals whether the WebSocket is live. The watcher checks
	// this to decide whether to push or queue.
	connected   bool
	connectedMu sync.RWMutex

	// pendingPulls holds server pushes that need content but arrived while
	// the event loop was busy with another operation. Only accessed from
	// the event loop goroutine, but the mutex is here because
	// handlePushWhileBusy is called from readResponse during operations.
	pendingPulls   []pendingPull
	pendingPullsMu sync.Mutex

	// retryBackoff tracks per-path retry state for failed operations.
	// app.js uses: delay = 5s * 2^count, capped at 5 minutes.
	retryBackoff   map[string]retryEntry
	retryBackoffMu sync.Mutex

	// versionDirty tracks whether s.version was updated since the last
	// persist. The event loop persists periodically (matching the
	// Obsidian app's debounced saveData behavior).
	versionDirty bool
}

type hashEntry struct {
	encHash     string
	contentHash string
}

type retryEntry struct {
	count       int
	lastFailure time.Time
}

// SyncConfig holds the parameters needed to connect to a sync server.
type SyncConfig struct {
	Host              string
	Token             string
	VaultID           string
	KeyHash           string
	Device            string
	EncryptionVersion int
	Version           int64
	Initial           bool
	Cipher            *CipherV0
	Vault             *Vault
	State             *state.State
	OnReady           func(version int64)
}

func NewSyncClient(cfg SyncConfig, logger *slog.Logger) *SyncClient {
	return &SyncClient{
		logger:            logger,
		host:              cfg.Host,
		token:             cfg.Token,
		vaultID:           cfg.VaultID,
		keyHash:           cfg.KeyHash,
		device:            cfg.Device,
		encryptionVersion: cfg.EncryptionVersion,
		version:           cfg.Version,
		initial:           cfg.Initial,
		cipher:            cfg.Cipher,
		vault:             cfg.Vault,
		state:             cfg.State,
		onReady:           cfg.OnReady,
		perFileMax:        208_666_624, // ~199MB, matches Obsidian client default
		opCh:              make(chan syncOp, 64),
		hashCache:         make(map[string]hashEntry),
		retryBackoff:      make(map[string]retryEntry),
	}
}

// Connect dials the WebSocket, sends init, and waits for auth confirmation.
func (s *SyncClient) Connect(ctx context.Context) error {
	// Cancel any previous reader goroutine from a prior connection.
	if s.connCancel != nil {
		s.connCancel()
	}

	url := "wss://" + s.host
	s.logger.Debug("connecting", slog.String("url", url))

	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Origin":     []string{"app://obsidian.md"},
			"User-Agent": []string{"Mozilla/5.0 obsidian/1.7.7"},
		},
	})
	if err != nil {
		return fmt.Errorf("dialing websocket: %w", err)
	}

	return s.handshake(ctx, conn)
}

// handshake performs the post-dial init/auth sequence. Extracted from
// Connect so the auth logic can be tested with a mock wsConn without
// needing a real network connection.
func (s *SyncClient) handshake(ctx context.Context, conn wsConn) error {
	s.conn = conn
	// Set a conservative initial read limit. Updated after auth when we
	// know perFileMax. Encrypted content adds overhead (IV + GCM tag)
	// so 16MB covers the default 5MB perFileMax with headroom.
	s.conn.SetReadLimit(16 * 1024 * 1024)
	s.touchLastMessage()

	init := InitMessage{
		Op:                "init",
		Token:             s.token,
		ID:                s.vaultID,
		KeyHash:           s.keyHash,
		Version:           s.version,
		Initial:           s.initial,
		Device:            s.device,
		EncryptionVersion: s.encryptionVersion,
	}

	if err := s.writeJSON(ctx, init); err != nil {
		s.conn.Close(websocket.StatusInternalError, "init failed")
		return fmt.Errorf("sending init: %w", err)
	}

	// Read auth response. This happens before Listen starts, so we read
	// directly without going through the event loop.
	var initResp InitResponse
	if err := s.readJSON(ctx, &initResp); err != nil {
		s.conn.Close(websocket.StatusInternalError, "auth read failed")
		return fmt.Errorf("reading auth response: %w", err)
	}

	if initResp.Res != "ok" {
		msg := initResp.Msg
		if msg == "" {
			msg = initResp.Res
		}
		s.conn.Close(websocket.StatusNormalClosure, "auth failed")
		return fmt.Errorf("auth failed: %s", msg)
	}

	// Only update perFileMax if the server sent a positive value.
	// If the server omits the field, Go defaults to 0 and we keep the
	// client default (208MB) rather than disabling the size limit.
	if initResp.PerFileMax > 0 {
		s.perFileMax = initResp.PerFileMax
	}
	// Tighten read limit now that we know the max file size. Allow 2x
	// for encryption overhead, minimum 4MB for metadata-heavy responses.
	readLimit := int64(s.perFileMax * 2)
	if readLimit < 4*1024*1024 {
		readLimit = 4 * 1024 * 1024
	}
	s.conn.SetReadLimit(readLimit)
	s.logger.Info("websocket authenticated",
		slog.Int("user_id", initResp.UserID),
		slog.Int("per_file_max", initResp.PerFileMax),
	)
	return nil
}

// WaitForReady reads from the WebSocket until the server sends "ready".
// Server pushes received before ready are decrypted and appended to
// serverPushes. After ready returns, no goroutine is reading the
// connection, so the caller can use pull() directly for reconciliation.
func (s *SyncClient) WaitForReady(ctx context.Context, serverPushes *[]ServerPush) error {
	// Send pings during the catch-up window so the server doesn't
	// timeout our connection while replaying missed pushes.
	pingTicker := time.NewTicker(heartbeatCheckAt)
	pingDone := make(chan struct{})
	var pingWg sync.WaitGroup
	pingWg.Add(1)
	defer func() {
		pingTicker.Stop()
		close(pingDone)
		pingWg.Wait()
	}()
	go func() {
		defer pingWg.Done()
		for {
			select {
			case <-pingDone:
				return
			case <-ctx.Done():
				return
			case <-pingTicker.C:
				// Re-check pingDone before writing so we don't race
				// with the caller after WaitForReady returns.
				select {
				case <-pingDone:
					return
				default:
				}
				s.lastMsgMu.Lock()
				elapsed := time.Since(s.lastMessage)
				s.lastMsgMu.Unlock()
				if elapsed > pingAfter {
					s.writeJSON(ctx, map[string]string{"op": "ping"})
				}
			}
		}
	}()

	for {
		typ, data, err := s.conn.Read(ctx)
		if err != nil {
			return fmt.Errorf("reading message: %w", err)
		}
		s.touchLastMessage()

		if typ == websocket.MessageBinary {
			s.logger.Debug("unexpected binary frame before ready", slog.Int("bytes", len(data)))
			continue
		}

		var msg GenericMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			s.logger.Debug("unparseable text frame", slog.Int("bytes", len(data)))
			continue
		}

		switch msg.Op {
		case "pong":
			continue

		case "ready":
			var readyMsg ReadyMessage
			if err := json.Unmarshal(data, &readyMsg); err != nil {
				return fmt.Errorf("decoding ready message: %w", err)
			}
			if readyMsg.Version > s.version {
				s.version = readyMsg.Version
			}
			s.initial = false
			s.setConnected(true)
			s.logger.Info("server ready",
				slog.Int64("version", readyMsg.Version),
				slog.Int("queued_pushes", len(*serverPushes)),
			)

			if s.onReady != nil {
				s.onReady(s.version)
			}
			return nil

		case "push":
			var push PushMessage
			if err := json.Unmarshal(data, &push); err != nil {
				s.logger.Warn("failed to decode push", slog.String("error", err.Error()))
				continue
			}
			if push.UID > s.version {
				s.version = push.UID
			}
			sp, err := s.decryptPush(push)
			if err != nil {
				s.logger.Warn("decrypting queued push",
					slog.Int64("uid", push.UID),
					slog.String("error", err.Error()),
				)
				continue
			}
			*serverPushes = append(*serverPushes, sp)

		default:
			s.logger.Debug("unexpected message before ready", slog.String("op", msg.Op))
		}
	}
}

// startReader launches a goroutine that reads from the WebSocket and
// feeds inboundCh. Exits when connCtx is cancelled or a read error
// occurs. The error is delivered as the final message on inboundCh.
// The goroutine captures ch by value so that if startReader is called
// again for a new connection, the old goroutine cannot send stale
// messages into the new channel.
func (s *SyncClient) startReader(connCtx context.Context) {
	ch := make(chan inboundMsg, 64)
	s.inboundCh = ch
	go func() {
		for {
			typ, data, err := s.conn.Read(connCtx)
			select {
			case ch <- inboundMsg{typ: typ, data: data, err: err}:
			case <-connCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
}

// Listen is the event loop with automatic reconnection. It owns all
// writes to the connection. Processes inbound messages (server pushes,
// acks), watcher operations (pushes), and heartbeat ticks. Returns only
// on permanent errors or context cancellation.
func (s *SyncClient) Listen(ctx context.Context) error {
	backoff := reconnectMin

	connCtx, connCancel := context.WithCancel(ctx)
	s.connCancel = connCancel
	s.startReader(connCtx)

	for {
		err := s.eventLoop(ctx, connCtx)
		if err == nil {
			return nil
		}

		s.setConnected(false)
		connCancel()

		if ctx.Err() != nil {
			return ctx.Err()
		}
		if isPermanentError(err) {
			return fmt.Errorf("permanent error: %w", err)
		}

		s.logger.Warn("connection lost, reconnecting",
			slog.String("error", err.Error()),
			slog.Duration("backoff", backoff),
		)

		jitter := time.Duration(rand.Int64N(int64(backoff) / 2))
		timer := time.NewTimer(backoff + jitter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}

		if err := s.reconnect(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if isPermanentError(err) {
				return fmt.Errorf("permanent reconnect error: %w", err)
			}
			s.logger.Warn("reconnect failed",
				slog.String("error", err.Error()),
				slog.Duration("backoff", backoff),
			)
			backoff = min(backoff*2, reconnectMax)
			continue
		}

		// Fresh connection context and reader for the new connection.
		connCtx, connCancel = context.WithCancel(ctx)
		s.connCancel = connCancel
		s.startReader(connCtx)

		backoff = reconnectMin
		s.logger.Info("reconnected")
	}
}

// eventLoop is the single event loop for one connection. It selects on
// inbound messages, watcher operations, and the heartbeat ticker. All
// writes happen here, so no mutex is needed. Returns on read error or
// context cancellation.
func (s *SyncClient) eventLoop(ctx context.Context, connCtx context.Context) error {
	ticker := time.NewTicker(heartbeatCheckAt)
	defer ticker.Stop()

	for {
		select {
		case msg := <-s.inboundCh:
			if msg.err != nil {
				return fmt.Errorf("reading message: %w", msg.err)
			}
			s.touchLastMessage()

			if msg.typ == websocket.MessageBinary {
				s.logger.Debug("unexpected binary frame in event loop", slog.Int("bytes", len(msg.data)))
				continue
			}

			if err := s.handleInbound(ctx, msg.data); err != nil {
				return err
			}
			s.drainPendingPulls(ctx)

		case op := <-s.opCh:
			if err := s.handlePushOp(ctx, op); err != nil {
				// Connection error during push. The op already got
				// its result. Return to trigger reconnect.
				return err
			}
			s.drainPendingPulls(ctx)

		case <-ticker.C:
			s.lastMsgMu.Lock()
			elapsed := time.Since(s.lastMessage)
			s.lastMsgMu.Unlock()

			if elapsed > disconnectAfter {
				s.persistVersionIfDirty()
				s.logger.Warn("connection timed out, closing")
				s.conn.Close(websocket.StatusGoingAway, "timeout")
				return fmt.Errorf("heartbeat timeout")
			}

			if elapsed > pingAfter {
				if err := s.writeJSON(ctx, map[string]string{"op": "ping"}); err != nil {
					return fmt.Errorf("sending ping: %w", err)
				}
			}

			s.persistVersionIfDirty()

		case <-ctx.Done():
			s.persistVersionIfDirty()
			return ctx.Err()

		case <-connCtx.Done():
			s.persistVersionIfDirty()
			return connCtx.Err()
		}
	}
}

// handleInbound processes a single inbound text message from the server.
func (s *SyncClient) handleInbound(ctx context.Context, data []byte) error {
	var msg GenericMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		s.logger.Debug("unparseable text frame", slog.Int("bytes", len(data)))
		return nil
	}

	switch msg.Op {
	case "pong":
		return nil

	case "push":
		var push PushMessage
		if err := json.Unmarshal(data, &push); err != nil {
			s.logger.Warn("failed to decode push", slog.String("error", err.Error()))
			return nil
		}
		if push.UID > s.version {
			s.version = push.UID
			s.versionDirty = true
		}
		if err := s.processPush(ctx, push); err != nil {
			s.logger.Warn("processing push",
				slog.Int64("uid", push.UID),
				slog.String("error", err.Error()),
			)
		}
		return nil

	default:
		// Unexpected message outside of a push/pull operation.
		s.logger.Debug("unexpected message in event loop", slog.String("op", msg.Op))
		return nil
	}
}

// handlePushOp executes a watcher push operation from the event loop.
// All writes and reads happen inline. Returns a connection-level error
// if the write fails (triggers reconnect). Operation-level errors are
// sent to op.result.
func (s *SyncClient) handlePushOp(ctx context.Context, op syncOp) error {
	err := s.executePush(ctx, op)
	op.result <- err
	// Distinguish connection errors from operation errors. If the
	// connection is dead, return the error to trigger reconnect.
	if err != nil && !s.isOperationError(err) {
		return err
	}
	return nil
}

// executePush does the actual push protocol sequence from the event loop.
func (s *SyncClient) executePush(ctx context.Context, op syncOp) error {
	// Check per-path retry backoff.
	if backoff, ok := s.checkRetryBackoff(op.path); ok {
		s.logger.Debug("skipping push in retry backoff",
			slog.String("path", op.path),
			slog.Duration("wait", time.Until(backoff)),
		)
		return nil
	}

	encPath, err := s.cipher.EncryptPath(op.path)
	if err != nil {
		s.recordRetryBackoff(op.path)
		return fmt.Errorf("encrypting path: %w", err)
	}

	ext := ""
	if !op.isFolder {
		base := op.path
		if slashIdx := strings.LastIndex(op.path, "/"); slashIdx >= 0 {
			base = op.path[slashIdx+1:]
		}
		if dotIdx := strings.LastIndex(base, "."); dotIdx > 0 && dotIdx < len(base)-1 {
			ext = strings.ToLower(base[dotIdx+1:])
		}
	}

	// Folders and deletions: metadata only, single request/response.
	if op.isFolder || op.isDeleted {
		msg := ClientPushMessage{
			Op:        "push",
			Path:      encPath,
			Extension: ext,
			Hash:      "",
			CTime:     0,
			MTime:     0,
			Folder:    op.isFolder,
			Deleted:   op.isDeleted,
		}

		if err := s.writeJSON(ctx, msg); err != nil {
			s.recordRetryBackoff(op.path)
			return fmt.Errorf("sending push metadata: %w", err)
		}

		if _, err := s.readResponse(ctx); err != nil {
			s.recordRetryBackoff(op.path)
			return err
		}

		if op.isDeleted {
			s.hashCacheMu.Lock()
			delete(s.hashCache, op.path)
			s.hashCacheMu.Unlock()
			s.persistPushedDelete(op.path)
		} else if op.isFolder {
			s.persistPushedFolder(op.path)
		}

		s.logger.Info("pushed",
			slog.String("path", op.path),
			slog.Bool("folder", op.isFolder),
			slog.Bool("deleted", op.isDeleted),
		)
		s.clearRetryBackoff(op.path)
		return nil
	}

	// File with content. Skip files exceeding the server's size limit.
	if s.perFileMax > 0 && len(op.content) > s.perFileMax {
		s.logger.Warn("skipping file exceeding size limit",
			slog.String("path", op.path),
			slog.Int("size", len(op.content)),
			slog.Int("limit", s.perFileMax),
		)
		s.clearRetryBackoff(op.path)
		return nil
	}

	var encContent []byte
	if len(op.content) > 0 {
		encContent, err = s.cipher.EncryptContent(op.content)
		if err != nil {
			s.recordRetryBackoff(op.path)
			return fmt.Errorf("encrypting content: %w", err)
		}
	} else {
		encContent = []byte{}
	}

	h := sha256.Sum256(op.content)
	hashHex := hex.EncodeToString(h[:])
	encHash, err := s.cipher.EncryptPath(hashHex)
	if err != nil {
		s.recordRetryBackoff(op.path)
		return fmt.Errorf("encrypting hash: %w", err)
	}

	pieces := 0
	if len(encContent) > 0 {
		pieces = int(math.Ceil(float64(len(encContent)) / float64(chunkSize)))
	}

	msg := ClientPushMessage{
		Op:        "push",
		Path:      encPath,
		Extension: ext,
		Hash:      encHash,
		CTime:     op.ctime,
		MTime:     op.mtime,
		Folder:    false,
		Deleted:   false,
		Size:      len(encContent),
		Pieces:    pieces,
	}

	// Populate hash cache before sending so server echoes are filtered.
	s.hashCacheMu.Lock()
	s.hashCache[op.path] = hashEntry{encHash: encHash, contentHash: hashHex}
	s.hashCacheMu.Unlock()

	if err := s.writeJSON(ctx, msg); err != nil {
		s.recordRetryBackoff(op.path)
		s.removeHashCache(op.path)
		return fmt.Errorf("sending push metadata: %w", err)
	}

	rawResp, err := s.readResponse(ctx)
	if err != nil {
		s.recordRetryBackoff(op.path)
		s.removeHashCache(op.path)
		return err
	}

	var resp GenericMessage
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		s.recordRetryBackoff(op.path)
		s.removeHashCache(op.path)
		return fmt.Errorf("decoding push response: %w", err)
	}

	// Server error -- abort before sending any binary data.
	// The Obsidian app's request() checks resp.err and throws on non-empty.
	if resp.Err != "" {
		s.recordRetryBackoff(op.path)
		s.removeHashCache(op.path)
		return fmt.Errorf("server rejected push for %s: %s", op.path, resp.Err)
	}

	// "ok" means file is unchanged on server, skip upload.
	if resp.Res == "ok" || resp.Op == "ok" {
		s.logger.Debug("push skipped, unchanged", slog.String("path", op.path))
		s.clearRetryBackoff(op.path)
		return nil
	}

	// Send binary chunks, waiting for ack after each.
	for i := 0; i < pieces; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(encContent) {
			end = len(encContent)
		}

		if err := s.conn.Write(ctx, websocket.MessageBinary, encContent[start:end]); err != nil {
			s.recordRetryBackoff(op.path)
			s.removeHashCache(op.path)
			return fmt.Errorf("sending chunk %d/%d: %w", i+1, pieces, err)
		}

		if _, err := s.readResponse(ctx); err != nil {
			s.recordRetryBackoff(op.path)
			s.removeHashCache(op.path)
			return err
		}
	}

	s.persistPushedFile(op.path, op.content, encHash, op.mtime, op.ctime)

	s.logger.Info("pushed",
		slog.String("path", op.path),
		slog.Int("bytes", len(op.content)),
	)
	s.clearRetryBackoff(op.path)
	return nil
}

// readResponse reads from inboundCh until a non-push, non-pong text
// message arrives (the server's response to our request). Server pushes
// that arrive while waiting are processed inline. This mirrors
// Obsidian's onMessage handler which routes pushes and pongs separately
// from request/response pairs.
func (s *SyncClient) readResponse(ctx context.Context) (json.RawMessage, error) {
	timeout := time.NewTimer(responseTimeout)
	defer timeout.Stop()

	for {
		select {
		case msg := <-s.inboundCh:
			if msg.err != nil {
				return nil, fmt.Errorf("reading response: %w", msg.err)
			}
			s.touchLastMessage()

			// Any message from the server proves the connection is alive.
			// Reset the timeout so interleaved pushes don't eat into the
			// budget meant for detecting a dead connection.
			if !timeout.Stop() {
				select {
				case <-timeout.C:
				default:
				}
			}
			timeout.Reset(responseTimeout)

			if msg.typ == websocket.MessageBinary {
				// Binary frame during a push ack wait is unexpected.
				s.logger.Debug("unexpected binary frame waiting for response", slog.Int("bytes", len(msg.data)))
				continue
			}

			op := gjson.GetBytes(msg.data, "op").Str

			if op == "pong" {
				continue
			}

			// Server push arrived while we're waiting for a response.
			// Process it inline (folders/deletes don't need pull, and
			// hash-matched files are skipped). File pushes that need
			// content are queued for later since we can't pull mid-push.
			if op == "push" {
				s.handlePushWhileBusy(ctx, msg.data)
				continue
			}

			return json.RawMessage(msg.data), nil

		case <-timeout.C:
			return nil, errResponseTimeout

		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// pendingPull tracks a server push that needs content but arrived while
// the event loop was busy with another operation (push or pull). These
// are processed after the current operation completes.
type pendingPull struct {
	push PushMessage
	path string
}

// handlePushWhileBusy processes a server push that arrives while we're
// in the middle of a push or pull operation. Uses Reconcile() to decide
// what to do. Decisions that don't need a pull (Skip, DeleteLocal,
// KeepLocal) are handled inline. Decisions that need content (Download,
// MergeMD, MergeJSON, TypeConflict) are queued for processing after the
// current operation completes.
func (s *SyncClient) handlePushWhileBusy(ctx context.Context, data []byte) {
	var push PushMessage
	if err := json.Unmarshal(data, &push); err != nil {
		s.logger.Warn("failed to decode push while busy", slog.String("error", err.Error()))
		return
	}
	if push.UID > s.version {
		s.version = push.UID
		s.versionDirty = true
	}

	path, err := s.cipher.DecryptPath(push.Path)
	if err != nil {
		s.logger.Warn("decrypting push path while busy", slog.String("error", err.Error()))
		return
	}
	path = normalizePath(path)

	local, encLocalHash := s.resolveLocalState(path)
	prev := s.ServerFileState(path)
	decision := Reconcile(local, prev, push, encLocalHash, s.initial)

	switch decision {
	case DecisionSkip:
		s.persistServerFile(path, push, push.Deleted)

	case DecisionDeleteLocal:
		s.logger.Info("delete (while busy)", slog.String("path", path))
		if push.Folder {
			if err := s.vault.DeleteEmptyDir(path); err != nil {
				s.logger.Info("folder not empty, skipping delete (while busy)", slog.String("path", path))
				s.persistServerFile(path, push, true)
				return
			}
		} else {
			s.vault.DeleteFile(path)
		}
		s.removeHashCache(path)
		s.persistServerFile(path, push, true)
		s.deleteLocalState(path)

	case DecisionKeepLocal:
		s.logger.Info("keeping local (while busy)", slog.String("path", path))
		s.persistServerFile(path, push, true)

	default:
		// Download, MergeMD, MergeJSON, TypeConflict all need content
		// from the server. We can't pull mid-operation, so queue it.
		s.queuePendingPull(pendingPull{push: push, path: path})
	}
}

func (s *SyncClient) queuePendingPull(pp pendingPull) {
	s.pendingPullsMu.Lock()
	s.pendingPulls = append(s.pendingPulls, pp)
	s.pendingPullsMu.Unlock()
}

func (s *SyncClient) drainPendingPulls(ctx context.Context) {
	s.pendingPullsMu.Lock()
	pulls := s.pendingPulls
	s.pendingPulls = nil
	s.pendingPullsMu.Unlock()

	for _, pp := range pulls {
		if err := s.processPush(ctx, pp.push); err != nil {
			s.logger.Warn("processing deferred push",
				slog.String("path", pp.path),
				slog.String("error", err.Error()),
			)
		}
	}
}

// ServerPush pairs a decoded PushMessage with its decrypted plaintext path.
// Used to queue server pushes during initial pull for reconciliation.
type ServerPush struct {
	Msg  PushMessage
	Path string
}

// processPush handles a single server push using the reconciliation
// decision tree. Called from the event loop, so pull() reads from
// inboundCh safely.
func (s *SyncClient) processPush(ctx context.Context, push PushMessage) error {
	path, err := s.cipher.DecryptPath(push.Path)
	if err != nil {
		return fmt.Errorf("decrypting path: %w", err)
	}
	path = normalizePath(path)

	local, encLocalHash := s.resolveLocalState(path)
	prev := s.ServerFileState(path)
	decision := Reconcile(local, prev, push, encLocalHash, s.initial)

	return s.executeLiveDecision(ctx, decision, path, push, local, prev, s.pull)
}

// pullFunc abstracts the two pull variants so executeLiveDecision works
// both from the event loop (pull via inboundCh) and during reconnect
// (pullDirect from the raw connection).
type pullFunc func(ctx context.Context, uid int64) ([]byte, error)

// executeLiveDecision performs the I/O action from a Reconcile() decision
// during live sync (event loop or reconnect). Unlike the startup reconciler
// which uses pullDirect, this accepts a pullFunc so the caller can provide
// the right pull method for the current connection state.
func (s *SyncClient) executeLiveDecision(ctx context.Context, decision ReconcileDecision, path string, push PushMessage, local *state.LocalFile, prev *state.ServerFile, pull pullFunc) error {
	switch decision {
	case DecisionSkip:
		s.persistServerFile(path, push, push.Deleted)
		return nil

	case DecisionDownload:
		return s.liveDownload(ctx, path, push, pull)

	case DecisionDeleteLocal:
		s.logger.Info("delete", slog.String("path", path))
		if push.Folder {
			if err := s.vault.DeleteEmptyDir(path); err != nil {
				s.logger.Info("folder not empty, skipping delete", slog.String("path", path))
				s.persistServerFile(path, push, true)
				return nil
			}
		} else {
			s.vault.DeleteFile(path)
		}
		s.removeHashCache(path)
		s.persistServerFile(path, push, true)
		s.deleteLocalState(path)
		return nil

	case DecisionKeepLocal:
		s.logger.Info("keeping local, server deleted", slog.String("path", path))
		s.persistServerFile(path, push, true)
		return nil

	case DecisionMergeMD:
		return s.liveMergeMD(ctx, path, push, local, prev, pull)

	case DecisionMergeJSON:
		return s.liveMergeJSON(ctx, path, push, pull)

	case DecisionTypeConflict:
		return s.liveTypeConflict(ctx, path, push, local, pull)

	default:
		s.logger.Warn("unknown decision", slog.String("path", path), slog.Int("decision", int(decision)))
		return nil
	}
}

// liveDownload pulls and writes a file during live sync.
func (s *SyncClient) liveDownload(ctx context.Context, path string, push PushMessage, pull pullFunc) error {
	if push.Folder {
		s.logger.Info("mkdir", slog.String("path", path))
		if err := s.vault.MkdirAll(path); err != nil {
			return err
		}
		s.persistServerFile(path, push, false)
		s.persistLocalFolder(path)
		return nil
	}

	// Stat before pull so we can detect concurrent modifications.
	prePullInfo, _ := s.vault.Stat(path)

	content, err := pull(ctx, push.UID)
	if err != nil {
		return fmt.Errorf("pulling %s (uid %d): %w", path, push.UID, err)
	}
	if content == nil {
		s.logger.Info("skip deleted content", slog.String("path", path))
		s.persistServerFile(path, push, true)
		s.deleteLocalState(path)
		return nil
	}

	var plaintext []byte
	if len(content) > 0 {
		plaintext, err = s.cipher.DecryptContent(content)
		if err != nil {
			return fmt.Errorf("decrypting content for %s: %w", path, err)
		}
	}

	// Check if file was modified during download by comparing against
	// the pre-pull stat, not the server mtime.
	if err := s.checkFileChangedDuringDownload(path, prePullInfo); err != nil {
		return err
	}

	var mtime time.Time
	if push.MTime > 0 {
		mtime = time.UnixMilli(push.MTime)
	}
	if err := s.vault.WriteFile(path, plaintext, mtime); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	contentH := sha256.Sum256(plaintext)
	contentHash := hex.EncodeToString(contentH[:])
	s.hashCacheMu.Lock()
	s.hashCache[path] = hashEntry{
		encHash:     push.Hash,
		contentHash: contentHash,
	}
	s.hashCacheMu.Unlock()

	s.persistServerFile(path, push, false)
	s.persistLocalFileAfterWrite(path, contentHash)

	s.logger.Info("wrote",
		slog.String("path", path),
		slog.Int("bytes", len(plaintext)),
	)
	return nil
}

// liveMergeMD performs a three-way merge for .md files during live sync.
func (s *SyncClient) liveMergeMD(ctx context.Context, path string, push PushMessage, local *state.LocalFile, prev *state.ServerFile, pull pullFunc) error {
	// Check if server hash matches our last upload hash -- echo of our own push.
	if local != nil && local.SyncHash != "" {
		encSyncHash, err := s.cipher.EncryptPath(local.SyncHash)
		if err == nil && encSyncHash == push.Hash {
			s.logger.Debug("server matches last push, skip merge", slog.String("path", path))
			s.persistServerFile(path, push, false)
			return nil
		}
	}

	localContent, err := s.vault.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading local file for merge: %w", err)
	}
	localText := string(localContent)

	// Get base version (previous server state).
	baseText := ""
	if prev != nil && prev.UID > 0 {
		baseEnc, err := pull(ctx, prev.UID)
		if err != nil {
			s.logger.Warn("failed to pull base for merge, falling back",
				slog.String("path", path),
				slog.String("error", err.Error()),
			)
			return s.liveDownload(ctx, path, push, pull)
		}
		if baseEnc != nil && len(baseEnc) > 0 {
			basePlain, err := s.cipher.DecryptContent(baseEnc)
			if err != nil {
				s.logger.Warn("failed to decrypt base, falling back",
					slog.String("path", path),
					slog.String("error", err.Error()),
				)
				return s.liveDownload(ctx, path, push, pull)
			}
			baseText = string(basePlain)
		}
	}

	// Get new server version.
	serverEnc, err := pull(ctx, push.UID)
	if err != nil {
		return fmt.Errorf("pulling server version for merge: %w", err)
	}
	if serverEnc == nil {
		s.persistServerFile(path, push, true)
		s.deleteLocalState(path)
		return nil
	}

	var serverText string
	if len(serverEnc) > 0 {
		serverPlain, err := s.cipher.DecryptContent(serverEnc)
		if err != nil {
			return fmt.Errorf("decrypting server version for merge: %w", err)
		}
		serverText = string(serverPlain)
	}

	// Trivial cases.
	if baseText == serverText || localText == serverText {
		s.persistServerFile(path, push, false)
		return nil
	}
	if serverText == "" {
		s.persistServerFile(path, push, false)
		return nil
	}

	// No base available -- check ctime then use mtime comparison per
	// app.js behavior. No conflict copy created, matching Obsidian exactly.
	if baseText == "" {
		// Files created less than 3 minutes ago: server wins unconditionally.
		// This prevents newly-created files from shadowing existing server
		// content when no merge base exists to detect divergence.
		if local != nil && local.CTime > 0 {
			age := time.Now().UnixMilli() - local.CTime
			if age < 0 {
				age = -age
			}
			if age < 180_000 {
				s.logger.Info("merge: no base, recently created, server wins", slog.String("path", path))
				return s.liveWriteContent(path, push, []byte(serverText))
			}
		}

		localMtime := int64(0)
		if local != nil {
			localMtime = local.MTime
		}
		if push.MTime > localMtime {
			s.logger.Info("merge: no base, server wins by mtime", slog.String("path", path))
			return s.liveWriteContent(path, push, []byte(serverText))
		}
		s.logger.Info("merge: no base, local wins by mtime", slog.String("path", path))
		s.persistServerFile(path, push, false)
		return nil
	}

	// Full three-way merge.
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(baseText, localText, true)
	if len(diffs) > 2 {
		diffs = dmp.DiffCleanupSemantic(diffs)
		diffs = dmp.DiffCleanupEfficiency(diffs)
	}
	patches := dmp.PatchMake(baseText, diffs)
	merged, _ := dmp.PatchApply(patches, serverText)

	s.logger.Info("merge: three-way", slog.String("path", path))
	return s.liveWriteContent(path, push, []byte(merged))
}

// liveMergeJSON performs a shallow JSON merge during live sync.
func (s *SyncClient) liveMergeJSON(ctx context.Context, path string, push PushMessage, pull pullFunc) error {
	localContent, err := s.vault.ReadFile(path)
	if err != nil {
		return s.liveDownload(ctx, path, push, pull)
	}

	var localObj map[string]json.RawMessage
	if err := json.Unmarshal(localContent, &localObj); err != nil {
		return s.liveDownload(ctx, path, push, pull)
	}

	serverEnc, err := pull(ctx, push.UID)
	if err != nil {
		return fmt.Errorf("pulling server config for merge: %w", err)
	}
	if serverEnc == nil {
		s.persistServerFile(path, push, true)
		s.deleteLocalState(path)
		return nil
	}

	var serverPlain []byte
	if len(serverEnc) > 0 {
		serverPlain, err = s.cipher.DecryptContent(serverEnc)
		if err != nil {
			return fmt.Errorf("decrypting server config: %w", err)
		}
	}

	var serverObj map[string]json.RawMessage
	if err := json.Unmarshal(serverPlain, &serverObj); err != nil {
		return s.liveWriteContent(path, push, serverPlain)
	}

	for k, v := range serverObj {
		localObj[k] = v
	}

	merged, err := json.MarshalIndent(localObj, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling merged config: %w", err)
	}

	s.logger.Info("merge: JSON", slog.String("path", path))
	return s.liveWriteContent(path, push, merged)
}

// liveTypeConflict handles file/folder type conflicts during live sync.
func (s *SyncClient) liveTypeConflict(ctx context.Context, path string, push PushMessage, local *state.LocalFile, pull pullFunc) error {
	if local != nil && local.Folder {
		cp := conflictCopyPath(path, "")
		s.logger.Info("type conflict: renaming folder",
			slog.String("from", path),
			slog.String("to", cp),
		)
		if err := s.vault.Rename(path, cp); err != nil {
			s.logger.Warn("failed to rename folder for type conflict",
				slog.String("path", path),
				slog.String("error", err.Error()),
			)
		}
		return s.liveDownload(ctx, path, push, pull)
	}

	// Local is file, server wants a folder. Save local to conflict copy.
	ext := extractExtension(path)
	dotExt := ""
	if ext != "" {
		dotExt = "." + ext
	}
	base := strings.TrimSuffix(path, dotExt)
	cp := conflictCopyPath(base, dotExt)

	s.logger.Info("type conflict: renaming local",
		slog.String("from", path),
		slog.String("to", cp),
	)

	content, err := s.vault.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading local file for conflict copy: %w", err)
	}
	if err := s.vault.WriteFile(cp, content, time.Time{}); err != nil {
		return fmt.Errorf("writing conflict copy %s: %w", cp, err)
	}
	s.vault.DeleteFile(path)

	if push.Deleted {
		s.persistServerFile(path, push, true)
		return nil
	}

	return s.liveDownload(ctx, path, push, pull)
}

// liveWriteContent writes plaintext to disk and persists state during live sync.
func (s *SyncClient) liveWriteContent(path string, push PushMessage, plaintext []byte) error {
	var mtime time.Time
	if push.MTime > 0 {
		mtime = time.UnixMilli(push.MTime)
	}
	if err := s.vault.WriteFile(path, plaintext, mtime); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	h := sha256.Sum256(plaintext)
	contentHash := hex.EncodeToString(h[:])

	s.hashCacheMu.Lock()
	s.hashCache[path] = hashEntry{
		encHash:     push.Hash,
		contentHash: contentHash,
	}
	s.hashCacheMu.Unlock()

	s.persistServerFile(path, push, false)
	s.persistLocalFileAfterWrite(path, contentHash)

	s.logger.Info("wrote",
		slog.String("path", path),
		slog.Int("bytes", len(plaintext)),
	)
	return nil
}

// checkFileChangedDuringDownload aborts if the file was modified while we
// were pulling content. prePullInfo is the os.FileInfo from before the pull
// started. If nil (file didn't exist before), the check is skipped.
func (s *SyncClient) checkFileChangedDuringDownload(path string, prePullInfo os.FileInfo) error {
	if prePullInfo == nil {
		return nil
	}
	info, err := s.vault.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// File was deleted during download. Let the write recreate it.
			return nil
		}
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.ModTime().Equal(prePullInfo.ModTime()) || info.Size() != prePullInfo.Size() {
		return fmt.Errorf("download cancelled because %s was changed locally during download", path)
	}
	return nil
}

// decryptPush decodes just the path from a PushMessage without processing it.
func (s *SyncClient) decryptPush(push PushMessage) (ServerPush, error) {
	path, err := s.cipher.DecryptPath(push.Path)
	if err != nil {
		return ServerPush{}, fmt.Errorf("decrypting path: %w", err)
	}
	path = normalizePath(path)
	return ServerPush{Msg: push, Path: path}, nil
}

// persistServerFile saves the server-side file state to bbolt. When a
// file is deleted, the entry is removed rather than stored with a deleted
// flag. Keeping deleted entries would cause unbounded growth since nothing
// cleans them up. Removing them is safe because:
//   - The reconciler checks !ok when deciding whether to push a remote
//     delete, so a missing entry behaves identically to a deleted one.
//   - IsServerFolder returns false for missing entries, which is correct
//     since the path no longer exists on the server.
func (s *SyncClient) persistServerFile(path string, push PushMessage, deleted bool) {
	if deleted {
		if err := s.state.DeleteServerFile(s.vaultID, path); err != nil {
			s.logger.Warn("failed to delete server file state",
				slog.String("path", path),
				slog.String("error", err.Error()),
			)
		}
		return
	}
	sf := state.ServerFile{
		Path:   path,
		Hash:   push.Hash,
		UID:    push.UID,
		MTime:  push.MTime,
		CTime:  push.CTime,
		Size:   push.Size,
		Folder: push.Folder,
		Device: push.Device,
	}
	if err := s.state.SetServerFile(s.vaultID, sf); err != nil {
		s.logger.Warn("failed to persist server file state",
			slog.String("path", path),
			slog.String("error", err.Error()),
		)
	}
}

// persistLocalFileAfterWrite records the local file state after we wrote
// a file to disk from a server push. Stat is called to get the actual
// mtime/size the OS assigned.
func (s *SyncClient) persistLocalFileAfterWrite(path, contentHash string) {
	info, err := s.vault.Stat(path)
	if err != nil {
		s.logger.Warn("failed to stat after write for local state",
			slog.String("path", path),
			slog.String("error", err.Error()),
		)
		return
	}
	now := time.Now().UnixMilli()
	lf := state.LocalFile{
		Path:     path,
		MTime:    info.ModTime().UnixMilli(),
		CTime:    fileCtime(info),
		Size:     info.Size(),
		Hash:     contentHash,
		SyncHash: contentHash,
		SyncTime: now,
		Folder:   false,
	}
	if err := s.state.SetLocalFile(s.vaultID, lf); err != nil {
		s.logger.Warn("failed to persist local file state",
			slog.String("path", path),
			slog.String("error", err.Error()),
		)
	}
}

// persistLocalFolder records the local state for a directory.
func (s *SyncClient) persistLocalFolder(path string) {
	now := time.Now().UnixMilli()
	lf := state.LocalFile{
		Path:     path,
		MTime:    now,
		Size:     0,
		Folder:   true,
		SyncTime: now,
	}
	if err := s.state.SetLocalFile(s.vaultID, lf); err != nil {
		s.logger.Warn("failed to persist local folder state",
			slog.String("path", path),
			slog.String("error", err.Error()),
		)
	}
}

// persistPushedFile records the local file state after we successfully
// pushed a file to the server. The server-side record (with the real
// server-assigned UID) is written by the echo handler -- either
// handlePushWhileBusy (if the echo arrives during the push's ack loop)
// or processPush (if it arrives after). Writing it here would race with
// the echo and overwrite the UID with 0.
func (s *SyncClient) persistPushedFile(path string, content []byte, encHash string, mtime int64, ctime int64) {
	h := sha256.Sum256(content)
	contentHash := hex.EncodeToString(h[:])
	now := time.Now().UnixMilli()

	info, err := s.vault.Stat(path)
	var size int64
	var fileMtime int64
	var fileCt int64
	if err == nil {
		size = info.Size()
		fileMtime = info.ModTime().UnixMilli()
		fileCt = fileCtime(info)
	} else {
		size = int64(len(content))
		fileMtime = mtime
	}

	lf := state.LocalFile{
		Path:     path,
		MTime:    fileMtime,
		CTime:    fileCt,
		Size:     size,
		Hash:     contentHash,
		SyncHash: contentHash,
		SyncTime: now,
		Folder:   false,
	}
	if err := s.state.SetLocalFile(s.vaultID, lf); err != nil {
		s.logger.Warn("failed to persist local file after push",
			slog.String("path", path),
			slog.String("error", err.Error()),
		)
	}
}

// persistPushedFolder records state after we successfully pushed a folder.
func (s *SyncClient) persistPushedFolder(path string) {
	now := time.Now().UnixMilli()
	lf := state.LocalFile{
		Path:     path,
		Folder:   true,
		SyncTime: now,
	}
	if err := s.state.SetLocalFile(s.vaultID, lf); err != nil {
		s.logger.Warn("failed to persist local folder after push",
			slog.String("path", path),
			slog.String("error", err.Error()),
		)
	}

	sf := state.ServerFile{
		Path:   path,
		Folder: true,
	}
	if err := s.state.SetServerFile(s.vaultID, sf); err != nil {
		s.logger.Warn("failed to persist server folder after push",
			slog.String("path", path),
			slog.String("error", err.Error()),
		)
	}
}

// persistPushedDelete removes the server and local file state after we
// successfully pushed a deletion. See persistServerFile for why we
// remove rather than store a deleted entry.
func (s *SyncClient) persistPushedDelete(path string) {
	if err := s.state.DeleteServerFile(s.vaultID, path); err != nil {
		s.logger.Warn("failed to delete server file state after push",
			slog.String("path", path),
			slog.String("error", err.Error()),
		)
	}
	s.deleteLocalState(path)
}

// deleteLocalState removes the local file tracking entry from bbolt.
// Errors are logged since the state is self-correcting on next scan.
func (s *SyncClient) deleteLocalState(path string) {
	if err := s.state.DeleteLocalFile(s.vaultID, path); err != nil {
		s.logger.Warn("failed to delete local file state",
			slog.String("path", path),
			slog.String("error", err.Error()),
		)
	}
}

// ServerFileState returns the persisted server file entry for a path,
// or nil if the server has no record of it. Used by the watcher to
// check whether a deleted path needs a server push and whether it
// was a folder.
func (s *SyncClient) ServerFileState(path string) *state.ServerFile {
	sf, err := s.state.GetServerFile(s.vaultID, path)
	if err != nil {
		s.logger.Warn("failed to look up server file state",
			slog.String("path", path),
			slog.String("error", err.Error()),
		)
		return nil
	}
	return sf
}

// resolveLocalState returns the current local file state for a path by
// checking persisted state and re-hashing from disk if the file changed
// since it was last persisted. Returns nil if the file does not exist.
// Also returns the encrypted local hash for use with Reconcile().
func (s *SyncClient) resolveLocalState(path string) (*state.LocalFile, string) {
	info, err := s.vault.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ""
		}
		s.logger.Warn("stat for reconcile", slog.String("path", path), slog.String("error", err.Error()))
		return nil, ""
	}

	persisted, err := s.state.GetLocalFile(s.vaultID, path)
	if err != nil {
		s.logger.Warn("loading local file state", slog.String("path", path), slog.String("error", err.Error()))
	}

	ctime := fileCtime(info)

	if info.IsDir() {
		lf := state.LocalFile{
			Path:   path,
			Folder: true,
			MTime:  info.ModTime().UnixMilli(),
		}
		return &lf, ""
	}

	mtime := info.ModTime().UnixMilli()
	size := info.Size()

	// If persisted state exists and mtime/size match, reuse the hash.
	// Update CTime from the live stat in case the persisted value is stale.
	if persisted != nil && persisted.MTime == mtime && persisted.Size == size && persisted.Hash != "" {
		if ctime > 0 {
			persisted.CTime = ctime
		}
		enc, err := s.cipher.EncryptPath(persisted.Hash)
		if err != nil {
			return persisted, ""
		}
		return persisted, enc
	}

	// Hash from disk.
	content, err := s.vault.ReadFile(path)
	if err != nil {
		s.logger.Warn("reading file for hash", slog.String("path", path), slog.String("error", err.Error()))
		if persisted != nil {
			return persisted, ""
		}
		lf := state.LocalFile{Path: path, MTime: mtime, CTime: ctime, Size: size}
		return &lf, ""
	}

	h := sha256.Sum256(content)
	hashHex := hex.EncodeToString(h[:])

	lf := state.LocalFile{
		Path:  path,
		MTime: mtime,
		CTime: ctime,
		Size:  size,
		Hash:  hashHex,
	}
	if persisted != nil {
		lf.SyncHash = persisted.SyncHash
		lf.SyncTime = persisted.SyncTime
	}

	enc, err := s.cipher.EncryptPath(hashHex)
	if err != nil {
		return &lf, ""
	}
	return &lf, enc
}

// Pull sends a pull request and reads the response + binary frames
// directly from the connection. Used by the reconciler during startup
// before the reader goroutine is running.
func (s *SyncClient) Pull(ctx context.Context, uid int64) ([]byte, error) {
	return s.pullDirect(ctx, uid)
}

func (s *SyncClient) pull(ctx context.Context, uid int64) ([]byte, error) {
	req := PullRequest{Op: "pull", UID: uid}
	if err := s.writeJSON(ctx, req); err != nil {
		return nil, fmt.Errorf("sending pull request: %w", err)
	}

	// Read from inboundCh until we get the pull response. Pongs and
	// server pushes may arrive in between.
	var resp PullResponse
	for {
		raw, err := s.readInbound(ctx)
		if err != nil {
			return nil, fmt.Errorf("reading pull response: %w", err)
		}

		op := gjson.GetBytes(raw.data, "op").Str
		if op == "pong" {
			continue
		}
		if op == "push" {
			s.handlePushWhileBusy(ctx, raw.data)
			continue
		}

		if err := json.Unmarshal(raw.data, &resp); err != nil {
			return nil, fmt.Errorf("decoding pull response: %w", err)
		}
		break
	}

	if resp.Deleted {
		return nil, nil
	}

	// Guard against a malicious or buggy server sending a huge Size.
	maxSize := s.perFileMax * 2
	if maxSize == 0 {
		maxSize = 10 * 1024 * 1024
	}
	if resp.Size > maxSize {
		return nil, fmt.Errorf("pull response size %d exceeds limit %d", resp.Size, maxSize)
	}
	maxPieces := resp.Size/chunkSize + 1
	if resp.Pieces < 0 || resp.Pieces > maxPieces {
		return nil, fmt.Errorf("pull response pieces %d out of range [0, %d] for size %d", resp.Pieces, maxPieces, resp.Size)
	}

	// Read binary frames containing the encrypted content.
	content := make([]byte, 0, resp.Size)
	for i := 0; i < resp.Pieces; i++ {
		raw, err := s.readInbound(ctx)
		if err != nil {
			return nil, fmt.Errorf("reading piece %d/%d: %w", i+1, resp.Pieces, err)
		}
		if raw.typ != websocket.MessageBinary {
			// Text frame during binary transfer. Could be a pong or push.
			op := gjson.GetBytes(raw.data, "op").Str
			if op == "pong" {
				i-- // retry this piece
				continue
			}
			if op == "push" {
				s.handlePushWhileBusy(ctx, raw.data)
				i-- // retry this piece
				continue
			}
			return nil, fmt.Errorf("expected binary frame, got text: %s", string(raw.data))
		}
		content = append(content, raw.data...)
	}

	return content, nil
}

// readInbound reads the next message from inboundCh with a timeout.
func (s *SyncClient) readInbound(ctx context.Context) (inboundMsg, error) {
	select {
	case msg := <-s.inboundCh:
		if msg.err != nil {
			return msg, msg.err
		}
		s.touchLastMessage()
		return msg, nil
	case <-time.After(responseTimeout):
		return inboundMsg{}, errResponseTimeout
	case <-ctx.Done():
		return inboundMsg{}, ctx.Err()
	}
}

// Push submits a push operation to the event loop and waits for the result.
// Called from the watcher goroutine.
func (s *SyncClient) Push(ctx context.Context, path string, content []byte, mtime int64, ctime int64, isFolder bool, isDeleted bool) error {
	op := syncOp{
		path:      path,
		content:   content,
		mtime:     mtime,
		ctime:     ctime,
		isFolder:  isFolder,
		isDeleted: isDeleted,
		result:    make(chan error, 1),
	}

	select {
	case s.opCh <- op:
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case err := <-op.result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ContentHash returns the cached plaintext content hash for the given
// relative path, or empty string if not cached. Used by the watcher
// to skip pushing files whose content hasn't changed.
func (s *SyncClient) ContentHash(relPath string) string {
	s.hashCacheMu.Lock()
	entry, ok := s.hashCache[relPath]
	s.hashCacheMu.Unlock()
	if !ok {
		return ""
	}
	return entry.contentHash
}

func (s *SyncClient) removeHashCache(path string) {
	s.hashCacheMu.Lock()
	delete(s.hashCache, path)
	s.hashCacheMu.Unlock()
}

func (s *SyncClient) setConnected(v bool) {
	s.connectedMu.Lock()
	s.connected = v
	s.connectedMu.Unlock()
}

// Connected reports whether the WebSocket connection is live.
func (s *SyncClient) Connected() bool {
	s.connectedMu.RLock()
	v := s.connected
	s.connectedMu.RUnlock()
	return v
}

// isOperationError returns true for errors that are specific to a single
// push operation (encryption failure, etc.) rather than connection-level.
func (s *SyncClient) isOperationError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "encrypting path") ||
		strings.Contains(msg, "encrypting content") ||
		strings.Contains(msg, "encrypting hash")
}

// Close cleanly shuts down the WebSocket connection.
func (s *SyncClient) Close() error {
	if s.connCancel != nil {
		s.connCancel()
	}
	if s.conn != nil {
		return s.conn.Close(websocket.StatusNormalClosure, "bye")
	}
	return nil
}

// reconnect dials a fresh WebSocket, re-authenticates, and processes any
// server pushes we missed while disconnected. The server replays all
// changes since our last version, so no full reconciliation is needed.
func (s *SyncClient) reconnect(ctx context.Context) error {
	if err := s.Connect(ctx); err != nil {
		return err
	}

	var serverPushes []ServerPush
	if err := s.WaitForReady(ctx, &serverPushes); err != nil {
		return err
	}

	// Process any pushes the server sent during the catch-up window.
	// WaitForReady reads directly from conn, no reader goroutine yet.
	for _, sp := range serverPushes {
		if err := s.processPushDirect(ctx, sp.Msg); err != nil {
			s.logger.Warn("processing reconnect push",
				slog.String("path", sp.Path),
				slog.String("error", err.Error()),
			)
		}
	}

	// Drain any pending pulls queued by handlePushWhileBusy during the
	// processPushDirect calls above. Each pull may trigger more
	// interleaved pushes, so loop until the queue is empty. The reader
	// goroutine has not started, so processPushDirect reads directly
	// from the connection.
	for {
		s.pendingPullsMu.Lock()
		pulls := s.pendingPulls
		s.pendingPulls = nil
		s.pendingPullsMu.Unlock()

		if len(pulls) == 0 {
			break
		}

		for _, pp := range pulls {
			if err := s.processPushDirect(ctx, pp.push); err != nil {
				s.logger.Warn("processing deferred reconnect push",
					slog.String("path", pp.path),
					slog.String("error", err.Error()),
				)
			}
		}
	}

	return nil
}

// processPushDirect handles a server push by reading directly from the
// connection (not inboundCh). Used during reconnect before the reader
// goroutine is running. Routes through Reconcile() for consistent
// decision-making.
func (s *SyncClient) processPushDirect(ctx context.Context, push PushMessage) error {
	path, err := s.cipher.DecryptPath(push.Path)
	if err != nil {
		return fmt.Errorf("decrypting path: %w", err)
	}
	path = normalizePath(path)

	local, encLocalHash := s.resolveLocalState(path)
	prev := s.ServerFileState(path)
	decision := Reconcile(local, prev, push, encLocalHash, s.initial)

	return s.executeLiveDecision(ctx, decision, path, push, local, prev, s.pullDirect)
}

// pullDirect reads directly from the connection (not inboundCh). Used
// during initial startup and reconnect before the reader goroutine runs.
// Server pushes that arrive mid-pull are handled inline (folders, deletes,
// hash matches) or queued to pendingPulls for processing once the event
// loop starts. This prevents data loss from dropped push notifications.
func (s *SyncClient) pullDirect(ctx context.Context, uid int64) ([]byte, error) {
	req := PullRequest{Op: "pull", UID: uid}
	if err := s.writeJSON(ctx, req); err != nil {
		return nil, fmt.Errorf("sending pull request: %w", err)
	}

	var resp PullResponse
	for {
		typ, data, err := s.conn.Read(ctx)
		if err != nil {
			return nil, fmt.Errorf("reading pull response: %w", err)
		}
		s.touchLastMessage()

		if typ == websocket.MessageBinary {
			s.logger.Debug("unexpected binary frame waiting for pull response", slog.Int("bytes", len(data)))
			continue
		}

		op := gjson.GetBytes(data, "op").Str
		if op == "pong" {
			continue
		}
		if op == "push" {
			s.handlePushWhileBusy(ctx, data)
			continue
		}

		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("decoding pull response: %w", err)
		}
		break
	}

	if resp.Deleted {
		return nil, nil
	}

	maxSize := s.perFileMax * 2
	if maxSize == 0 {
		maxSize = 10 * 1024 * 1024
	}
	if resp.Size > maxSize {
		return nil, fmt.Errorf("pull response size %d exceeds limit %d", resp.Size, maxSize)
	}
	maxPieces := resp.Size/chunkSize + 1
	if resp.Pieces < 0 || resp.Pieces > maxPieces {
		return nil, fmt.Errorf("pull response pieces %d out of range [0, %d] for size %d", resp.Pieces, maxPieces, resp.Size)
	}

	content := make([]byte, 0, resp.Size)
	for i := 0; i < resp.Pieces; i++ {
		typ, data, err := s.conn.Read(ctx)
		if err != nil {
			return nil, fmt.Errorf("reading piece %d/%d: %w", i+1, resp.Pieces, err)
		}
		s.touchLastMessage()

		if typ != websocket.MessageBinary {
			op := gjson.GetBytes(data, "op").Str
			if op == "pong" {
				i--
				continue
			}
			if op == "push" {
				s.handlePushWhileBusy(ctx, data)
				i--
				continue
			}
			return nil, fmt.Errorf("expected binary frame, got text: %s", string(data))
		}
		content = append(content, data...)
	}

	return content, nil
}

// isPermanentError returns true for errors that won't resolve on retry.
func isPermanentError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "auth failed") ||
		strings.Contains(msg, "subscription") ||
		strings.Contains(msg, "Vault not found")
}

func (s *SyncClient) touchLastMessage() {
	s.lastMsgMu.Lock()
	s.lastMessage = time.Now()
	s.lastMsgMu.Unlock()
}

// persistVersionIfDirty saves the current version to bbolt if it changed
// since the last persist. Called periodically from the event loop to
// reduce the replay window on crash. The Obsidian app debounces version
// persistence to 2 seconds; we do it on the heartbeat ticker (~20s).
func (s *SyncClient) persistVersionIfDirty() {
	if !s.versionDirty {
		return
	}
	s.versionDirty = false
	vs := state.VaultState{
		Version: s.version,
		Initial: s.initial,
	}
	if err := s.state.SetVault(s.vaultID, vs); err != nil {
		s.logger.Warn("failed to persist version",
			slog.String("error", err.Error()),
		)
		return
	}
	s.logger.Debug("version persisted", slog.Int64("version", s.version))
}

// checkRetryBackoff returns (waitUntil, true) if path is in backoff,
// or (zeroTime, false) if not. Matches app.js: 5s * 2^count, capped at 5min.
func (s *SyncClient) checkRetryBackoff(path string) (time.Time, bool) {
	s.retryBackoffMu.Lock()
	defer s.retryBackoffMu.Unlock()

	entry, ok := s.retryBackoff[path]
	if !ok {
		return time.Time{}, false
	}

	delay := 5 * time.Second * time.Duration(1<<entry.count)
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	waitUntil := entry.lastFailure.Add(delay)

	if time.Now().Before(waitUntil) {
		return waitUntil, true
	}
	return time.Time{}, false
}

// recordRetryBackoff records a failure for path, incrementing its retry count.
func (s *SyncClient) recordRetryBackoff(path string) {
	s.retryBackoffMu.Lock()
	defer s.retryBackoffMu.Unlock()

	entry := s.retryBackoff[path]
	entry.count++
	entry.lastFailure = time.Now()
	s.retryBackoff[path] = entry
}

// clearRetryBackoff removes path from the backoff map on successful operation.
func (s *SyncClient) clearRetryBackoff(path string) {
	s.retryBackoffMu.Lock()
	defer s.retryBackoffMu.Unlock()
	delete(s.retryBackoff, path)
}

// writeJSON marshals v to JSON and writes it as a text frame.
// Only called from the event loop or during Connect (before Listen starts).
func (s *SyncClient) writeJSON(ctx context.Context, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshalling message: %w", err)
	}
	return s.conn.Write(ctx, websocket.MessageText, data)
}

// readJSON reads a text frame and unmarshals it into v.
// Only called during Connect (before Listen starts).
func (s *SyncClient) readJSON(ctx context.Context, v interface{}) error {
	_, data, err := s.conn.Read(ctx)
	if err != nil {
		return fmt.Errorf("reading message: %w", err)
	}
	s.touchLastMessage()
	return json.Unmarshal(data, v)
}
