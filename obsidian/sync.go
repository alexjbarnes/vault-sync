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
	"strings"
	"sync"
	"time"

	"github.com/alexjbarnes/vault-sync/internal/state"
	"github.com/coder/websocket"
	"github.com/tidwall/gjson"
)

const (
	pingAfter        = 10 * time.Second
	disconnectAfter  = 120 * time.Second
	heartbeatCheckAt = 20 * time.Second
	chunkSize        = 2097152 // 2MB

	reconnectMin    = 1 * time.Second
	reconnectMax    = 60 * time.Second
	responseTimeout = 30 * time.Second
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

// SyncClient manages a WebSocket connection to an Obsidian Sync server.
//
// Architecture: a reader goroutine feeds inboundCh with raw WebSocket
// messages. A single event loop goroutine (Listen) processes inbound
// messages, watcher operations (opCh), and heartbeat ticks. All writes
// to the connection happen from the event loop, eliminating the need
// for a write mutex and preventing deadlocks between push and pull.
type SyncClient struct {
	conn   *websocket.Conn
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
}

type hashEntry struct {
	encHash     string
	contentHash string
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
		opCh:              make(chan syncOp, 64),
		hashCache:         make(map[string]hashEntry),
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
		s.conn.Close(websocket.StatusNormalClosure, "auth failed")
		return fmt.Errorf("auth failed: %s", initResp.Res)
	}

	s.perFileMax = initResp.PerFileMax
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
				s.logger.Warn("connection timed out, closing")
				s.conn.Close(websocket.StatusGoingAway, "timeout")
				return fmt.Errorf("heartbeat timeout")
			}

			if elapsed > pingAfter {
				if err := s.writeJSON(ctx, map[string]string{"op": "ping"}); err != nil {
					return fmt.Errorf("sending ping: %w", err)
				}
			}

		case <-ctx.Done():
			return ctx.Err()

		case <-connCtx.Done():
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
	encPath, err := s.cipher.EncryptPath(op.path)
	if err != nil {
		return fmt.Errorf("encrypting path: %w", err)
	}

	ext := ""
	if !op.isFolder {
		if idx := strings.LastIndex(op.path, "."); idx >= 0 {
			ext = op.path[idx+1:]
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
			return fmt.Errorf("sending push metadata: %w", err)
		}

		if _, err := s.readResponse(ctx); err != nil {
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
		return nil
	}

	// File with content.
	var encContent []byte
	if len(op.content) > 0 {
		encContent, err = s.cipher.EncryptContent(op.content)
		if err != nil {
			return fmt.Errorf("encrypting content: %w", err)
		}
	} else {
		encContent = []byte{}
	}

	h := sha256.Sum256(op.content)
	hashHex := hex.EncodeToString(h[:])
	encHash, err := s.cipher.EncryptPath(hashHex)
	if err != nil {
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
		s.removeHashCache(op.path)
		return fmt.Errorf("sending push metadata: %w", err)
	}

	rawResp, err := s.readResponse(ctx)
	if err != nil {
		s.removeHashCache(op.path)
		return err
	}

	var resp GenericMessage
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		s.removeHashCache(op.path)
		return fmt.Errorf("decoding push response: %w", err)
	}

	// "ok" means file is unchanged on server, skip upload.
	if resp.Res == "ok" || resp.Op == "ok" {
		s.logger.Debug("push skipped, unchanged", slog.String("path", op.path))
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
			s.removeHashCache(op.path)
			return fmt.Errorf("sending chunk %d/%d: %w", i+1, pieces, err)
		}

		if _, err := s.readResponse(ctx); err != nil {
			s.removeHashCache(op.path)
			return err
		}
	}

	s.persistPushedFile(op.path, op.content, encHash, op.mtime)

	s.logger.Info("pushed",
		slog.String("path", op.path),
		slog.Int("bytes", len(op.content)),
	)
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
// in the middle of a push or pull operation. Folders, deletes, and
// hash-matched files are handled immediately. Files that need content
// are deferred.
func (s *SyncClient) handlePushWhileBusy(ctx context.Context, data []byte) {
	var push PushMessage
	if err := json.Unmarshal(data, &push); err != nil {
		s.logger.Warn("failed to decode push while busy", slog.String("error", err.Error()))
		return
	}
	if push.UID > s.version {
		s.version = push.UID
	}

	path, err := s.cipher.DecryptPath(push.Path)
	if err != nil {
		s.logger.Warn("decrypting push path while busy", slog.String("error", err.Error()))
		return
	}

	// Handle cases that don't need a pull.
	if push.Deleted {
		s.logger.Info("delete", slog.String("path", path))
		if err := s.vault.DeleteFile(path); err != nil {
			s.logger.Warn("deleting file from push while busy", slog.String("path", path), slog.String("error", err.Error()))
		}
		s.removeHashCache(path)
		s.persistServerFile(path, push, true)
		s.deleteLocalState(path)
		return
	}

	if push.Folder {
		s.logger.Info("mkdir", slog.String("path", path))
		if err := s.vault.MkdirAll(path); err != nil {
			s.logger.Warn("mkdir from push while busy", slog.String("path", path), slog.String("error", err.Error()))
		}
		s.persistServerFile(path, push, false)
		s.persistLocalFolder(path)
		return
	}

	// Hash cache hit means content is identical.
	if push.Hash != "" {
		s.hashCacheMu.Lock()
		cached, ok := s.hashCache[path]
		s.hashCacheMu.Unlock()
		if ok && cached.encHash == push.Hash {
			s.logger.Debug("skipping push while busy, hash unchanged", slog.String("path", path))
			s.persistServerFile(path, push, false)
			return
		}
	}

	// Needs content. We can't pull mid-operation, so queue it. The event
	// loop will process it when the current operation completes. We store
	// it on a slice that the event loop checks after each operation.
	s.queuePendingPull(pendingPull{push: push, path: path})
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

// processPush handles a single server push: decrypts the path, then creates
// folders, removes deleted files, or pulls and writes file content. Called
// from the event loop, so pull() reads from inboundCh safely.
func (s *SyncClient) processPush(ctx context.Context, push PushMessage) error {
	path, err := s.cipher.DecryptPath(push.Path)
	if err != nil {
		return fmt.Errorf("decrypting path: %w", err)
	}

	if push.Deleted {
		s.logger.Info("delete", slog.String("path", path))
		if err := s.vault.DeleteFile(path); err != nil {
			return fmt.Errorf("deleting %s: %w", path, err)
		}
		s.removeHashCache(path)
		s.persistServerFile(path, push, true)
		s.deleteLocalState(path)
		return nil
	}

	if push.Folder {
		s.logger.Info("mkdir", slog.String("path", path))
		if err := s.vault.MkdirAll(path); err != nil {
			return err
		}
		s.persistServerFile(path, push, false)
		s.persistLocalFolder(path)
		return nil
	}

	// Check hash cache: if the encrypted hash matches, content is identical.
	if push.Hash != "" {
		s.hashCacheMu.Lock()
		cached, ok := s.hashCache[path]
		s.hashCacheMu.Unlock()
		if ok && cached.encHash == push.Hash {
			s.logger.Debug("skipping push, hash unchanged", slog.String("path", path))
			s.persistServerFile(path, push, false)
			return nil
		}
	}

	// Pull content. Called from the event loop so we read from inboundCh.
	content, err := s.pull(ctx, push.UID)
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

	if err := s.vault.WriteFile(path, plaintext); err != nil {
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

// decryptPush decodes just the path from a PushMessage without processing it.
func (s *SyncClient) decryptPush(push PushMessage) (ServerPush, error) {
	path, err := s.cipher.DecryptPath(push.Path)
	if err != nil {
		return ServerPush{}, fmt.Errorf("decrypting path: %w", err)
	}
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

// persistPushedFile records both local and server state after we successfully
// pushed a file to the server.
func (s *SyncClient) persistPushedFile(path string, content []byte, encHash string, mtime int64) {
	h := sha256.Sum256(content)
	contentHash := hex.EncodeToString(h[:])
	now := time.Now().UnixMilli()

	info, err := s.vault.Stat(path)
	var size int64
	var fileMtime int64
	if err == nil {
		size = info.Size()
		fileMtime = info.ModTime().UnixMilli()
	} else {
		size = int64(len(content))
		fileMtime = mtime
	}

	lf := state.LocalFile{
		Path:     path,
		MTime:    fileMtime,
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

	sf := state.ServerFile{
		Path:   path,
		Hash:   encHash,
		MTime:  mtime,
		Size:   size,
		Folder: false,
	}
	if err := s.state.SetServerFile(s.vaultID, sf); err != nil {
		s.logger.Warn("failed to persist server file after push",
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

// IsServerFolder checks whether the given path is recorded as a folder
// in the server file state. Returns false if the path is not found.
func (s *SyncClient) IsServerFolder(path string) bool {
	sf, err := s.state.GetServerFile(s.vaultID, path)
	if err != nil {
		s.logger.Warn("failed to look up server file state",
			slog.String("path", path),
			slog.String("error", err.Error()),
		)
		return false
	}
	return sf != nil && sf.Folder
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
	if resp.Pieces > maxPieces {
		return nil, fmt.Errorf("pull response pieces %d exceeds expected max %d for size %d", resp.Pieces, maxPieces, resp.Size)
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
// connection (not inboundCh). Used during initial startup and reconnect
// before the reader goroutine is running.
func (s *SyncClient) processPushDirect(ctx context.Context, push PushMessage) error {
	path, err := s.cipher.DecryptPath(push.Path)
	if err != nil {
		return fmt.Errorf("decrypting path: %w", err)
	}

	if push.Deleted {
		s.logger.Info("delete", slog.String("path", path))
		if err := s.vault.DeleteFile(path); err != nil {
			return fmt.Errorf("deleting %s: %w", path, err)
		}
		s.removeHashCache(path)
		s.persistServerFile(path, push, true)
		s.deleteLocalState(path)
		return nil
	}

	if push.Folder {
		s.logger.Info("mkdir", slog.String("path", path))
		if err := s.vault.MkdirAll(path); err != nil {
			return err
		}
		s.persistServerFile(path, push, false)
		s.persistLocalFolder(path)
		return nil
	}

	if push.Hash != "" {
		s.hashCacheMu.Lock()
		cached, ok := s.hashCache[path]
		s.hashCacheMu.Unlock()
		if ok && cached.encHash == push.Hash {
			s.logger.Debug("skipping push, hash unchanged", slog.String("path", path))
			s.persistServerFile(path, push, false)
			return nil
		}
	}

	content, err := s.pullDirect(ctx, push.UID)
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

	if err := s.vault.WriteFile(path, plaintext); err != nil {
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
	if resp.Pieces > maxPieces {
		return nil, fmt.Errorf("pull response pieces %d exceeds expected max %d for size %d", resp.Pieces, maxPieces, resp.Size)
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
	if strings.Contains(msg, "auth failed") {
		return true
	}
	return false
}

func (s *SyncClient) touchLastMessage() {
	s.lastMsgMu.Lock()
	s.lastMessage = time.Now()
	s.lastMsgMu.Unlock()
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
