package obsidian

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/tidwall/gjson"
)

const (
	pingAfter        = 10 * time.Second
	disconnectAfter  = 120 * time.Second
	heartbeatCheckAt = 20 * time.Second
	chunkSize        = 2097152 // 2MB
)

// SyncClient manages a WebSocket connection to an Obsidian Sync server.
//
// Architecture: the WebSocket is full-duplex, so reads and writes happen
// independently. A single goroutine (Listen) owns all conn.Read calls.
// Writes come from the watcher (Push) and heartbeat goroutines, serialized
// by writeMu to preserve multi-message protocol sequences.
//
// The only cross-goroutine communication is responseCh, which delivers
// server responses (push acks, chunk acks) from the read loop to the
// watcher goroutine that sent the request.
type SyncClient struct {
	conn   *websocket.Conn
	logger *slog.Logger

	token             string
	vaultID           string
	keyHash           string
	device            string
	encryptionVersion int
	version           int64
	initial           bool

	cipher *CipherV0
	vault  *Vault

	onReady func(version int64)

	// writeMu serializes all conn.Write calls. Required because a client
	// push is a multi-message sequence (metadata JSON + binary chunks)
	// that must be atomic from the server's perspective. Without this,
	// a heartbeat ping could land between push metadata and a binary
	// chunk, breaking the protocol.
	writeMu sync.Mutex

	// responseCh delivers server responses to the watcher goroutine.
	// The read loop sends push acks and chunk acks here. The watcher's
	// Push method receives from it. Buffered at 1 since at most one
	// request/response exchange is in flight (writeMu ensures this).
	responseCh chan json.RawMessage

	// Hash cache for deduplication. Keyed by relative path.
	// encHash: encrypted hash from the wire (for outbound echo comparison).
	// contentHash: hex(SHA-256(plaintext)) (for inbound echo from watcher).
	hashCache   map[string]hashEntry
	hashCacheMu sync.Mutex

	lastMessage time.Time
	lastMsgMu   sync.Mutex
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
	OnReady           func(version int64)
}

func NewSyncClient(cfg SyncConfig, logger *slog.Logger) *SyncClient {
	return &SyncClient{
		logger:            logger,
		token:             cfg.Token,
		vaultID:           cfg.VaultID,
		keyHash:           cfg.KeyHash,
		device:            cfg.Device,
		encryptionVersion: cfg.EncryptionVersion,
		version:           cfg.Version,
		initial:           cfg.Initial,
		cipher:            cfg.Cipher,
		vault:             cfg.Vault,
		onReady:           cfg.OnReady,
		responseCh:        make(chan json.RawMessage, 1),
		hashCache:         make(map[string]hashEntry),
	}
}

// Connect dials the WebSocket, sends init, and waits for auth confirmation.
func (s *SyncClient) Connect(ctx context.Context, host string) error {
	url := "wss://" + host
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
	s.conn.SetReadLimit(256 * 1024 * 1024)
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
	// directly without going through the read loop.
	var initResp InitResponse
	if err := s.readJSON(ctx, &initResp); err != nil {
		s.conn.Close(websocket.StatusInternalError, "auth read failed")
		return fmt.Errorf("reading auth response: %w", err)
	}

	if initResp.Res != "ok" {
		s.conn.Close(websocket.StatusNormalClosure, "auth failed")
		return fmt.Errorf("auth failed: %s", initResp.Res)
	}

	s.logger.Info("websocket authenticated",
		slog.Int("user_id", initResp.UserID),
		slog.Int("per_file_max", initResp.PerFileMax),
	)
	return nil
}

// Listen is the main read loop. It owns all conn.Read calls exclusively.
// Server pushes are queued until "ready", then processed inline (including
// pulling content). After ready, incoming pushes are processed immediately.
// Blocks until context is cancelled or an error occurs.
func (s *SyncClient) Listen(ctx context.Context) error {
	go s.heartbeat(ctx)

	var queued []PushMessage
	ready := false

	for {
		typ, data, err := s.conn.Read(ctx)
		if err != nil {
			return fmt.Errorf("reading message: %w", err)
		}
		s.touchLastMessage()

		// Binary frames are only expected during an inline pull, which
		// reads them directly via readBinary. If one arrives here it's
		// unexpected -- log and skip.
		if typ == websocket.MessageBinary {
			s.logger.Debug("unexpected binary frame in read loop", slog.Int("bytes", len(data)))
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
				s.logger.Warn("failed to decode ready", slog.String("error", err.Error()))
				continue
			}
			if readyMsg.Version > s.version {
				s.version = readyMsg.Version
			}
			s.initial = false
			s.logger.Info("server ready",
				slog.Int64("version", readyMsg.Version),
				slog.Int("queued_pushes", len(queued)),
			)

			for _, push := range queued {
				if err := s.processPush(ctx, push); err != nil {
					s.logger.Warn("processing queued push",
						slog.Int64("uid", push.UID),
						slog.String("error", err.Error()),
					)
				}
			}
			queued = nil
			ready = true

			if s.onReady != nil {
				s.onReady(s.version)
			}

		case "push":
			var push PushMessage
			if err := json.Unmarshal(data, &push); err != nil {
				s.logger.Warn("failed to decode push", slog.String("error", err.Error()))
				continue
			}
			if push.UID > s.version {
				s.version = push.UID
			}
			if ready {
				if err := s.processPush(ctx, push); err != nil {
					s.logger.Warn("processing push",
						slog.Int64("uid", push.UID),
						slog.String("error", err.Error()),
					)
				}
			} else {
				queued = append(queued, push)
			}

		default:
			// Any other message is a response to a watcher Push request.
			// Route it to the watcher via responseCh.
			select {
			case s.responseCh <- json.RawMessage(data):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// processPush handles a single server push: decrypts the path, then creates
// folders, removes deleted files, or pulls and writes file content.
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
		return nil
	}

	if push.Folder {
		s.logger.Info("mkdir", slog.String("path", path))
		return s.vault.MkdirAll(path)
	}

	// Check hash cache: if the encrypted hash matches, content is identical.
	if push.Hash != "" {
		s.hashCacheMu.Lock()
		cached, ok := s.hashCache[path]
		s.hashCacheMu.Unlock()
		if ok && cached.encHash == push.Hash {
			s.logger.Debug("skipping push, hash unchanged", slog.String("path", path))
			return nil
		}
	}

	// Pull content inline. This is safe because we're in the read loop and
	// the pull response + binary frames are the next messages on the wire.
	content, err := s.pull(ctx, push.UID)
	if err != nil {
		return fmt.Errorf("pulling %s (uid %d): %w", path, push.UID, err)
	}
	if content == nil {
		s.logger.Info("skip deleted content", slog.String("path", path))
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

	h := sha256.Sum256(plaintext)
	s.hashCacheMu.Lock()
	s.hashCache[path] = hashEntry{
		encHash:     push.Hash,
		contentHash: hex.EncodeToString(h[:]),
	}
	s.hashCacheMu.Unlock()

	s.logger.Info("wrote",
		slog.String("path", path),
		slog.Int("bytes", len(plaintext)),
	)
	return nil
}

// pull sends a pull request and reads the response + binary frames inline.
// Called from the read loop, so the pull response is the next message on
// the wire. No channel coordination needed.
func (s *SyncClient) pull(ctx context.Context, uid int64) ([]byte, error) {
	// Acquire writeMu to prevent heartbeat pings from interleaving with
	// the pull request. The read side is already exclusive to this goroutine.
	s.writeMu.Lock()
	req := PullRequest{Op: "pull", UID: uid}
	err := s.writeJSON(ctx, req)
	s.writeMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("sending pull request: %w", err)
	}

	// Read messages until we get the pull response. Pongs may arrive
	// if the heartbeat sent a ping just before the pull request.
	var resp PullResponse
	for {
		_, data, err := s.conn.Read(ctx)
		if err != nil {
			return nil, fmt.Errorf("reading pull response: %w", err)
		}
		s.touchLastMessage()

		if gjson.GetBytes(data, "op").Str == "pong" {
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

	// Read binary frames containing the encrypted content.
	content := make([]byte, 0, resp.Size)
	for i := 0; i < resp.Pieces; i++ {
		_, data, err := s.conn.Read(ctx)
		if err != nil {
			return nil, fmt.Errorf("reading piece %d/%d: %w", i+1, resp.Pieces, err)
		}
		s.touchLastMessage()
		content = append(content, data...)
	}

	return content, nil
}

// Push uploads a file change to the server. Called from the watcher
// goroutine. Writes are serialized by writeMu, and server responses
// are received via responseCh (delivered by the read loop).
func (s *SyncClient) Push(ctx context.Context, path string, content []byte, mtime int64, ctime int64, isFolder bool, isDeleted bool) error {
	encPath, err := s.cipher.EncryptPath(path)
	if err != nil {
		return fmt.Errorf("encrypting path: %w", err)
	}

	ext := ""
	if !isFolder {
		if idx := strings.LastIndex(path, "."); idx >= 0 {
			ext = path[idx+1:]
		}
	}

	// Folders and deletions: metadata only, single request/response.
	if isFolder || isDeleted {
		msg := ClientPushMessage{
			Op:        "push",
			Path:      encPath,
			Extension: ext,
			Hash:      "",
			CTime:     0,
			MTime:     0,
			Folder:    isFolder,
			Deleted:   isDeleted,
		}

		s.writeMu.Lock()
		err := s.writeJSON(ctx, msg)
		s.writeMu.Unlock()
		if err != nil {
			return fmt.Errorf("sending push metadata: %w", err)
		}

		select {
		case <-s.responseCh:
		case <-ctx.Done():
			return ctx.Err()
		}

		if isDeleted {
			s.hashCacheMu.Lock()
			delete(s.hashCache, path)
			s.hashCacheMu.Unlock()
		}

		s.logger.Info("pushed",
			slog.String("path", path),
			slog.Bool("folder", isFolder),
			slog.Bool("deleted", isDeleted),
		)
		return nil
	}

	// File with content.
	var encContent []byte
	if len(content) > 0 {
		encContent, err = s.cipher.EncryptContent(content)
		if err != nil {
			return fmt.Errorf("encrypting content: %w", err)
		}
	} else {
		encContent = []byte{}
	}

	h := sha256.Sum256(content)
	hashHex := hex.EncodeToString(h[:])
	encHash, err := s.cipher.EncryptPath(hashHex)
	if err != nil {
		return fmt.Errorf("encrypting hash: %w", err)
	}

	// Empty files have 0 pieces and no binary frames are sent.
	// math.Ceil on empty content would give 1 piece, sending a spurious
	// empty binary frame that the server doesn't expect.
	pieces := 0
	if len(encContent) > 0 {
		pieces = int(math.Ceil(float64(len(encContent)) / float64(chunkSize)))
	}

	msg := ClientPushMessage{
		Op:        "push",
		Path:      encPath,
		Extension: ext,
		Hash:      encHash,
		CTime:     ctime,
		MTime:     mtime,
		Folder:    false,
		Deleted:   false,
		Size:      len(encContent),
		Pieces:    pieces,
	}

	// Populate hash cache before sending so the read loop can filter out
	// the server's echo of this push. Without this, the echo arrives as a
	// "push" op, processPush calls pull, pull tries to acquire writeMu,
	// and we deadlock because Push holds writeMu waiting for responseCh.
	s.hashCacheMu.Lock()
	s.hashCache[path] = hashEntry{encHash: encHash, contentHash: hashHex}
	s.hashCacheMu.Unlock()

	// Hold writeMu for the entire push sequence: metadata + all binary
	// chunks. This prevents heartbeat pings from breaking the sequence.
	s.writeMu.Lock()
	if err := s.writeJSON(ctx, msg); err != nil {
		s.writeMu.Unlock()
		s.removeHashCache(path)
		return fmt.Errorf("sending push metadata: %w", err)
	}

	// Wait for server response (delivered by read loop via responseCh).
	var rawResp json.RawMessage
	select {
	case rawResp = <-s.responseCh:
	case <-ctx.Done():
		s.writeMu.Unlock()
		s.removeHashCache(path)
		return ctx.Err()
	}

	var resp GenericMessage
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		s.writeMu.Unlock()
		s.removeHashCache(path)
		return fmt.Errorf("decoding push response: %w", err)
	}

	// "ok" means file is unchanged on server, skip upload.
	if resp.Res == "ok" || resp.Op == "ok" {
		s.writeMu.Unlock()
		s.logger.Debug("push skipped, unchanged", slog.String("path", path))
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
			s.writeMu.Unlock()
			s.removeHashCache(path)
			return fmt.Errorf("sending chunk %d/%d: %w", i+1, pieces, err)
		}

		select {
		case <-s.responseCh:
		case <-ctx.Done():
			s.writeMu.Unlock()
			s.removeHashCache(path)
			return ctx.Err()
		}
	}
	s.writeMu.Unlock()

	s.logger.Info("pushed",
		slog.String("path", path),
		slog.Int("bytes", len(content)),
	)
	return nil
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

// Close cleanly shuts down the WebSocket connection.
func (s *SyncClient) Close() error {
	if s.conn != nil {
		return s.conn.Close(websocket.StatusNormalClosure, "bye")
	}
	return nil
}

func (s *SyncClient) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(heartbeatCheckAt)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.lastMsgMu.Lock()
			elapsed := time.Since(s.lastMessage)
			s.lastMsgMu.Unlock()

			if elapsed > disconnectAfter {
				s.logger.Warn("connection timed out, closing")
				s.conn.Close(websocket.StatusGoingAway, "timeout")
				return
			}

			if elapsed > pingAfter {
				s.writeMu.Lock()
				err := s.writeJSON(ctx, map[string]string{"op": "ping"})
				s.writeMu.Unlock()
				if err != nil {
					s.logger.Warn("failed to send ping", slog.String("error", err.Error()))
					return
				}
			}
		}
	}
}

func (s *SyncClient) touchLastMessage() {
	s.lastMsgMu.Lock()
	s.lastMessage = time.Now()
	s.lastMsgMu.Unlock()
}

// writeJSON marshals v to JSON and writes it as a text frame.
// Callers must hold writeMu (except during Connect, before Listen starts).
func (s *SyncClient) writeJSON(ctx context.Context, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshalling message: %w", err)
	}
	return s.conn.Write(ctx, websocket.MessageText, data)
}

// readJSON reads a text frame and unmarshals it into v.
// Only called from the read loop goroutine (Listen) or during Connect.
func (s *SyncClient) readJSON(ctx context.Context, v interface{}) error {
	_, data, err := s.conn.Read(ctx)
	if err != nil {
		return fmt.Errorf("reading message: %w", err)
	}
	s.touchLastMessage()
	return json.Unmarshal(data, v)
}
