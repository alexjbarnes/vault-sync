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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	pingAfter        = 10 * time.Second
	disconnectAfter  = 120 * time.Second
	heartbeatCheckAt = 20 * time.Second
	chunkSize        = 2097152 // 2MB
)

// SyncClient manages a WebSocket connection to an Obsidian Sync server.
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

	cipher  *CipherV0
	syncDir string

	onReady func(version int64)

	// Channel-based message dispatch.
	responseCh chan json.RawMessage // JSON responses to request/response calls
	dataCh     chan []byte          // binary frames for pull content
	reqMu      sync.Mutex           // serializes request/response exchanges

	// Hash cache for deduplication. Keyed by relative path.
	// encHash is the encrypted hash from the server push (for outbound echo).
	// contentHash is hex(SHA-256(plaintext)) (for inbound echo from watcher).
	hashCache   map[string]hashEntry
	hashCacheMu sync.Mutex

	lastMessage time.Time
	mu          sync.Mutex
}

type hashEntry struct {
	encHash     string // encrypted hash as sent/received over the wire
	contentHash string // hex(SHA-256(plaintext content))
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
	SyncDir           string
	OnReady           func(version int64)
}

// NewSyncClient creates a sync client but does not connect.
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
		syncDir:           cfg.SyncDir,
		onReady:           cfg.OnReady,
		responseCh:        make(chan json.RawMessage, 1),
		dataCh:            make(chan []byte, 1),
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
	s.lastMessage = time.Now()

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

	// Read auth response directly (before dispatcher is running).
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

// Listen starts the read loop dispatcher goroutine, processes incoming pushes,
// and blocks until the context is cancelled or an error occurs.
func (s *SyncClient) Listen(ctx context.Context) error {
	go s.heartbeat(ctx)

	pushCh := make(chan PushMessage, 64)
	readyCh := make(chan ReadyMessage, 1)
	errCh := make(chan error, 1)

	// Read loop goroutine: reads from WebSocket, dispatches to channels.
	go func() {
		for {
			typ, data, err := s.conn.Read(ctx)
			if err != nil {
				errCh <- fmt.Errorf("reading message: %w", err)
				return
			}

			s.mu.Lock()
			s.lastMessage = time.Now()
			s.mu.Unlock()

			// Binary frame goes to dataCh for a pending pull.
			if typ == websocket.MessageBinary {
				select {
				case s.dataCh <- data:
				case <-ctx.Done():
					return
				}
				continue
			}

			// Try to parse as JSON.
			var msg GenericMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				// Could not parse as JSON text frame. Treat as binary data.
				select {
				case s.dataCh <- data:
				case <-ctx.Done():
					return
				}
				continue
			}

			switch msg.Op {
			case "pong":
				continue

			case "ready":
				var ready ReadyMessage
				if err := json.Unmarshal(data, &ready); err != nil {
					s.logger.Warn("failed to decode ready", slog.String("error", err.Error()))
					continue
				}
				select {
				case readyCh <- ready:
				case <-ctx.Done():
					return
				}

			case "push":
				var push PushMessage
				if err := json.Unmarshal(data, &push); err != nil {
					s.logger.Warn("failed to decode push", slog.String("error", err.Error()))
					continue
				}
				select {
				case pushCh <- push:
				case <-ctx.Done():
					return
				}

			default:
				// Any message that isn't push/ready/pong is a response to a
				// pending request (pull response, push ack, chunk ack).
				// Server responses may have "op" or "res" fields.
				select {
				case s.responseCh <- json.RawMessage(data):
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Queue pushes until ready, then process them. After ready, process inline.
	var queued []PushMessage
	ready := false

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case err := <-errCh:
			return err

		case readyMsg := <-readyCh:
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

		case push := <-pushCh:
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

	// filepath.Join resolves ".." segments, so a malicious path like
	// "../../etc/passwd" becomes "/etc/passwd" rather than staying inside
	// syncDir. We check the resolved path has syncDir as a prefix to
	// prevent writes outside the sync directory. This is defense in depth:
	// the path comes from AES-GCM decryption so it can only be crafted by
	// someone with the vault encryption key, but we guard against bugs in
	// decryption or a compromised server. syncDir is resolved to an
	// absolute path at startup (in config.Load) so this prefix check is
	// reliable.
	fullPath := filepath.Join(s.syncDir, path)
	if !strings.HasPrefix(fullPath, s.syncDir+string(os.PathSeparator)) {
		return fmt.Errorf("path traversal blocked: %q resolves outside sync dir", path)
	}

	if push.Deleted {
		s.logger.Info("delete", slog.String("path", path))
		err := os.Remove(fullPath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing %s: %w", path, err)
		}
		s.hashCacheMu.Lock()
		delete(s.hashCache, path)
		s.hashCacheMu.Unlock()
		return nil
	}

	if push.Folder {
		s.logger.Info("mkdir", slog.String("path", path))
		return os.MkdirAll(fullPath, 0755)
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

	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", path, err)
	}

	if err := os.WriteFile(fullPath, plaintext, 0644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	// Update hash cache with both encrypted and plaintext hashes.
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

// pull sends a pull request for the given uid and reads the response JSON
// followed by binary content frames. Returns nil if the file was deleted.
// Must hold reqMu or be called from a context where no other requests are active.
func (s *SyncClient) pull(ctx context.Context, uid int64) ([]byte, error) {
	s.reqMu.Lock()
	defer s.reqMu.Unlock()

	req := PullRequest{Op: "pull", UID: uid}
	if err := s.writeJSON(ctx, req); err != nil {
		return nil, fmt.Errorf("sending pull request: %w", err)
	}

	// Wait for JSON response from dispatcher.
	var rawResp json.RawMessage
	select {
	case rawResp = <-s.responseCh:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	var resp PullResponse
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		return nil, fmt.Errorf("decoding pull response: %w", err)
	}

	if resp.Deleted {
		return nil, nil
	}

	content := make([]byte, 0, resp.Size)
	for i := 0; i < resp.Pieces; i++ {
		select {
		case chunk := <-s.dataCh:
			content = append(content, chunk...)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return content, nil
}

// Push uploads a file change to the server. For files, it encrypts the
// content and path, sends the metadata, and streams binary chunks if the
// server requests them. For folders and deletions, only metadata is sent.
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

	// Folders and deletions: metadata only.
	if isFolder || isDeleted {
		s.reqMu.Lock()
		defer s.reqMu.Unlock()

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
		if err := s.writeJSON(ctx, msg); err != nil {
			return fmt.Errorf("sending push metadata: %w", err)
		}

		// Wait for server ack.
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

	// Compute and encrypt content hash.
	h := sha256.Sum256(content)
	hashHex := hex.EncodeToString(h[:])
	encHash, err := s.cipher.EncryptPath(hashHex)
	if err != nil {
		return fmt.Errorf("encrypting hash: %w", err)
	}

	pieces := 1
	if len(encContent) > 0 {
		pieces = int(math.Ceil(float64(len(encContent)) / float64(chunkSize)))
	}

	s.reqMu.Lock()
	defer s.reqMu.Unlock()

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
	if err := s.writeJSON(ctx, msg); err != nil {
		return fmt.Errorf("sending push metadata: %w", err)
	}

	// Wait for server response.
	var rawResp json.RawMessage
	select {
	case rawResp = <-s.responseCh:
	case <-ctx.Done():
		return ctx.Err()
	}

	var resp GenericMessage
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		return fmt.Errorf("decoding push response: %w", err)
	}

	// "ok" means file is unchanged on server, skip upload.
	// Server may respond with {"res":"ok"} or {"op":"ok"}.
	if resp.Res == "ok" || resp.Op == "ok" {
		s.logger.Debug("push skipped, unchanged", slog.String("path", path))
		s.hashCacheMu.Lock()
		s.hashCache[path] = hashEntry{encHash: encHash, contentHash: hashHex}
		s.hashCacheMu.Unlock()
		return nil
	}

	// Send binary chunks, waiting for ack after each.
	for i := 0; i < pieces; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(encContent) {
			end = len(encContent)
		}
		chunk := encContent[start:end]

		if err := s.conn.Write(ctx, websocket.MessageBinary, chunk); err != nil {
			return fmt.Errorf("sending chunk %d/%d: %w", i+1, pieces, err)
		}

		// Wait for server ack after each chunk.
		select {
		case <-s.responseCh:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	s.hashCacheMu.Lock()
	s.hashCache[path] = hashEntry{encHash: encHash, contentHash: hashHex}
	s.hashCacheMu.Unlock()

	s.logger.Info("pushed",
		slog.String("path", path),
		slog.Int("bytes", len(content)),
	)
	return nil
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
			s.mu.Lock()
			elapsed := time.Since(s.lastMessage)
			s.mu.Unlock()

			if elapsed > disconnectAfter {
				s.logger.Warn("connection timed out, closing")
				s.conn.Close(websocket.StatusGoingAway, "timeout")
				return
			}

			if elapsed > pingAfter {
				if err := s.writeJSON(ctx, map[string]string{"op": "ping"}); err != nil {
					s.logger.Warn("failed to send ping", slog.String("error", err.Error()))
					return
				}
			}
		}
	}
}

func (s *SyncClient) writeJSON(ctx context.Context, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshalling message: %w", err)
	}
	return s.conn.Write(ctx, websocket.MessageText, data)
}

func (s *SyncClient) readJSON(ctx context.Context, v interface{}) error {
	_, data, err := s.conn.Read(ctx)
	if err != nil {
		return fmt.Errorf("reading message: %w", err)
	}
	s.mu.Lock()
	s.lastMessage = time.Now()
	s.mu.Unlock()
	return json.Unmarshal(data, v)
}
