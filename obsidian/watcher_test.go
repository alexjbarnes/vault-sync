package obsidian

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexjbarnes/vault-sync/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

func newTestWatcher(t *testing.T, vault *Vault, pusher syncPusher) *Watcher {
	t.Helper()
	return &Watcher{
		vault:  vault,
		pusher: pusher,
		logger: testLogger,
		queued: make(map[string]pendingEvent),
	}
}

// --- shouldIgnore ---

func TestShouldIgnore(t *testing.T) {
	tests := []struct {
		path   string
		ignore bool
	}{
		{"notes/hello.md", false},
		{".git", true},
		// .git/HEAD base is "HEAD" which isn't ignored on its own.
		// In practice, .git is caught first and the walk skips it.
		{".git/HEAD", false},
		{".DS_Store", true},
		{".hidden", true},
		{".obsidian", false},
		{".obsidian/app.json", false},
		{"node_modules", true},
		{"workspace.json", true},
		{"workspace-mobile.json", true},
		{"file.swp", true},
		{"file~", true},
		{"regular.txt", false},
		{"sub/dir/file.md", false},
		// Nested .obsidian should still not be ignored.
		{"vault/.obsidian/plugins.json", false},
	}

	w := &Watcher{}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.ignore, w.shouldIgnore(tt.path), "shouldIgnore(%q)", tt.path)
		})
	}
}

// --- handleWrite ---

func TestHandleWrite_DisconnectedQueuesEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	mock.EXPECT().Connected().Return(false)

	absPath := filepath.Join(v.Dir(), "test.md")
	require.NoError(t, os.WriteFile(absPath, []byte("content"), 0644))

	w.handleWrite(context.Background(), absPath)

	ev, ok := w.queued[absPath]
	assert.True(t, ok, "event should be queued")
	assert.False(t, ev.isDelete)
}

func TestHandleWrite_PushesFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	content := []byte("hello world")
	absPath := filepath.Join(v.Dir(), "test.md")
	require.NoError(t, os.WriteFile(absPath, content, 0644))

	mock.EXPECT().Connected().Return(true)
	mock.EXPECT().ContentHash("test.md").Return("")
	mock.EXPECT().ServerFileState("test.md").Return(nil)
	mock.EXPECT().Push(
		gomock.Any(), "test.md", content,
		gomock.Any(), gomock.Any(),
		false, false,
	).Return(nil)

	w.handleWrite(context.Background(), absPath)
}

func TestHandleWrite_PushesFolder(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	dirPath := filepath.Join(v.Dir(), "subfolder")
	require.NoError(t, os.MkdirAll(dirPath, 0755))

	mock.EXPECT().Connected().Return(true)
	mock.EXPECT().Push(
		gomock.Any(), "subfolder", []byte(nil),
		int64(0), int64(0),
		true, false,
	).Return(nil)

	w.handleWrite(context.Background(), dirPath)
}

func TestHandleWrite_SkipsWhenContentHashMatches(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	content := []byte("same content")
	absPath := filepath.Join(v.Dir(), "cached.md")
	require.NoError(t, os.WriteFile(absPath, content, 0644))

	hash := sha256Hex(content)

	mock.EXPECT().Connected().Return(true)
	mock.EXPECT().ContentHash("cached.md").Return(hash)
	// Push should NOT be called since hash matches.

	w.handleWrite(context.Background(), absPath)
}

func TestHandleWrite_FileDeletedBeforeStat(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	// File doesn't exist on disk.
	absPath := filepath.Join(v.Dir(), "gone.md")

	mock.EXPECT().Connected().Return(true)
	// Push should NOT be called.

	w.handleWrite(context.Background(), absPath)
}

func TestHandleWrite_FolderPushError_Requeues(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	require.NoError(t, v.MkdirAll("err-dir"))
	absPath := filepath.Join(v.Dir(), "err-dir")

	gomock.InOrder(
		mock.EXPECT().Connected().Return(true),
		mock.EXPECT().Push(
			gomock.Any(), "err-dir", []byte(nil),
			int64(0), int64(0),
			true, false,
		).Return(fmt.Errorf("connection lost")),
		mock.EXPECT().Connected().Return(false),
	)

	w.handleWrite(context.Background(), absPath)

	_, ok := w.queued[absPath]
	assert.True(t, ok, "folder should be re-queued after disconnect")
}

func TestHandleWrite_PushFailureRequeuesIfDisconnected(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	content := []byte("will fail")
	absPath := filepath.Join(v.Dir(), "fail.md")
	require.NoError(t, os.WriteFile(absPath, content, 0644))

	gomock.InOrder(
		mock.EXPECT().Connected().Return(true),
		mock.EXPECT().ContentHash("fail.md").Return(""),
		mock.EXPECT().ServerFileState("fail.md").Return(nil),
		mock.EXPECT().Push(
			gomock.Any(), "fail.md", content,
			gomock.Any(), gomock.Any(),
			false, false,
		).Return(fmt.Errorf("connection lost")),
		// requeueIfDisconnected checks Connected() again.
		mock.EXPECT().Connected().Return(false),
	)

	w.handleWrite(context.Background(), absPath)

	_, ok := w.queued[absPath]
	assert.True(t, ok, "should be re-queued after disconnect")
}

func TestHandleWrite_PushFailureNotRequeuedIfStillConnected(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	content := []byte("rejected")
	absPath := filepath.Join(v.Dir(), "rejected.md")
	require.NoError(t, os.WriteFile(absPath, content, 0644))

	gomock.InOrder(
		mock.EXPECT().Connected().Return(true),
		mock.EXPECT().ContentHash("rejected.md").Return(""),
		mock.EXPECT().ServerFileState("rejected.md").Return(nil),
		mock.EXPECT().Push(
			gomock.Any(), "rejected.md", content,
			gomock.Any(), gomock.Any(),
			false, false,
		).Return(fmt.Errorf("server rejected")),
		// Still connected -- server rejected the push, no requeue.
		mock.EXPECT().Connected().Return(true),
	)

	w.handleWrite(context.Background(), absPath)

	_, ok := w.queued[absPath]
	assert.False(t, ok, "should not be re-queued when still connected")
}

func TestHandleWrite_AdoptsServerCtimeWhenOlder(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	content := []byte("with ctime")
	absPath := filepath.Join(v.Dir(), "ctime.md")
	require.NoError(t, os.WriteFile(absPath, content, 0644))

	// Server has an older ctime that should be adopted.
	serverCtime := int64(1000)
	mock.EXPECT().Connected().Return(true)
	mock.EXPECT().ContentHash("ctime.md").Return("")
	mock.EXPECT().ServerFileState("ctime.md").Return(&state.ServerFile{
		CTime: serverCtime,
	})
	mock.EXPECT().Push(
		gomock.Any(), "ctime.md", content,
		gomock.Any(),
		serverCtime, // The adopted ctime.
		false, false,
	).Return(nil)

	w.handleWrite(context.Background(), absPath)
}

// --- handleDelete ---

func TestHandleDelete_DisconnectedQueuesEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	mock.EXPECT().Connected().Return(false)

	absPath := filepath.Join(v.Dir(), "deleted.md")
	w.handleDelete(context.Background(), absPath)

	ev, ok := w.queued[absPath]
	assert.True(t, ok)
	assert.True(t, ev.isDelete)
}

func TestHandleDelete_PushesDeleteForKnownServerFile(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	absPath := filepath.Join(v.Dir(), "known.md")

	mock.EXPECT().Connected().Return(true)
	mock.EXPECT().ServerFileState("known.md").Return(&state.ServerFile{
		Path:   "known.md",
		Folder: false,
	})
	mock.EXPECT().Push(
		gomock.Any(), "known.md", []byte(nil),
		int64(0), int64(0),
		false, true, // deleted=true
	).Return(nil)

	w.handleDelete(context.Background(), absPath)
}

func TestHandleDelete_PushesDeleteForFolder(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	absPath := filepath.Join(v.Dir(), "old-dir")

	mock.EXPECT().Connected().Return(true)
	mock.EXPECT().ServerFileState("old-dir").Return(&state.ServerFile{
		Path:   "old-dir",
		Folder: true,
	})
	mock.EXPECT().Push(
		gomock.Any(), "old-dir", []byte(nil),
		int64(0), int64(0),
		true, true, // folder=true, deleted=true
	).Return(nil)

	w.handleDelete(context.Background(), absPath)
}

func TestHandleDelete_SkipsUnknownPath(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	absPath := filepath.Join(v.Dir(), "local-only.md")

	mock.EXPECT().Connected().Return(true)
	mock.EXPECT().ServerFileState("local-only.md").Return(nil)
	// Push should NOT be called.

	w.handleDelete(context.Background(), absPath)
}

func TestHandleDelete_PushFailureRequeuesIfDisconnected(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	absPath := filepath.Join(v.Dir(), "fail-del.md")

	gomock.InOrder(
		mock.EXPECT().Connected().Return(true),
		mock.EXPECT().ServerFileState("fail-del.md").Return(&state.ServerFile{Path: "fail-del.md"}),
		mock.EXPECT().Push(
			gomock.Any(), "fail-del.md", []byte(nil),
			int64(0), int64(0),
			false, true,
		).Return(fmt.Errorf("connection lost")),
		mock.EXPECT().Connected().Return(false),
	)

	w.handleDelete(context.Background(), absPath)

	ev, ok := w.queued[absPath]
	assert.True(t, ok)
	assert.True(t, ev.isDelete)
}

// --- drainQueue ---

func TestDrainQueue_EmptyQueueDoesNothing(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	// No Connected() call expected since queue is empty.
	w.drainQueue(context.Background())
}

func TestDrainQueue_SkipsWhenDisconnected(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	absPath := filepath.Join(v.Dir(), "queued.md")
	w.queued[absPath] = pendingEvent{absPath: absPath, isDelete: false}

	mock.EXPECT().Connected().Return(false)

	w.drainQueue(context.Background())

	// Event should still be in queue.
	_, ok := w.queued[absPath]
	assert.True(t, ok)
}

func TestDrainQueue_ProcessesWriteEvents(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	content := []byte("queued write")
	absPath := filepath.Join(v.Dir(), "queued.md")
	require.NoError(t, os.WriteFile(absPath, content, 0644))
	w.queued[absPath] = pendingEvent{absPath: absPath, isDelete: false}

	// drainQueue checks Connected(), then handleWrite checks Connected() again.
	mock.EXPECT().Connected().Return(true).AnyTimes()
	mock.EXPECT().ContentHash("queued.md").Return("")
	mock.EXPECT().ServerFileState("queued.md").Return(nil)
	mock.EXPECT().Push(
		gomock.Any(), "queued.md", content,
		gomock.Any(), gomock.Any(),
		false, false,
	).Return(nil)

	w.drainQueue(context.Background())

	assert.Empty(t, w.queued)
}

func TestDrainQueue_ProcessesDeleteEvents(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	absPath := filepath.Join(v.Dir(), "del.md")
	w.queued[absPath] = pendingEvent{absPath: absPath, isDelete: true}

	mock.EXPECT().Connected().Return(true).AnyTimes()
	mock.EXPECT().ServerFileState("del.md").Return(&state.ServerFile{Path: "del.md"})
	mock.EXPECT().Push(
		gomock.Any(), "del.md", []byte(nil),
		int64(0), int64(0),
		false, true,
	).Return(nil)

	w.drainQueue(context.Background())

	assert.Empty(t, w.queued)
}

func TestDrainQueue_StopsWhenDisconnectedMidDrain(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	// Queue two events. After the first is processed, connection drops.
	abs1 := filepath.Join(v.Dir(), "a.md")
	abs2 := filepath.Join(v.Dir(), "b.md")
	require.NoError(t, os.WriteFile(abs1, []byte("a"), 0644))
	require.NoError(t, os.WriteFile(abs2, []byte("b"), 0644))
	w.queued[abs1] = pendingEvent{absPath: abs1, isDelete: false}
	w.queued[abs2] = pendingEvent{absPath: abs2, isDelete: false}

	callCount := 0
	mock.EXPECT().Connected().DoAndReturn(func() bool {
		callCount++
		// First Connected() call in drainQueue: true.
		// handleWrite calls Connected(): true.
		// After first item, drainQueue checks Connected(): false.
		return callCount <= 2
	}).AnyTimes()
	mock.EXPECT().ContentHash(gomock.Any()).Return("").AnyTimes()
	mock.EXPECT().ServerFileState(gomock.Any()).Return(nil).AnyTimes()
	// Only one Push should fire before disconnect stops the drain.
	mock.EXPECT().Push(
		gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any(), gomock.Any(),
		gomock.Any(), gomock.Any(),
	).Return(nil).Times(1)

	w.drainQueue(context.Background())

	// One event should remain queued (the one that wasn't processed).
	// The one that was processed is removed from the queue even though
	// we disconnected after -- it was already pushed successfully.
	// But the second item was never dequeued because we broke out of the loop.
	require.Len(t, w.queued, 1, "one event should remain in queue")
}

func TestDrainQueue_LastEventWinsForSamePath(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	absPath := filepath.Join(v.Dir(), "flip.md")

	// Write then delete for the same path. Map deduplication means
	// only the last event (delete) survives.
	w.queued[absPath] = pendingEvent{absPath: absPath, isDelete: false}
	w.queued[absPath] = pendingEvent{absPath: absPath, isDelete: true}

	mock.EXPECT().Connected().Return(true).AnyTimes()
	mock.EXPECT().ServerFileState("flip.md").Return(&state.ServerFile{Path: "flip.md"})
	mock.EXPECT().Push(
		gomock.Any(), "flip.md", []byte(nil),
		int64(0), int64(0),
		false, true, // delete
	).Return(nil)

	w.drainQueue(context.Background())

	assert.Empty(t, w.queued)
}

// --- Path normalization in watcher ---

func TestHandleWrite_NormalizesPath(t *testing.T) {
	ctrl := gomock.NewController(t)
	mock := NewMockSyncPusher(ctrl)
	v := tempVault(t)
	w := newTestWatcher(t, v, mock)

	// Create a file in a subdirectory.
	require.NoError(t, os.MkdirAll(filepath.Join(v.Dir(), "sub"), 0755))
	content := []byte("nested")
	absPath := filepath.Join(v.Dir(), "sub", "note.md")
	require.NoError(t, os.WriteFile(absPath, content, 0644))

	mock.EXPECT().Connected().Return(true)
	mock.EXPECT().ContentHash("sub/note.md").Return("")
	mock.EXPECT().ServerFileState("sub/note.md").Return(nil)
	// The path passed to Push should be normalized (forward slashes).
	mock.EXPECT().Push(
		gomock.Any(), "sub/note.md", content,
		gomock.Any(), gomock.Any(),
		false, false,
	).Return(nil)

	w.handleWrite(context.Background(), absPath)
}
