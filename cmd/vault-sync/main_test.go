package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRun_MCPOnly(t *testing.T) {
	tmpDir := t.TempDir()
	syncDir := filepath.Join(tmpDir, "vault")

	if err := os.MkdirAll(syncDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Isolate state DB to temp directory.
	t.Setenv("HOME", tmpDir)

	// MCP-only mode: disable sync, enable MCP with basic auth.
	t.Setenv("ENABLE_SYNC", "false")
	t.Setenv("ENABLE_MCP", "true")
	t.Setenv("MCP_SERVER_URL", "http://localhost:19293")
	t.Setenv("MCP_AUTH_USERS", "testuser:testpass")
	t.Setenv("OBSIDIAN_SYNC_DIR", syncDir)
	t.Setenv("MCP_LISTEN_ADDR", "127.0.0.1:0")

	errCh := make(chan error, 1)

	go func() {
		errCh <- run()
	}()

	// Let the server bind and start, then signal shutdown.
	time.Sleep(500 * time.Millisecond)

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}

	if err := proc.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run() returned error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run() did not shut down within timeout")
	}
}
