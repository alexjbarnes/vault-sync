package obsidian

import (
	"testing"

	"github.com/alexjbarnes/vault-sync/internal/state"
	"github.com/stretchr/testify/assert"
)

func localFile(path string, hash string, mtime int64, folder bool) *state.LocalFile {
	return &state.LocalFile{
		Path:   path,
		Hash:   hash,
		MTime:  mtime,
		Folder: folder,
	}
}

func serverFile(hash string, uid int64, mtime int64, folder bool) *state.ServerFile {
	return &state.ServerFile{
		Hash:   hash,
		UID:    uid,
		MTime:  mtime,
		Folder: folder,
	}
}

func push(hash string, uid int64, mtime int64, folder, deleted bool) PushMessage {
	return PushMessage{
		Op:      "push",
		Hash:    hash,
		UID:     uid,
		MTime:   mtime,
		Folder:  folder,
		Deleted: deleted,
	}
}

func TestReconcile(t *testing.T) {
	tests := []struct {
		name         string
		local        *state.LocalFile
		prev         *state.ServerFile
		push         PushMessage
		encLocalHash string
		initial      bool
		want         ReconcileDecision
	}{
		// --- Step 0: initial sync drops deletions ---
		{
			name:    "initial sync, push deleted, no local",
			local:   nil,
			prev:    nil,
			push:    push("", 1, 100, false, true),
			initial: true,
			want:    DecisionSkip,
		},
		{
			name:    "initial sync, push deleted, local exists",
			local:   localFile("a.md", "h1", 100, false),
			prev:    nil,
			push:    push("", 1, 100, false, true),
			initial: true,
			want:    DecisionSkip,
		},
		{
			name:    "initial sync, push deleted folder",
			local:   localFile("dir", "", 100, true),
			prev:    nil,
			push:    push("", 1, 100, true, true),
			initial: true,
			want:    DecisionSkip,
		},

		// --- Step 1: no local file ---
		{
			name:  "no local, push not deleted -> download",
			local: nil,
			prev:  nil,
			push:  push("h_server", 10, 200, false, false),
			want:  DecisionDownload,
		},
		{
			name:  "no local, push deleted -> skip",
			local: nil,
			prev:  nil,
			push:  push("", 10, 200, false, true),
			want:  DecisionSkip,
		},
		{
			name:  "no local, push is folder -> download",
			local: nil,
			prev:  nil,
			push:  push("", 10, 200, true, false),
			want:  DecisionDownload,
		},
		{
			name:  "no local, push is deleted folder -> skip",
			local: nil,
			prev:  nil,
			push:  push("", 10, 200, true, true),
			want:  DecisionSkip,
		},

		// --- Step 2: both folders ---
		{
			name:  "both folders, not deleted -> skip",
			local: localFile("dir", "", 100, true),
			prev:  nil,
			push:  push("", 10, 200, true, false),
			want:  DecisionSkip,
		},
		{
			name:  "both folders, push deleted -> delete local",
			local: localFile("dir", "", 100, true),
			prev:  nil,
			push:  push("", 10, 200, true, true),
			want:  DecisionDeleteLocal,
		},

		// --- Step 3: hashes match ---
		{
			name:         "hashes match -> skip",
			local:        localFile("a.md", "h1", 100, false),
			prev:         nil,
			push:         push("enc_h1", 10, 200, false, false),
			encLocalHash: "enc_h1",
			want:         DecisionSkip,
		},
		{
			name:         "hashes match but push is folder -> step 5 type conflict",
			local:        localFile("a.md", "h1", 100, false),
			prev:         nil,
			push:         push("enc_h1", 10, 200, true, false),
			encLocalHash: "enc_h1",
			want:         DecisionTypeConflict,
		},
		{
			name:         "hashes match but push deleted -> step 4/5/6",
			local:        localFile("a.md", "h1", 100, false),
			prev:         serverFile("enc_h1", 5, 50, false),
			push:         push("", 10, 200, false, true),
			encLocalHash: "enc_h1",
			want:         DecisionDeleteLocal,
		},
		{
			name:         "empty enc hash -> skip hash comparison, fall to merge",
			local:        localFile("a.md", "", 100, false),
			prev:         nil,
			push:         push("enc_h1", 10, 200, false, false),
			encLocalHash: "",
			want:         DecisionMergeMD, // .md -> step 8 merge
		},
		{
			name:         "empty enc hash, non-md file -> download",
			local:        localFile("photo.png", "", 100, false),
			prev:         nil,
			push:         push("enc_h1", 10, 200, false, false),
			encLocalHash: "",
			want:         DecisionDownload, // step 9
		},

		// --- Step 4: clean local (hash matches prev server) ---
		{
			name:         "clean local, push not deleted -> download",
			local:        localFile("a.md", "h1", 100, false),
			prev:         serverFile("enc_h1", 5, 50, false),
			push:         push("enc_h2", 10, 200, false, false),
			encLocalHash: "enc_h1",
			want:         DecisionDownload,
		},
		{
			name:         "clean local, push deleted -> delete local",
			local:        localFile("a.md", "h1", 100, false),
			prev:         serverFile("enc_h1", 5, 50, false),
			push:         push("", 10, 200, false, true),
			encLocalHash: "enc_h1",
			want:         DecisionDeleteLocal,
		},
		{
			name:         "clean local but prev is folder -> skip step 4, fall to merge",
			local:        localFile("a.md", "h1", 100, false),
			prev:         serverFile("enc_h1", 5, 50, true),
			push:         push("enc_h2", 10, 200, false, false),
			encLocalHash: "enc_h1",
			want:         DecisionMergeMD, // .md -> step 8 merge
		},
		{
			name:         "clean local but local is folder -> skip step 4",
			local:        localFile("dir", "", 100, true),
			prev:         serverFile("enc_h1", 5, 50, false),
			push:         push("enc_h2", 10, 200, false, false),
			encLocalHash: "",
			want:         DecisionTypeConflict, // step 5
		},
		{
			name:         "clean local but prev hash empty -> skip step 4, fall to merge",
			local:        localFile("a.md", "h1", 100, false),
			prev:         serverFile("", 5, 50, false),
			push:         push("enc_h2", 10, 200, false, false),
			encLocalHash: "enc_h1",
			want:         DecisionMergeMD, // .md -> step 8 merge
		},
		{
			name:         "no prev record -> skip step 4, fall to merge",
			local:        localFile("a.md", "h1", 100, false),
			prev:         nil,
			push:         push("enc_h2", 10, 200, false, false),
			encLocalHash: "enc_h1",
			want:         DecisionMergeMD, // .md -> step 8 merge
		},
		{
			name:         "clean local but prev hash empty, non-md -> download",
			local:        localFile("photo.png", "h1", 100, false),
			prev:         serverFile("", 5, 50, false),
			push:         push("enc_h2", 10, 200, false, false),
			encLocalHash: "enc_h1",
			want:         DecisionDownload, // step 9
		},
		{
			name:         "no prev record, non-md -> download",
			local:        localFile("photo.png", "h1", 100, false),
			prev:         nil,
			push:         push("enc_h2", 10, 200, false, false),
			encLocalHash: "enc_h1",
			want:         DecisionDownload, // step 9
		},

		// --- Step 5: type conflict ---
		{
			name:         "local file, server folder -> type conflict",
			local:        localFile("a.md", "h1", 100, false),
			prev:         nil,
			push:         push("", 10, 200, true, false),
			encLocalHash: "enc_h1",
			want:         DecisionTypeConflict,
		},
		{
			name:         "local folder, server file -> type conflict",
			local:        localFile("dir", "", 100, true),
			prev:         nil,
			push:         push("enc_h2", 10, 200, false, false),
			encLocalHash: "",
			want:         DecisionTypeConflict,
		},
		{
			name:         "local file, server deletes folder -> skip",
			local:        localFile("a.md", "h1", 100, false),
			prev:         nil,
			push:         push("", 10, 200, true, true),
			encLocalHash: "enc_h1",
			want:         DecisionSkip,
		},
		{
			name:         "local folder, server deletes file -> skip",
			local:        localFile("dir", "", 100, true),
			prev:         nil,
			push:         push("", 10, 200, false, true),
			encLocalHash: "",
			want:         DecisionSkip,
		},

		// --- Step 6: server deleted, local dirty -> keep local ---
		{
			name:         "dirty local, server deleted -> keep local",
			local:        localFile("a.md", "h_dirty", 100, false),
			prev:         serverFile("enc_h_old", 5, 50, false),
			push:         push("", 10, 200, false, true),
			encLocalHash: "enc_h_dirty",
			want:         DecisionKeepLocal,
		},
		{
			name:         "dirty local, no prev, server deleted -> keep local",
			local:        localFile("a.md", "h_dirty", 100, false),
			prev:         nil,
			push:         push("", 10, 200, false, true),
			encLocalHash: "enc_h_dirty",
			want:         DecisionKeepLocal,
		},

		// --- Step 7: initial sync mtime comparison ---
		{
			name:         "initial sync, server newer -> download",
			local:        localFile("a.md", "h1", 100, false),
			prev:         nil,
			push:         push("enc_h2", 10, 200, false, false),
			encLocalHash: "enc_h1",
			initial:      true,
			want:         DecisionDownload,
		},
		{
			name:         "initial sync, local newer -> skip",
			local:        localFile("a.md", "h1", 300, false),
			prev:         nil,
			push:         push("enc_h2", 10, 200, false, false),
			encLocalHash: "enc_h1",
			initial:      true,
			want:         DecisionSkip,
		},
		{
			name:         "initial sync, same mtime -> skip (local wins tie)",
			local:        localFile("a.md", "h1", 200, false),
			prev:         nil,
			push:         push("enc_h2", 10, 200, false, false),
			encLocalHash: "enc_h1",
			initial:      true,
			want:         DecisionSkip,
		},

		// --- Step 8: both changed, merge by extension ---
		{
			name:         "both changed, .md file -> merge MD",
			local:        localFile("notes/a.md", "h_local", 100, false),
			prev:         serverFile("enc_h_old", 5, 50, false),
			push:         push("enc_h_server", 10, 200, false, false),
			encLocalHash: "enc_h_local",
			want:         DecisionMergeMD,
		},
		{
			name:         "both changed, .MD uppercase -> merge MD",
			local:        localFile("notes/a.MD", "h_local", 100, false),
			prev:         serverFile("enc_h_old", 5, 50, false),
			push:         push("enc_h_server", 10, 200, false, false),
			encLocalHash: "enc_h_local",
			want:         DecisionMergeMD,
		},
		{
			name:         "both changed, .json in .obsidian -> merge JSON",
			local:        localFile(".obsidian/app.json", "h_local", 100, false),
			prev:         serverFile("enc_h_old", 5, 50, false),
			push:         push("enc_h_server", 10, 200, false, false),
			encLocalHash: "enc_h_local",
			want:         DecisionMergeJSON,
		},
		{
			name:         "both changed, .json in .obsidian subdir -> merge JSON",
			local:        localFile(".obsidian/plugins/sync/data.json", "h_local", 100, false),
			prev:         serverFile("enc_h_old", 5, 50, false),
			push:         push("enc_h_server", 10, 200, false, false),
			encLocalHash: "enc_h_local",
			want:         DecisionMergeJSON,
		},
		{
			name:         "both changed, .json NOT in .obsidian -> download (step 9)",
			local:        localFile("data/config.json", "h_local", 100, false),
			prev:         serverFile("enc_h_old", 5, 50, false),
			push:         push("enc_h_server", 10, 200, false, false),
			encLocalHash: "enc_h_local",
			want:         DecisionDownload,
		},

		// --- Step 9: all other file types, server wins ---
		{
			name:         "both changed, .png -> download",
			local:        localFile("img/photo.png", "h_local", 100, false),
			prev:         serverFile("enc_h_old", 5, 50, false),
			push:         push("enc_h_server", 10, 200, false, false),
			encLocalHash: "enc_h_local",
			want:         DecisionDownload,
		},
		{
			name:         "both changed, .canvas -> download",
			local:        localFile("board.canvas", "h_local", 100, false),
			prev:         serverFile("enc_h_old", 5, 50, false),
			push:         push("enc_h_server", 10, 200, false, false),
			encLocalHash: "enc_h_local",
			want:         DecisionDownload,
		},
		{
			name:         "both changed, no extension -> download",
			local:        localFile("Makefile", "h_local", 100, false),
			prev:         serverFile("enc_h_old", 5, 50, false),
			push:         push("enc_h_server", 10, 200, false, false),
			encLocalHash: "enc_h_local",
			want:         DecisionDownload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Reconcile(tt.local, tt.prev, tt.push, tt.encLocalHash, tt.initial)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- extractExtension tests ---

func TestExtractExtension(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"notes/hello.md", "md"},
		{"notes/hello.MD", "md"},
		{"notes/hello.Canvas", "canvas"},
		{".obsidian/app.json", "json"},
		{".obsidian/plugins/sync/data.json", "json"},
		{"folder.with.dots/file", ""},
		{"Makefile", ""},
		{".gitignore", ""},
		{"file.", ""},
		{"a/b/c.tar.gz", "gz"},
		{"photo.JPEG", "jpeg"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := extractExtension(tt.path)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- conflictCopyPath tests ---

func TestConflictCopyPath(t *testing.T) {
	tests := []struct {
		base string
		ext  string
		want string
	}{
		{"notes/hello", ".md", "notes/hello (Conflicted copy).md"},
		{"dir", "", "dir (Conflicted copy)"},
		{".obsidian/app", ".json", ".obsidian/app (Conflicted copy).json"},
	}

	for _, tt := range tests {
		t.Run(tt.base+tt.ext, func(t *testing.T) {
			got := conflictCopyPath(tt.base, tt.ext)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- sortByLengthAsc tests ---

func TestSortByLengthAsc(t *testing.T) {
	paths := []string{"a/b/c/d", "a", "a/b/c", "a/b"}
	sortByLengthAsc(paths)
	assert.Equal(t, []string{"a", "a/b", "a/b/c", "a/b/c/d"}, paths)
}

func TestSortByLengthAsc_Empty(t *testing.T) {
	var paths []string
	sortByLengthAsc(paths)
	assert.Empty(t, paths)
}

func TestSortByLengthAsc_SingleElement(t *testing.T) {
	paths := []string{"only"}
	sortByLengthAsc(paths)
	assert.Equal(t, []string{"only"}, paths)
}

// --- sortByFileSize tests ---

func TestSortByFileSize(t *testing.T) {
	current := map[string]state.LocalFile{
		"big.png":    {Path: "big.png", Size: 5000},
		"small.md":   {Path: "small.md", Size: 100},
		"medium.pdf": {Path: "medium.pdf", Size: 2000},
	}
	paths := []string{"big.png", "small.md", "medium.pdf"}
	sortByFileSize(paths, current)
	assert.Equal(t, []string{"small.md", "medium.pdf", "big.png"}, paths)
}
