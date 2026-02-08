//go:build !linux && !darwin

package obsidian

import "os"

// fileCtime returns 0 on unsupported platforms. The ctime is used for
// the 3-minute new-file heuristic in merge and for preserving creation
// time metadata. Returning 0 disables these features gracefully: the
// merge falls back to mtime comparison and pushes send ctime=0.
func fileCtime(_ os.FileInfo) int64 {
	return 0
}
