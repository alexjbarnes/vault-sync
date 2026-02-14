//go:build darwin

package obsidian

import (
	"math"
	"os"
	"syscall"
)

// fileCtime returns the inode change time (ctime) in milliseconds.
// Matches Node.js file.stat.ctimeMs which the Obsidian app uses.
// On macOS, Stat_t has Ctimespec (not Ctim like Linux).
func fileCtime(info os.FileInfo) int64 {
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	ms := float64(sys.Ctimespec.Sec)*1000 + float64(sys.Ctimespec.Nsec)/1e6
	return int64(math.Ceil(ms))
}
