//go:build linux

package obsidian

import (
	"math"
	"os"
	"syscall"
)

// fileCtime returns the inode change time (ctime) in milliseconds.
// Matches Node.js file.stat.ctimeMs which the Obsidian app uses.
func fileCtime(info os.FileInfo) int64 {
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	ms := float64(sys.Ctim.Sec)*1000 + float64(sys.Ctim.Nsec)/1e6
	return int64(math.Ceil(ms))
}
