//go:build linux

package obsidian

import (
	"math"
	"os"
	"syscall"
)

const (
	// msPerSec is the number of milliseconds per second, used when
	// converting syscall timespec values to milliseconds.
	msPerSec = 1000

	// nsPerMs is the number of nanoseconds per millisecond.
	nsPerMs = 1e6
)

// fileCtime returns the inode change time (ctime) in milliseconds.
// Matches Node.js file.stat.ctimeMs which the Obsidian app uses.
func fileCtime(info os.FileInfo) int64 {
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}

	ms := float64(sys.Ctim.Sec)*msPerSec + float64(sys.Ctim.Nsec)/nsPerMs

	return int64(math.Ceil(ms))
}
