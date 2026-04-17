//go:build darwin

package updater

import (
	"syscall"

	"github.com/metacubex/mihomo/log"

	"golang.org/x/sys/unix"
)

func init() {
	flagsHook = preserveDarwinFlags
}

// preserveDarwinFlags carries over macOS st_flags (uchg/schg/hidden).
func preserveDarwinFlags(src, dst string) {
	var st syscall.Stat_t
	if err := syscall.Stat(src, &st); err != nil {
		return
	}
	if st.Flags == 0 {
		return
	}
	if err := unix.Chflags(dst, int(st.Flags)); err != nil {
		log.Warnln("updater: chflags %s: %v", dst, err)
	}
}
