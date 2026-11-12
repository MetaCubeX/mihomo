//go:build linux || darwin

package updater

import (
	"os"
	"syscall"

	"github.com/metacubex/mihomo/log"

	"golang.org/x/sys/unix"
)

func init() {
	preservePosixAttrs = preservePosixAttrsUnix
}

// flagsHook is set on darwin to carry over st_flags (chflags).
var flagsHook func(src, dst string)

// preservePosixAttrsUnix copies owner, mode, file flags and xattrs from src to
// dst. Best-effort: errors are logged, not returned. Covers Linux file
// capabilities (security.capability), SELinux labels, POSIX ACLs, setuid/sgid,
// uid/gid, and macOS com.apple.* xattrs. chown(2) on Linux strips setuid/sgid
// when non-root, so chmod is reapplied after.
func preservePosixAttrsUnix(src, dst string) {
	info, err := os.Stat(src)
	if err != nil {
		log.Warnln("updater: stat %s: %v", src, err)
		return
	}

	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		if chownErr := os.Chown(dst, int(sys.Uid), int(sys.Gid)); chownErr != nil && !os.IsPermission(chownErr) {
			log.Warnln("updater: chown %s: %v", dst, chownErr)
		}
	}

	if chmodErr := os.Chmod(dst, info.Mode()); chmodErr != nil {
		log.Warnln("updater: chmod %s: %v", dst, chmodErr)
	}

	if flagsHook != nil {
		flagsHook(src, dst)
	}

	copyXattrs(src, dst)
}

func copyXattrs(src, dst string) {
	size, err := unix.Llistxattr(src, nil)
	if err != nil {
		if err != unix.ENOTSUP {
			log.Warnln("updater: llistxattr %s: %v", src, err)
		}
		return
	}
	if size == 0 {
		return
	}

	buf := make([]byte, size)
	size, err = unix.Llistxattr(src, buf)
	if err != nil {
		log.Warnln("updater: llistxattr %s: %v", src, err)
		return
	}

	for _, name := range splitXattrNames(buf[:size]) {
		valSize, err := unix.Lgetxattr(src, name, nil)
		if err != nil {
			continue
		}
		val := make([]byte, valSize)
		if _, err = unix.Lgetxattr(src, name, val); err != nil {
			continue
		}
		if err = unix.Lsetxattr(dst, name, val, 0); err != nil {
			log.Warnln("updater: lsetxattr %s %s: %v", dst, name, err)
		}
	}
}

func splitXattrNames(b []byte) []string {
	var names []string
	start := 0
	for i, c := range b {
		if c == 0 {
			if i > start {
				names = append(names, string(b[start:i]))
			}
			start = i + 1
		}
	}
	return names
}
