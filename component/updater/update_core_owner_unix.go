//go:build aix || android || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package updater

import (
	"errors"
	"os"
	"syscall"
)

type fileOwnership struct {
	uid   int
	gid   int
	valid bool
}

func ownershipFromFileInfo(info os.FileInfo) fileOwnership {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileOwnership{}
	}
	return fileOwnership{uid: int(stat.Uid), gid: int(stat.Gid), valid: true}
}

func applyFileOwnership(path string, ownership fileOwnership) error {
	if !ownership.valid {
		return nil
	}
	err := os.Chown(path, ownership.uid, ownership.gid)
	if err != nil && os.Geteuid() != 0 && (errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)) {
		// A non-root updater may be unable to chown even when the newly-created
		// file already has the desired ownership.  Do not turn that into a false
		// upgrade failure.
		return nil
	}
	return err
}
