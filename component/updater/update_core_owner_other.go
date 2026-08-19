//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris

package updater

import "os"

type fileOwnership struct {
	valid bool
}

func ownershipFromFileInfo(_ os.FileInfo) fileOwnership {
	return fileOwnership{}
}

func applyFileOwnership(_ string, _ fileOwnership) error {
	return nil
}
