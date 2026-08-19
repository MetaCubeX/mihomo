//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris && !windows

package updater

func syncFile(_ string) error {
	return nil
}

func syncDirectory(_ string) error {
	return nil
}
