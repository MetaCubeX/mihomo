//go:build aix || android || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package updater

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func syncFile(path string) (err error) {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening %s for sync: %w", path, err)
	}
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("closing %s after sync: %w", path, closeErr)
		}
	}()
	if err = file.Sync(); err != nil {
		return fmt.Errorf("syncing %s: %w", path, err)
	}
	return nil
}

func syncDirectory(path string) (err error) {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := dir.Close()
		if err == nil {
			err = closeErr
		}
	}()
	if err = dir.Sync(); errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		// Some Unix filesystems do not support syncing directories.
		return nil
	}
	return err
}
