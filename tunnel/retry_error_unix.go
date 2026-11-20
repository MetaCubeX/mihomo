//go:build !windows

package tunnel

import (
	"errors"
	"syscall"
)

func isLocalResourceExhaustion(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL) ||
		errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS)
}
