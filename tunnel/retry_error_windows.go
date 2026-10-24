//go:build windows

package tunnel

import (
	"errors"

	"golang.org/x/sys/windows"
)

func isLocalResourceExhaustion(err error) bool {
	return errors.Is(err, windows.WSAEADDRNOTAVAIL) ||
		errors.Is(err, windows.WSAEMFILE) ||
		errors.Is(err, windows.ERROR_TOO_MANY_OPEN_FILES) ||
		errors.Is(err, windows.WSAENOBUFS)
}
