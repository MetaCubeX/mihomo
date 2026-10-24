//go:build !windows

package tunnel

import "syscall"

func localResourceExhaustionTestCases() []namedRetryError {
	return []namedRetryError{
		{name: "EADDRNOTAVAIL", err: syscall.EADDRNOTAVAIL},
		{name: "EMFILE", err: syscall.EMFILE},
		{name: "ENFILE", err: syscall.ENFILE},
		{name: "ENOBUFS", err: syscall.ENOBUFS},
	}
}
