//go:build windows

package tunnel

import "golang.org/x/sys/windows"

func localResourceExhaustionTestCases() []namedRetryError {
	return []namedRetryError{
		{name: "WSAEADDRNOTAVAIL", err: windows.WSAEADDRNOTAVAIL},
		{name: "WSAEMFILE", err: windows.WSAEMFILE},
		{name: "ERROR_TOO_MANY_OPEN_FILES", err: windows.ERROR_TOO_MANY_OPEN_FILES},
		{name: "WSAENOBUFS", err: windows.WSAENOBUFS},
	}
}
