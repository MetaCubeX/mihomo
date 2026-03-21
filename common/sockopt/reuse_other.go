//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package sockopt

func reuseControl(fd uintptr) error { return nil }
