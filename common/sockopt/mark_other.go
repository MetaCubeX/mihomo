//go:build !linux

package sockopt

func markControl(fd uintptr, mark int) error { return nil }
