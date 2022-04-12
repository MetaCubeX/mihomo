//go:build !linux && !windows

package tun

const (
	offset     = 4 /* 4 bytes TUN_PI */
	defaultMTU = 1500
)
