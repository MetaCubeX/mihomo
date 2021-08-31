//go:build !darwin && !linux && !windows && (!freebsd || !amd64)
// +build !darwin
// +build !linux
// +build !windows
// +build !freebsd !amd64

package process

import "net"

func findProcessName(network string, ip net.IP, srcPort int) (string, error) {
	return "", ErrPlatformNotSupport
}
