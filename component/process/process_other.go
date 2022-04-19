//go:build !darwin && !linux && !windows && (!freebsd || !amd64)

package process

import "net/netip"

func findProcessName(network string, ip netip.Addr, srcPort int) (string, error) {
	return "", ErrPlatformNotSupport
}
