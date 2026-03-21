//go:build !darwin && !linux && !windows && (!freebsd || !amd64)

package process

import "net/netip"

func findProcessName(network string, ip netip.Addr, srcPort int) (uint32, string, error) {
	return 0, "", ErrPlatformNotSupport
}

func resolveSocketByNetlink(network string, ip netip.Addr, srcPort int) (uint32, uint32, error) {
	return 0, 0, ErrPlatformNotSupport
}
