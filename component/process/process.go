package process

import (
	"errors"
	"net/netip"
)

var (
	ErrInvalidNetwork     = errors.New("invalid network")
	ErrPlatformNotSupport = errors.New("not support on this platform")
	ErrNotFound           = errors.New("process not found")
)

const (
	TCP = "tcp"
	UDP = "udp"
)

func FindProcessName(network string, srcIP netip.Addr, srcPort int) (int32, string, error) {
	return findProcessName(network, srcIP, srcPort)
}

func FindUid(network string, srcIP netip.Addr, srcPort int) (int32, error) {
	_, uid, err := resolveSocketByNetlink(network, srcIP, srcPort)
	if err != nil {
		return -1, err
	}
	return uid, nil
}
