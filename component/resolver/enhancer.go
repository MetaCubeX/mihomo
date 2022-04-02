package resolver

import (
	"net"
)

var DefaultHostMapper Enhancer

type Enhancer interface {
	FakeIPEnabled() bool
	MappingEnabled() bool
	IsFakeIP(net.IP) bool
	IsFakeBroadcastIP(net.IP) bool
	IsExistFakeIP(net.IP) bool
	FindHostByIP(net.IP) (string, bool)
	FlushFakeIP() error
	InsertHostByIP(net.IP, string)
}

func FakeIPEnabled() bool {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.FakeIPEnabled()
	}

	return false
}

func MappingEnabled() bool {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.MappingEnabled()
	}

	return false
}

func IsFakeIP(ip net.IP) bool {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.IsFakeIP(ip)
	}

	return false
}

func IsFakeBroadcastIP(ip net.IP) bool {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.IsFakeBroadcastIP(ip)
	}

	return false
}

func IsExistFakeIP(ip net.IP) bool {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.IsExistFakeIP(ip)
	}

	return false
}

func InsertHostByIP(ip net.IP, host string) {
	if mapper := DefaultHostMapper; mapper != nil {
		mapper.InsertHostByIP(ip, host)
	}
}

func FindHostByIP(ip net.IP) (string, bool) {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.FindHostByIP(ip)
	}

	return "", false
}

func FlushFakeIP() error {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.FlushFakeIP()
	}
	return nil
}
