package utils

import (
	"context"
	"net"
	"strconv"
)

func SplitHostPort(hostport string) (string, uint16, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err
	}
	portUint, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", 0, err
	}
	return host, uint16(portUint), err
}

func ParseIPZone(s string) (net.IP, string) {
	s, zone := splitHostZone(s)
	return net.ParseIP(s), zone
}

func splitHostZone(s string) (host, zone string) {
	if i := last(s, '%'); i > 0 {
		host, zone = s[:i], s[i+1:]
	} else {
		host = s
	}
	return
}

func last(s string, b byte) int {
	i := len(s)
	for i--; i >= 0; i-- {
		if s[i] == b {
			break
		}
	}
	return i
}

type PacketDialer interface {
	ListenPacket(rAddr net.Addr) (net.PacketConn, error)
	Context() context.Context
	RemoteAddr(host string) (net.Addr, error)
}
