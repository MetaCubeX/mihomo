//go:build !linux

package miu

import "net"

func setCork(net.Conn, bool) {}
