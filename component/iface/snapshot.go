package iface

import "net"

// interfaceSnapshot keeps interface metadata and addresses from the same read.
type interfaceSnapshot struct {
	net.Interface
	Addrs []net.Addr
}
