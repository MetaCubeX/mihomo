package constant

import (
	"net/netip"

	"github.com/metacubex/mihomo/transport/socks5"
)

const (
	BpfFSPath = "/sys/fs/bpf/mihomo"

	TcpAutoRedirPort  = 't'<<8 | 'r'<<0
	MihomoTrafficMark = 'c'<<24 | 'l'<<16 | 't'<<8 | 'm'<<0
)

type EBpf interface {
	Start() error
	Close()
	Lookup(srcAddrPort netip.AddrPort) (socks5.Addr, error)
}
