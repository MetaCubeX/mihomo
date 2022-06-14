package system

import (
	"net"
	"net/netip"

	"github.com/Dreamacro/clash/common/pool"
)

type packet struct {
	local     netip.AddrPort
	data      []byte
	offset    int
	writeBack func(b []byte, addr net.Addr) (int, error)
}

func (pkt *packet) Data() []byte {
	return pkt.data[:pkt.offset]
}

func (pkt *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	return pkt.writeBack(b, addr)
}

func (pkt *packet) Drop() {
	_ = pool.Put(pkt.data)
}

func (pkt *packet) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(pkt.local)
}
