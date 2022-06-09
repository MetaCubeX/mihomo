package system

import (
	"net"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type packet struct {
	local     *net.UDPAddr
	data      *buf.Buffer
	writeBack func(b []byte, addr net.Addr) (int, error)
}

func (pkt *packet) Data() *buf.Buffer {
	return pkt.data
}

func (pkt *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	return pkt.writeBack(b, addr)
}

func (pkt *packet) WritePacket(buffer *buf.Buffer, addr M.Socksaddr) error {
	defer buffer.Release()
	return common.Error(pkt.writeBack(buffer.Bytes(), addr.UDPAddr()))
}

func (pkt *packet) LocalAddr() net.Addr {
	return pkt.local
}
