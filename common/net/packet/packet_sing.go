package packet

import (
	"net"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type SingPacketConn = N.NetPacketConn

type EnhanceSingPacketConn interface {
	SingPacketConn
	EnhancePacketConn
}

type enhanceSingPacketConn struct {
	SingPacketConn
	packetReadWaiter N.PacketReadWaiter
}

func (c *enhanceSingPacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	var buff *buf.Buffer
	var dest M.Socksaddr
	newBuffer := func() *buf.Buffer {
		buff = buf.NewPacket() // do not use stack buffer
		return buff
	}
	if c.packetReadWaiter != nil {
		c.packetReadWaiter.InitializeReadWaiter(newBuffer)
		defer c.packetReadWaiter.InitializeReadWaiter(nil)
		dest, err = c.packetReadWaiter.WaitReadPacket()
	} else {
		dest, err = c.SingPacketConn.ReadPacket(newBuffer())
	}
	if dest.IsFqdn() {
		addr = dest
	} else {
		addr = dest.UDPAddr()
	}
	if err != nil {
		if buff != nil {
			buff.Release()
		}
		return
	}
	if buff == nil {
		return
	}
	if buff.IsEmpty() {
		buff.Release()
		return
	}
	data = buff.Bytes()
	put = buff.Release
	return
}

func (c *enhanceSingPacketConn) Upstream() any {
	return c.SingPacketConn
}

func (c *enhanceSingPacketConn) WriterReplaceable() bool {
	return true
}

func (c *enhanceSingPacketConn) ReaderReplaceable() bool {
	return true
}

func newEnhanceSingPacketConn(conn SingPacketConn) *enhanceSingPacketConn {
	epc := &enhanceSingPacketConn{SingPacketConn: conn}
	if readWaiter, isReadWaiter := bufio.CreatePacketReadWaiter(conn); isReadWaiter {
		epc.packetReadWaiter = readWaiter
	}
	return epc
}
