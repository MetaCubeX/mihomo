package packet

import (
	"net"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type SingPacketConn = N.NetPacketConn

type enhanceSingPacketConn struct {
	N.NetPacketConn
	readWaiter N.PacketReadWaiter
}

func (c *enhanceSingPacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	var buff *buf.Buffer
	var dest M.Socksaddr
	newBuffer := func() *buf.Buffer {
		buff = buf.NewPacket() // do not use stack buffer
		return buff
	}
	if c.readWaiter != nil {
		c.readWaiter.InitializeReadWaiter(newBuffer)
		defer c.readWaiter.InitializeReadWaiter(nil)
		dest, err = c.readWaiter.WaitReadPacket()
	} else {
		dest, err = c.NetPacketConn.ReadPacket(newBuffer())
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
	return c.NetPacketConn
}

func (c *enhanceSingPacketConn) WriterReplaceable() bool {
	return true
}

func (c *enhanceSingPacketConn) ReaderReplaceable() bool {
	return true
}

func newEnhanceSingPacketConn(conn N.NetPacketConn) *enhanceSingPacketConn {
	epc := &enhanceSingPacketConn{NetPacketConn: conn}
	if readWaiter, isReadWaiter := bufio.CreatePacketReadWaiter(conn); isReadWaiter {
		epc.readWaiter = readWaiter
	}
	return epc
}
