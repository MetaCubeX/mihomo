package singsnell

import (
	"context"
	"net"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// Interfaces below exist in newer github.com/sagernet/sing releases but not in
// the github.com/metacubex/sing version mihomo depends on. They are declared
// here so the ported code keeps the same shape as upstream.

type CloseHandlerFunc = func(it error)

type TCPConnectionHandlerEx interface {
	NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose CloseHandlerFunc)
}

type UDPConnectionHandlerEx interface {
	NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose CloseHandlerFunc)
}

type VectorisedWriteCreator interface {
	CreateVectorisedWriter() (N.VectorisedWriter, bool)
}

type PacketBatchWriter interface {
	WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error
}

type PacketBatchWriteCreator interface {
	CreatePacketBatchWriter() (PacketBatchWriter, bool)
}

type EarlyReader interface {
	NeedHandshakeForRead() bool
}

type EarlyWriter interface {
	NeedHandshakeForWrite() bool
}

// NewBufferSize mirrors ReadWaitOptions.NewBufferSize from newer sing releases.
func NewBufferSize(options N.ReadWaitOptions, bufferSize int) *buf.Buffer {
	buffer := buf.NewSize(bufferSize + options.FrontHeadroom + options.RearHeadroom)
	if options.FrontHeadroom > 0 {
		buffer.Resize(options.FrontHeadroom, 0)
	}
	if options.RearHeadroom > 0 {
		buffer.Reserve(options.RearHeadroom)
	}
	return buffer
}
