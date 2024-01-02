package outbound

import (
	"net/netip"

	"github.com/metacubex/mihomo/common/callback"
	C "github.com/metacubex/mihomo/constant"

	"github.com/puzpuzpuz/xsync/v3"
)

type loopBackDetector struct {
	connMap       *xsync.MapOf[netip.AddrPort, struct{}]
	packetConnMap *xsync.MapOf[netip.AddrPort, struct{}]
}

func newLoopBackDetector() *loopBackDetector {
	return &loopBackDetector{
		connMap:       xsync.NewMapOf[netip.AddrPort, struct{}](),
		packetConnMap: xsync.NewMapOf[netip.AddrPort, struct{}](),
	}
}

func (l *loopBackDetector) NewConn(conn C.Conn) C.Conn {
	metadata := C.Metadata{}
	if metadata.SetRemoteAddr(conn.LocalAddr()) != nil {
		return conn
	}
	connAddr := metadata.AddrPort()
	if !connAddr.IsValid() {
		return conn
	}
	l.connMap.Store(connAddr, struct{}{})
	return callback.NewCloseCallbackConn(conn, func() {
		l.connMap.Delete(connAddr)
	})
}

func (l *loopBackDetector) NewPacketConn(conn C.PacketConn) C.PacketConn {
	metadata := C.Metadata{}
	if metadata.SetRemoteAddr(conn.LocalAddr()) != nil {
		return conn
	}
	connAddr := metadata.AddrPort()
	if !connAddr.IsValid() {
		return conn
	}
	l.packetConnMap.Store(connAddr, struct{}{})
	return callback.NewCloseCallbackPacketConn(conn, func() {
		l.packetConnMap.Delete(connAddr)
	})
}

func (l *loopBackDetector) CheckConn(connAddr netip.AddrPort) bool {
	if !connAddr.IsValid() {
		return false
	}
	_, ok := l.connMap.Load(connAddr)
	return ok
}

func (l *loopBackDetector) CheckPacketConn(connAddr netip.AddrPort) bool {
	if !connAddr.IsValid() {
		return false
	}
	_, ok := l.packetConnMap.Load(connAddr)
	return ok
}
