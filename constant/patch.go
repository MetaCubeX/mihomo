package constant

import "net"

type WrappedConn interface {
	RawConn() (net.Conn, bool)
}

type WrappedPacketConn interface {
	RawPacketConn() (net.PacketConn, bool)
}
