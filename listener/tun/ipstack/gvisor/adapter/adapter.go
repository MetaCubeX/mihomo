package adapter

import (
	"net"
)

// TCPConn implements the net.Conn interface.
type TCPConn interface {
	net.Conn
}

// UDPConn implements net.Conn and net.PacketConn.
type UDPConn interface {
	net.Conn
	net.PacketConn
}
