package adapters

import (
	"net"

	C "github.com/Dreamacro/clash/constant"
	"github.com/riobard/go-shadowsocks2/socks"
)

// SocketAdapter is a adapter for socks and redir connection
type SocketAdapter struct {
	conn net.Conn
	addr *C.Addr
}

// Close socks and redir connection
func (s *SocketAdapter) Close() {
	s.conn.Close()
}

// Addr return destination address
func (s *SocketAdapter) Addr() *C.Addr {
	return s.addr
}

// Conn return raw net.Conn
func (s *SocketAdapter) Conn() net.Conn {
	return s.conn
}

// NewSocket is SocketAdapter generator
func NewSocket(target socks.Addr, conn net.Conn) *SocketAdapter {
	return &SocketAdapter{
		conn: conn,
		addr: parseSocksAddr(target),
	}
}
