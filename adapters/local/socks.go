package adapters

import (
	"net"

	C "github.com/Dreamacro/clash/constant"
	"github.com/riobard/go-shadowsocks2/socks"
)

// SocksAdapter is a adapter for socks and redir connection
type SocksAdapter struct {
	conn net.Conn
	addr *C.Addr
}

// Close socks and redir connection
func (s *SocksAdapter) Close() {
	s.conn.Close()
}

// Addr return destination address
func (s *SocksAdapter) Addr() *C.Addr {
	return s.addr
}

// Conn return raw net.Conn
func (s *SocksAdapter) Conn() net.Conn {
	return s.conn
}

// NewSocks is SocksAdapter generator
func NewSocks(target socks.Addr, conn net.Conn) *SocksAdapter {
	return &SocksAdapter{
		conn: conn,
		addr: parseSocksAddr(target),
	}
}
