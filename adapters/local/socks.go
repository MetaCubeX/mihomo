package adapters

import (
	"net"

	C "github.com/Dreamacro/clash/constant"
	"github.com/riobard/go-shadowsocks2/socks"
)

type SocksAdapter struct {
	conn net.Conn
	addr *C.Addr
}

func (s *SocksAdapter) Close() {
	s.conn.Close()
}

func (s *SocksAdapter) Addr() *C.Addr {
	return s.addr
}

func (s *SocksAdapter) Conn() net.Conn {
	return s.conn
}

func NewSocks(target socks.Addr, conn net.Conn) *SocksAdapter {
	return &SocksAdapter{
		conn: conn,
		addr: parseSocksAddr(target),
	}
}
