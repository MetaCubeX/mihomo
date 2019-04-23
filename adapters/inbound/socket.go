package adapters

import (
	"net"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/go-shadowsocks2/socks"
)

// SocketAdapter is a adapter for socks and redir connection
type SocketAdapter struct {
	net.Conn
	metadata *C.Metadata
}

// Metadata return destination metadata
func (s *SocketAdapter) Metadata() *C.Metadata {
	return s.metadata
}

// NewSocket is SocketAdapter generator
func NewSocket(target socks.Addr, conn net.Conn, source C.SourceType, netType C.NetWork) *SocketAdapter {
	metadata := parseSocksAddr(target)
	metadata.NetWork = netType
	metadata.Source = source
	metadata.SourceIP = parseSourceIP(conn)

	return &SocketAdapter{
		Conn:     conn,
		metadata: metadata,
	}
}
