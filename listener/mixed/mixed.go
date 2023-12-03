package mixed

import (
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/lru"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/http"
	"github.com/metacubex/mihomo/listener/socks"
	"github.com/metacubex/mihomo/transport/socks4"
	"github.com/metacubex/mihomo/transport/socks5"
)

type Listener struct {
	listener net.Listener
	addr     string
	cache    *lru.LruCache[string, bool]
	closed   bool
}

// RawAddress implements C.Listener
func (l *Listener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *Listener) Address() string {
	return l.listener.Addr().String()
}

// Close implements C.Listener
func (l *Listener) Close() error {
	l.closed = true
	return l.listener.Close()
}

func New(addr string, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-MIXED"),
			inbound.WithSpecialRules(""),
		}
	}
	l, err := inbound.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	ml := &Listener{
		listener: l,
		addr:     addr,
		cache:    lru.New[string, bool](lru.WithAge[string, bool](30)),
	}
	go func() {
		for {
			c, err := ml.listener.Accept()
			if err != nil {
				if ml.closed {
					break
				}
				continue
			}
			go handleConn(c, tunnel, ml.cache, additions...)
		}
	}()

	return ml, nil
}

func handleConn(conn net.Conn, tunnel C.Tunnel, cache *lru.LruCache[string, bool], additions ...inbound.Addition) {
	N.TCPKeepAlive(conn)

	bufConn := N.NewBufferedConn(conn)
	head, err := bufConn.Peek(1)
	if err != nil {
		return
	}

	switch head[0] {
	case socks4.Version:
		socks.HandleSocks4(bufConn, tunnel, additions...)
	case socks5.Version:
		socks.HandleSocks5(bufConn, tunnel, additions...)
	default:
		http.HandleConn(bufConn, tunnel, cache, additions...)
	}
}
