package redir

import (
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
)

type Listener struct {
	listener net.Listener
	addr     string
	closed   bool
	name string 
	preferRulesName string
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

func New(addr string, in chan<- C.ConnContext) (*Listener, error) {
	return NewWithInfos(addr,"DEFAULT-REDIR","",in)
}

func NewWithInfos(addr,name,preferRulesName string, in chan<- C.ConnContext) (*Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	rl := &Listener{
		listener: l,
		addr:     addr,
		name: name,
		preferRulesName: preferRulesName,
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if rl.closed {
					break
				}
				continue
			}
			go handleRedir(rl.name,rl.preferRulesName,c, in)
		}
	}()

	return rl, nil
}
func handleRedir(name,preferRulesName string,conn net.Conn, in chan<- C.ConnContext) {
	target, err := parserPacket(conn)
	if err != nil {
		conn.Close()
		return
	}
	conn.(*net.TCPConn).SetKeepAlive(true)
	in <- inbound.NewSocketWithInfos(target, conn, C.REDIR,name,preferRulesName)
}
