package adapters

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"

	C "github.com/Dreamacro/clash/constant"

	"github.com/riobard/go-shadowsocks2/socks"
)

// Socks5Adapter is a shadowsocks adapter
type Socks5Adapter struct {
	conn net.Conn
}

// Close is used to close connection
func (ss *Socks5Adapter) Close() {
	ss.conn.Close()
}

func (ss *Socks5Adapter) Conn() net.Conn {
	return ss.conn
}

type Socks5 struct {
	addr string
	name string
}

func (ss *Socks5) Name() string {
	return ss.name
}

func (ss *Socks5) Type() C.AdapterType {
	return C.Socks5
}

func (ss *Socks5) Generator(addr *C.Addr) (adapter C.ProxyAdapter, err error) {
	c, err := net.Dial("tcp", ss.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error", ss.addr)
	}
	c.(*net.TCPConn).SetKeepAlive(true)

	if err := ss.sharkHand(addr, c); err != nil {
		return nil, err
	}
	return &Socks5Adapter{conn: c}, nil
}

func (ss *Socks5) sharkHand(addr *C.Addr, rw io.ReadWriter) error {
	buf := make([]byte, socks.MaxAddrLen)

	// VER, CMD, RSV
	_, err := rw.Write([]byte{5, 1, 0})
	if err != nil {
		return err
	}

	if _, err := io.ReadFull(rw, buf[:2]); err != nil {
		return err
	}

	if buf[0] != 5 {
		return errors.New("SOCKS version error")
	} else if buf[1] != 0 {
		return errors.New("SOCKS need auth")
	}

	// VER, CMD, RSV, ADDR
	if _, err := rw.Write(bytes.Join([][]byte{[]byte{5, 1, 0}, serializesSocksAddr(addr)}, []byte(""))); err != nil {
		return err
	}

	if _, err := io.ReadFull(rw, buf[:10]); err != nil {
		return err
	}

	return nil
}

func NewSocks5(name, addr string) *Socks5 {
	return &Socks5{
		addr: addr,
		name: name,
	}
}
