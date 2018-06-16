package adapters

import (
	"io"
	"net"

	C "github.com/Dreamacro/clash/constant"
)

// DirectAdapter is a directly connected adapter
type DirectAdapter struct {
	conn net.Conn
}

// ReadWriter is used to handle network traffic
func (d *DirectAdapter) ReadWriter() io.ReadWriter {
	return d.conn
}

// Close is used to close connection
func (d *DirectAdapter) Close() {
	d.conn.Close()
}

// Close is used to close connection
func (d *DirectAdapter) Conn() net.Conn {
	return d.conn
}

type Direct struct {
}

func (d *Direct) Name() string {
	return "Direct"
}

func (d *Direct) Generator(addr *C.Addr) (adapter C.ProxyAdapter, err error) {
	c, err := net.Dial("tcp", net.JoinHostPort(addr.String(), addr.Port))
	if err != nil {
		return
	}
	c.(*net.TCPConn).SetKeepAlive(true)
	return &DirectAdapter{conn: c}, nil
}

func NewDirect() *Direct {
	return &Direct{}
}
