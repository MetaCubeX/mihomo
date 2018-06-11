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

// Writer is used to output network traffic
func (d *DirectAdapter) Writer() io.Writer {
	return d.conn
}

// Reader is used to input network traffic
func (d *DirectAdapter) Reader() io.Reader {
	return d.conn
}

// Close is used to close connection
func (d *DirectAdapter) Close() {
	d.conn.Close()
}

type Direct struct {
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
