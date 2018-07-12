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

// Conn is used to http request
func (d *DirectAdapter) Conn() net.Conn {
	return d.conn
}

type Direct struct {
	traffic *C.Traffic
}

func (d *Direct) Name() string {
	return "Direct"
}

func (d *Direct) Type() C.AdapterType {
	return C.Direct
}

func (d *Direct) Generator(addr *C.Addr) (adapter C.ProxyAdapter, err error) {
	c, err := net.Dial("tcp", net.JoinHostPort(addr.String(), addr.Port))
	if err != nil {
		return
	}
	c.(*net.TCPConn).SetKeepAlive(true)
	return &DirectAdapter{conn: NewTrafficTrack(c, d.traffic)}, nil
}

func NewDirect(traffic *C.Traffic) *Direct {
	return &Direct{traffic: traffic}
}
