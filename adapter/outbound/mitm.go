package outbound

import (
	"context"
	"net"
	"time"

	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
)

type Mitm struct {
	*Base
	serverAddr      *net.TCPAddr
	httpProxyClient *Http
}

// DialContext implements C.ProxyAdapter
func (m *Mitm) DialContext(_ context.Context, metadata *C.Metadata, _ ...dialer.Option) (C.Conn, error) {
	c, err := net.DialTCP("tcp", nil, m.serverAddr)
	if err != nil {
		return nil, err
	}

	_ = c.SetKeepAlive(true)
	_ = c.SetKeepAlivePeriod(60 * time.Second)
	_ = c.SetLinger(0)

	metadata.Type = C.MITM

	hc, err := m.httpProxyClient.StreamConn(c, metadata)
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	return NewConn(hc, m), nil
}

func NewMitm(serverAddr string) *Mitm {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", serverAddr)
	return &Mitm{
		Base: &Base{
			name: "Mitm",
			tp:   C.Mitm,
		},
		serverAddr:      tcpAddr,
		httpProxyClient: NewHttp(HttpOption{}),
	}
}
