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
func (m *Mitm) DialContext(ctx context.Context, metadata *C.Metadata, _ ...dialer.Option) (C.Conn, error) {
	c, err := net.DialTCP("tcp", nil, m.serverAddr)
	if err != nil {
		return nil, err
	}

	_ = c.SetKeepAlive(true)
	_ = c.SetKeepAlivePeriod(60 * time.Second)

	metadata.Type = C.MITM

	hc, err := m.httpProxyClient.StreamConnContext(ctx, c, metadata)
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	return NewConn(hc, m), nil
}

func NewMitm(serverAddr string) *Mitm {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", serverAddr)
	http, _ := NewHttp(HttpOption{})
	return &Mitm{
		Base: &Base{
			name: "Mitm",
			tp:   C.Mitm,
		},
		serverAddr:      tcpAddr,
		httpProxyClient: http,
	}
}
