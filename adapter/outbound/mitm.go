package outbound

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
)

var (
	errIgnored      = errors.New("not match in mitm host lists")
	httpProxyClient = NewHttp(HttpOption{})
	rewriteHosts    *trie.DomainTrie[bool]
)

type Mitm struct {
	*Base
	serverAddr *net.TCPAddr
}

// DialContext implements C.ProxyAdapter
func (m *Mitm) DialContext(_ context.Context, metadata *C.Metadata, _ ...dialer.Option) (C.Conn, error) {
	if (rewriteHosts == nil || rewriteHosts.Search(metadata.String()) == nil) && metadata.DstPort != "80" {
		return nil, errIgnored
	}

	c, err := net.DialTCP("tcp", nil, m.serverAddr)
	if err != nil {
		return nil, err
	}

	_ = c.SetKeepAlive(true)
	_ = c.SetKeepAlivePeriod(60 * time.Second)

	metadata.Type = C.MITM

	hc, err := httpProxyClient.StreamConn(c, metadata)
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
		serverAddr: tcpAddr,
	}
}

func UpdateRewriteHosts(hosts *trie.DomainTrie[bool]) {
	rewriteHosts = hosts
}
