package outbound

import (
	"context"
	"errors"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
)

var (
	errIgnored      = errors.New("not match in mitm host lists")
	httpProxyClient = NewHttp(HttpOption{})

	MiddlemanRewriteHosts *trie.DomainTrie[bool]
)

type Mitm struct {
	*Base
	serverAddr string
}

// DialContext implements C.ProxyAdapter
func (m *Mitm) DialContext(ctx context.Context, metadata *C.Metadata, _ ...dialer.Option) (C.Conn, error) {
	if MiddlemanRewriteHosts == nil {
		return nil, errIgnored
	}

	if MiddlemanRewriteHosts.Search(metadata.String()) == nil && metadata.DstPort != "80" {
		return nil, errIgnored
	}

	metadata.Type = C.MITM

	c, err := dialer.DialContext(ctx, "tcp", m.serverAddr, []dialer.Option{dialer.WithInterface(""), dialer.WithRoutingMark(0), dialer.WithDirect()}...)
	if err != nil {
		return nil, err
	}

	tcpKeepAlive(c)

	defer safeConnClose(c, err)

	c, err = httpProxyClient.StreamConn(c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, m), nil
}

func NewMitm(serverAddr string) *Mitm {
	return &Mitm{
		Base: &Base{
			name: "Mitm",
			tp:   C.Mitm,
		},
		serverAddr: serverAddr,
	}
}
