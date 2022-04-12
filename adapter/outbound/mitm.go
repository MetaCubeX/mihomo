package outbound

import (
	"context"
	"errors"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"

	"go.uber.org/atomic"
)

var (
	errIgnored      = errors.New("not match in mitm host lists")
	httpProxyClient = NewHttp(HttpOption{})

	MiddlemanServerAddress = atomic.NewString("")
	MiddlemanRewriteHosts  *trie.DomainTrie[bool]
)

type Mitm struct {
	*Base
}

// DialContext implements C.ProxyAdapter
func (d *Mitm) DialContext(ctx context.Context, metadata *C.Metadata, _ ...dialer.Option) (C.Conn, error) {
	addr := MiddlemanServerAddress.Load()
	if addr == "" || MiddlemanRewriteHosts == nil {
		return nil, errIgnored
	}

	if MiddlemanRewriteHosts.Search(metadata.String()) == nil && metadata.DstPort != "80" {
		return nil, errIgnored
	}

	metadata.Type = C.MITM

	if metadata.Host != "" {
		metadata.AddrType = C.AtypDomainName
		metadata.DstIP = nil
	}

	c, err := dialer.DialContext(ctx, "tcp", addr, []dialer.Option{dialer.WithInterface(""), dialer.WithRoutingMark(0)}...)
	if err != nil {
		return nil, err
	}

	tcpKeepAlive(c)

	defer safeConnClose(c, err)

	c, err = httpProxyClient.StreamConn(c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, d), nil
}

func NewMitm() *Mitm {
	return &Mitm{
		Base: &Base{
			name: "Mitm",
			tp:   C.Mitm,
		},
	}
}
