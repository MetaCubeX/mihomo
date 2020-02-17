package dns

import (
	"context"
	"strings"

	"github.com/Dreamacro/clash/component/dialer"

	D "github.com/miekg/dns"
)

type client struct {
	*D.Client
	r    *Resolver
	addr string
	host string
}

func (c *client) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	return c.ExchangeContext(context.Background(), m)
}

func (c *client) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	network := "udp"
	if strings.HasPrefix(c.Client.Net, "tcp") {
		network = "tcp"
	}

	ip, err := c.r.ResolveIP(c.host)
	if err != nil {
		return nil, err
	}

	d := dialer.Dialer()
	if dialer.DialHook != nil {
		dialer.DialHook(d, network, ip)
	}

	c.Client.Dialer = d

	// miekg/dns ExchangeContext doesn't respond to context cancel.
	// this is a workaround
	type result struct {
		msg *D.Msg
		err error
	}
	ch := make(chan result, 1)
	go func() {
		msg, _, err := c.Client.Exchange(m, c.addr)
		ch <- result{msg, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		return ret.msg, ret.err
	}
}
