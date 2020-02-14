package dns

import (
	"context"

	"github.com/Dreamacro/clash/component/dialer"

	D "github.com/miekg/dns"
)

type client struct {
	*D.Client
	Address string
}

func (c *client) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	return c.ExchangeContext(context.Background(), m)
}

func (c *client) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	c.Client.Dialer = dialer.Dialer()

	// miekg/dns ExchangeContext doesn't respond to context cancel.
	// this is a workaround
	type result struct {
		msg *D.Msg
		err error
	}
	ch := make(chan result, 1)
	go func() {
		msg, _, err := c.Client.ExchangeContext(ctx, m, c.Address)
		ch <- result{msg, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		return ret.msg, ret.err
	}
}
