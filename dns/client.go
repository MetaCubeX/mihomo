package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	D "github.com/miekg/dns"
	"github.com/zhangyunhao116/fastrand"
)

type client struct {
	*D.Client
	r            *Resolver
	port         string
	host         string
	iface        string
	proxyAdapter C.ProxyAdapter
	proxyName    string
	addr         string
}

var _ dnsClient = (*client)(nil)

// Address implements dnsClient
func (c *client) Address() string {
	if len(c.addr) != 0 {
		return c.addr
	}
	schema := "udp"
	if strings.HasPrefix(c.Client.Net, "tcp") {
		schema = "tcp"
		if strings.HasSuffix(c.Client.Net, "tls") {
			schema = "tls"
		}
	}

	c.addr = fmt.Sprintf("%s://%s", schema, net.JoinHostPort(c.host, c.port))
	return c.addr
}

func (c *client) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	var (
		ip  netip.Addr
		err error
	)
	if c.r == nil {
		// a default ip dns
		if ip, err = netip.ParseAddr(c.host); err != nil {
			return nil, fmt.Errorf("dns %s not a valid ip", c.host)
		}
	} else {
		ips, err := resolver.LookupIPWithResolver(ctx, c.host, c.r)
		if err != nil {
			return nil, fmt.Errorf("use default dns resolve failed: %w", err)
		} else if len(ips) == 0 {
			return nil, fmt.Errorf("%w: %s", resolver.ErrIPNotFound, c.host)
		}
		ip = ips[fastrand.Intn(len(ips))]
	}

	network := "udp"
	if strings.HasPrefix(c.Client.Net, "tcp") {
		network = "tcp"
	}

	var options []dialer.Option
	if c.iface != "" {
		options = append(options, dialer.WithInterface(c.iface))
	}

	conn, err := getDialHandler(c.r, c.proxyAdapter, c.proxyName, options...)(ctx, network, net.JoinHostPort(ip.String(), c.port))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.Close()
	}()

	// miekg/dns ExchangeContext doesn't respond to context cancel.
	// this is a workaround
	type result struct {
		msg *D.Msg
		err error
	}
	ch := make(chan result, 1)
	go func() {
		if strings.HasSuffix(c.Client.Net, "tls") {
			conn = tls.Client(conn, ca.GetGlobalTLSConfig(c.Client.TLSConfig))
		}

		msg, _, err := c.Client.ExchangeWithConn(m, &D.Conn{
			Conn:         conn,
			UDPSize:      c.Client.UDPSize,
			TsigSecret:   c.Client.TsigSecret,
			TsigProvider: c.Client.TsigProvider,
		})

		ch <- result{msg, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		return ret.msg, ret.err
	}
}
