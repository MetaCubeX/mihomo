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
	"github.com/metacubex/mihomo/log"

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

	dialHandler := getDialHandler(c.r, c.proxyAdapter, c.proxyName, options...)
	addr := net.JoinHostPort(ip.String(), c.port)
	conn, err := dialHandler(ctx, network, addr)
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

		dConn := &D.Conn{
			Conn:         conn,
			UDPSize:      c.Client.UDPSize,
			TsigSecret:   c.Client.TsigSecret,
			TsigProvider: c.Client.TsigProvider,
		}

		msg, _, err := c.Client.ExchangeWithConn(m, dConn)

		// Resolvers MUST resend queries over TCP if they receive a truncated UDP response (with TC=1 set)!
		if msg != nil && msg.Truncated && c.Client.Net == "" {
			tcpClient := *c.Client // copy a client
			tcpClient.Net = "tcp"
			network = "tcp"
			log.Debugln("[DNS] Truncated reply from %s:%s for %s over UDP, retrying over TCP", c.host, c.port, m.Question[0].String())
			dConn.Conn, err = dialHandler(ctx, network, addr)
			if err != nil {
				ch <- result{msg, err}
				return
			}
			defer func() {
				_ = conn.Close()
			}()
			msg, _, err = tcpClient.ExchangeWithConn(m, dConn)
		}

		ch <- result{msg, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		return ret.msg, ret.err
	}
}
