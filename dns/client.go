package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

type client struct {
	*D.Client
	port   string
	host   string
	dialer *dnsDialer
	addr   string
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
	network := "udp"
	if strings.HasPrefix(c.Client.Net, "tcp") {
		network = "tcp"
	}

	addr := net.JoinHostPort(c.host, c.port)
	conn, err := c.dialer.DialContext(ctx, network, addr)
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
			dConn.Conn, err = c.dialer.DialContext(ctx, network, addr)
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

func (c *client) ResetConnection() {}
