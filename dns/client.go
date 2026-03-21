package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

type client struct {
	port   string
	host   string
	dialer *dnsDialer
	schema string
}

var _ dnsClient = (*client)(nil)

// Address implements dnsClient
func (c *client) Address() string {
	return fmt.Sprintf("%s://%s", c.schema, net.JoinHostPort(c.host, c.port))
}

func (c *client) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	network := "udp"
	if c.schema != "udp" {
		network = "tcp"
	}

	addr := net.JoinHostPort(c.host, c.port)
	conn, err := c.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// miekg/dns ExchangeContext doesn't respond to context cancel.
	// this is a workaround
	type result struct {
		msg *D.Msg
		err error
	}
	ch := make(chan result, 1)
	go func() {
		dClient := &D.Client{
			UDPSize: 4096,
			Timeout: 5 * time.Second,
		}
		dConn := &D.Conn{
			Conn:    conn,
			UDPSize: dClient.UDPSize,
		}

		msg, _, err := dClient.ExchangeWithConn(m, dConn)

		// Resolvers MUST resend queries over TCP if they receive a truncated UDP response (with TC=1 set)!
		if msg != nil && msg.Truncated && network == "udp" {
			network = "tcp"
			log.Debugln("[DNS] Truncated reply from %s:%s for %s over UDP, retrying over TCP", c.host, c.port, m.Question[0].String())
			var tcpConn net.Conn
			tcpConn, err = c.dialer.DialContext(ctx, network, addr)
			if err != nil {
				ch <- result{msg, err}
				return
			}
			defer tcpConn.Close()
			dConn.Conn = tcpConn
			msg, _, err = dClient.ExchangeWithConn(m, dConn)
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

func newClient(addr string, resolver *Resolver, netType string, params map[string]string, proxyAdapter C.ProxyAdapter, proxyName string) *client {
	host, port, _ := net.SplitHostPort(addr)
	c := &client{
		port:   port,
		host:   host,
		dialer: newDNSDialer(resolver, proxyAdapter, proxyName),
		schema: "udp",
	}
	if strings.HasPrefix(netType, "tcp") {
		c.schema = "tcp"
	}
	return c
}
