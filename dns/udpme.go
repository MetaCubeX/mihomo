package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	C "github.com/metacubex/mihomo/constant"
	D "github.com/miekg/dns"
)

type udpmeClient struct {
	port   string
	host   string
	dialer *dnsDialer
}

func newUdpme(addr string, resolver *Resolver, proxyAdapter C.ProxyAdapter, proxyName string) *udpmeClient {
	host, port, _ := net.SplitHostPort(addr)
	c := &udpmeClient{
		port:   port,
		host:   host,
		dialer: newDNSDialer(resolver, proxyAdapter, proxyName),
	}
	return c
}

func (c *udpmeClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	network := "udp"
	addr := net.JoinHostPort(c.host, c.port)
	conn, err := c.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	mc := m.Copy()
	if mc.IsEdns0() == nil {
		mc.SetEdns0(512, false)
	}

	type result struct {
		msg *D.Msg
		err error
	}
	ch := make(chan result, 1)
	go func() {
		dConn := &D.Conn{
			Conn: conn,
		}
		dConn.SetDeadline(time.Now().Add(5 * time.Second))

		if err := dConn.WriteMsg(mc); err != nil {
			ch <- result{nil, err}
			return
		}

		for {
			msg, err := dConn.ReadMsg()
			if err != nil {
				ch <- result{nil, err}
				return
			}
			if msg.IsEdns0() == nil {
				continue
			}
			ch <- result{msg, nil}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		return ret.msg, ret.err
	}
}

func (c *udpmeClient) Address() string {
	return fmt.Sprintf("udpme://%s", net.JoinHostPort(c.host, c.port))
}

func (c *udpmeClient) ResetConnection() {}
