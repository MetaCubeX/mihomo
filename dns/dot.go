package dns

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/deque"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/tls"
	D "github.com/miekg/dns"
)

const maxOldDotConns = 8

type dnsOverTLS struct {
	port           string
	host           string
	dialer         *dnsDialer
	skipCertVerify bool
	disableReuse   bool

	access      sync.Mutex
	connections deque.Deque[net.Conn] // LIFO
}

var _ dnsClient = (*dnsOverTLS)(nil)

// Address implements dnsClient
func (t *dnsOverTLS) Address() string {
	return fmt.Sprintf("tls://%s", net.JoinHostPort(t.host, t.port))
}

func (t *dnsOverTLS) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	// miekg/dns ExchangeContext doesn't respond to context cancel.
	// this is a workaround
	type result struct {
		msg *D.Msg
		err error
	}
	ch := make(chan result, 1)

	go func() {
		var msg *D.Msg
		var err error
		defer func() { ch <- result{msg, err} }()
		for { // retry loop; only retry when reusing old conn
			err = ctx.Err() // check context first
			if err != nil {
				return
			}

			var conn net.Conn
			isOldConn := true

			if !t.disableReuse {
				t.access.Lock()
				if t.connections.Len() > 0 {
					conn = t.connections.PopBack()
				}
				t.access.Unlock()
			}

			if conn == nil {
				conn, err = t.dialContext(ctx)
				if err != nil {
					return
				}
				isOldConn = false
			}

			dClient := &D.Client{
				UDPSize: 4096,
				Timeout: 5 * time.Second,
			}
			dConn := &D.Conn{
				Conn:    conn,
				UDPSize: dClient.UDPSize,
			}

			msg, _, err = dClient.ExchangeWithConn(m, dConn)
			if err != nil {
				_ = conn.Close()
				conn = nil
				if isOldConn { // retry
					continue
				}
				return
			}

			if !t.disableReuse {
				t.access.Lock()
				if t.connections.Len() >= maxOldDotConns {
					oldConn := t.connections.PopFront()
					go oldConn.Close() // close in a new goroutine, not blocking the current task
				}
				t.connections.PushBack(conn)
				t.access.Unlock()
			} else {
				_ = conn.Close()
			}
			return
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		return ret.msg, ret.err
	}
}

func (t *dnsOverTLS) dialContext(ctx context.Context) (net.Conn, error) {
	conn, err := t.dialer.DialContext(ctx, "tcp", net.JoinHostPort(t.host, t.port))
	if err != nil {
		return nil, err
	}

	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         t.host,
			InsecureSkipVerify: t.skipCertVerify,
		},
	})
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	conn = tlsConn

	return conn, nil
}

func (t *dnsOverTLS) ResetConnection() {
	if !t.disableReuse {
		t.access.Lock()
		for t.connections.Len() > 0 {
			oldConn := t.connections.PopFront()
			go oldConn.Close() // close in a new goroutine, not blocking the current task
		}
		t.access.Unlock()
	}
}

func (t *dnsOverTLS) Close() error {
	runtime.SetFinalizer(t, nil)
	t.ResetConnection()
	return nil
}

func newDoTClient(addr string, resolver *Resolver, params map[string]string, proxyAdapter C.ProxyAdapter, proxyName string) *dnsOverTLS {
	host, port, _ := net.SplitHostPort(addr)
	c := &dnsOverTLS{
		port:   port,
		host:   host,
		dialer: newDNSDialer(resolver, proxyAdapter, proxyName),
	}
	c.connections.SetBaseCap(maxOldDotConns)
	if params["skip-cert-verify"] == "true" {
		c.skipCertVerify = true
	}
	if params["disable-reuse"] == "true" {
		c.disableReuse = true
	}
	runtime.SetFinalizer(c, (*dnsOverTLS).Close)
	return c
}
