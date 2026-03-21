package trusttunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
	"github.com/metacubex/tls"
	"golang.org/x/exp/slices"
)

type RoundTripper interface {
	http.RoundTripper
	CloseIdleConnections()
}

type ResolvUDPFunc func(ctx context.Context, server string) (netip.AddrPort, error)

type ClientOptions struct {
	Dialer                C.Dialer
	ResolvUDP             ResolvUDPFunc
	Server                string
	Username              string
	Password              string
	TLSConfig             *vmess.TLSConfig
	QUIC                  bool
	QUICCongestionControl string
	QUICCwnd              int
	HealthCheck           bool
}

type Client struct {
	ctx              context.Context
	dialer           C.Dialer
	resolv           ResolvUDPFunc
	server           string
	auth             string
	roundTripper     RoundTripper
	startOnce        sync.Once
	healthCheck      bool
	healthCheckTimer *time.Timer
}

func NewClient(ctx context.Context, options ClientOptions) (client *Client, err error) {
	client = &Client{
		ctx:    ctx,
		dialer: options.Dialer,
		resolv: options.ResolvUDP,
		server: options.Server,
		auth:   buildAuth(options.Username, options.Password),
	}
	if options.QUIC {
		if len(options.TLSConfig.NextProtos) == 0 {
			options.TLSConfig.NextProtos = []string{"h3"}
		} else if !slices.Contains(options.TLSConfig.NextProtos, "h3") {
			return nil, errors.New("require alpn h3")
		}
		err = client.quicRoundTripper(options.TLSConfig, options.QUICCongestionControl, options.QUICCwnd)
		if err != nil {
			return nil, err
		}
	} else {
		if len(options.TLSConfig.NextProtos) == 0 {
			options.TLSConfig.NextProtos = []string{"h2"}
		} else if !slices.Contains(options.TLSConfig.NextProtos, "h2") {
			return nil, errors.New("require alpn h2")
		}
		client.h2RoundTripper(options.TLSConfig)
	}
	if options.HealthCheck {
		client.healthCheck = true
	}
	return client, nil
}

func (c *Client) h2RoundTripper(tlsConfig *vmess.TLSConfig) {
	c.roundTripper = &http.Http2Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			conn, err := c.dialer.DialContext(ctx, network, c.server)
			if err != nil {
				return nil, err
			}
			tlsConn, err := vmess.StreamTLSConn(ctx, conn, tlsConfig)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		AllowHTTP:       false,
		IdleConnTimeout: DefaultSessionTimeout,
	}
}

func (c *Client) start() {
	if c.healthCheck {
		c.healthCheckTimer = time.NewTimer(DefaultHealthCheckTimeout)
		go c.loopHealthCheck()
	}
}

func (c *Client) loopHealthCheck() {
	for {
		select {
		case <-c.healthCheckTimer.C:
		case <-c.ctx.Done():
			c.healthCheckTimer.Stop()
			return
		}
		ctx, cancel := context.WithTimeout(c.ctx, DefaultHealthCheckTimeout)
		_ = c.HealthCheck(ctx)
		cancel()
	}
}

func (c *Client) resetHealthCheckTimer() {
	if c.healthCheckTimer == nil {
		return
	}
	c.healthCheckTimer.Reset(DefaultHealthCheckTimeout)
}

func (c *Client) dial(ctx context.Context, request *http.Request, conn *httpConn, pipeReader *io.PipeReader, pipeWriter *io.PipeWriter) {
	c.startOnce.Do(c.start)
	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			conn.SetLocalAddr(connInfo.Conn.LocalAddr())
			conn.SetRemoteAddr(connInfo.Conn.RemoteAddr())
		},
	}
	request = request.WithContext(httptrace.WithClientTrace(ctx, trace))
	response, err := c.roundTripper.RoundTrip(request)
	if err != nil {
		_ = pipeWriter.CloseWithError(err)
		_ = pipeReader.CloseWithError(err)
		conn.setUp(nil, err)
	} else if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		err = fmt.Errorf("unexpected status code: %d", response.StatusCode)
		_ = pipeWriter.CloseWithError(err)
		_ = pipeReader.CloseWithError(err)
		conn.setUp(nil, err)
	} else {
		c.resetHealthCheckTimer()
		conn.setUp(response.Body, nil)
	}
}

func (c *Client) Dial(ctx context.Context, host string) (net.Conn, error) {
	pipeReader, pipeWriter := io.Pipe()
	request := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   host,
		},
		Header: make(http.Header),
		Body:   pipeReader,
		Host:   host,
	}
	request.Header.Add("User-Agent", TCPUserAgent)
	request.Header.Add("Proxy-Authorization", c.auth)
	conn := &tcpConn{
		httpConn: httpConn{
			writer:  pipeWriter,
			created: make(chan struct{}),
		},
	}
	go c.dial(ctx, request, &conn.httpConn, pipeReader, pipeWriter)
	return conn, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	pipeReader, pipeWriter := io.Pipe()
	request := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   UDPMagicAddress,
		},
		Header: make(http.Header),
		Body:   pipeReader,
		Host:   UDPMagicAddress,
	}
	request.Header.Add("User-Agent", UDPUserAgent)
	request.Header.Add("Proxy-Authorization", c.auth)
	conn := &clientPacketConn{
		packetConn: packetConn{
			httpConn: httpConn{
				writer:  pipeWriter,
				created: make(chan struct{}),
			},
		},
	}
	go c.dial(ctx, request, &conn.httpConn, pipeReader, pipeWriter)
	return conn, nil
}

func (c *Client) ListenICMP(ctx context.Context) (*IcmpConn, error) {
	pipeReader, pipeWriter := io.Pipe()
	request := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   ICMPMagicAddress,
		},
		Header: make(http.Header),
		Body:   pipeReader,
		Host:   ICMPMagicAddress,
	}
	request.Header.Add("User-Agent", ICMPUserAgent)
	request.Header.Add("Proxy-Authorization", c.auth)
	conn := &IcmpConn{
		httpConn{
			writer:  pipeWriter,
			created: make(chan struct{}),
		},
	}
	go c.dial(ctx, request, &conn.httpConn, pipeReader, pipeWriter)
	return conn, nil
}

func (c *Client) Close() error {
	forceCloseAllConnections(c.roundTripper)
	if c.healthCheckTimer != nil {
		c.healthCheckTimer.Stop()
	}
	return nil
}

func (c *Client) ResetConnections() {
	forceCloseAllConnections(c.roundTripper)
	c.resetHealthCheckTimer()
}

func (c *Client) HealthCheck(ctx context.Context) error {
	defer c.resetHealthCheckTimer()
	request := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   HealthCheckMagicAddress,
		},
		Header: make(http.Header),
		Host:   HealthCheckMagicAddress,
	}
	request.Header.Add("User-Agent", HealthCheckUserAgent)
	request.Header.Add("Proxy-Authorization", c.auth)
	response, err := c.roundTripper.RoundTrip(request.WithContext(ctx))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}
	return nil
}
