package trusttunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
	"github.com/metacubex/mihomo/common/once"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
	"golang.org/x/exp/slices"
)

type DialOptionsFunc func() []dialer.Option

type ClientOptions struct {
	Dialer                C.Dialer
	DialOptions           DialOptionsFunc // for quic
	Server                string
	Username              string
	Password              string
	TLSConfig             *vmess.TLSConfig
	QUIC                  bool
	QUICCongestionControl string
	QUICCwnd              int
	QUICBBRProfile        string
	HealthCheck           bool
	MaxConnections        int
	MinStreams            int
	MaxStreams            int
}

type Client struct {
	ctx              context.Context
	dialer           C.Dialer
	dialOptions      DialOptionsFunc
	server           string
	auth             string
	roundTripper     http.RoundTripper
	startOnce        sync.Once
	healthCheck      bool
	healthCheckTimer *time.Timer
	count            atomic.Int64
}

func NewClient(ctx context.Context, options ClientOptions) (client *Client, err error) {
	client = &Client{
		ctx:         ctx,
		dialer:      options.Dialer,
		dialOptions: options.DialOptions,
		server:      options.Server,
		auth:        buildAuth(options.Username, options.Password),
	}
	if options.QUIC {
		if len(options.TLSConfig.NextProtos) == 0 {
			options.TLSConfig.NextProtos = []string{"h3"}
		} else if !slices.Contains(options.TLSConfig.NextProtos, "h3") {
			return nil, errors.New("require alpn h3")
		}
		err = client.quicRoundTripper(options.TLSConfig, options.QUICCongestionControl, options.QUICCwnd, options.QUICBBRProfile)
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

func (c *Client) roundTrip(request *http.Request, conn *httpConn) {
	c.startOnce.Do(c.start)
	pipeReader, pipeWriter := io.Pipe()
	request.Body = pipeReader
	*conn = httpConn{
		writer:  pipeWriter,
		created: make(chan struct{}),
	}
	c.count.Add(1)
	conn.closeFn = once.OnceFunc(func() {
		c.count.Add(-1)
	})
	ctx, cancel := context.WithCancel(c.ctx) // requestCtx must alive during conn not closed
	conn.cancelFn = cancel                   // cancel ctx when conn closed
	go func() {
		timeout := time.AfterFunc(C.DefaultTCPTimeout, cancel) // only cancel when RoundTrip timeout
		defer timeout.Stop()                                   // RoundTrip already returned, stop the timer
		request = request.WithContext(httputils.NewAddrContext(&conn.NetAddr, ctx))
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
	}()
}

func (c *Client) newConnectRequest(host, userAgent string) *http.Request {
	request := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   c.server, // Use the proxy server authority so the pool keys reuse against the actual proxy endpoint.
		},
		Header: make(http.Header),
		Host:   host, // Send the actual CONNECT target as the Host header (:authority).
	}
	request.Header.Add("User-Agent", userAgent)
	request.Header.Add("Proxy-Authorization", c.auth)
	return request
}

func (c *Client) Dial(ctx context.Context, host string) (net.Conn, error) {
	request := c.newConnectRequest(host, TCPUserAgent)
	conn := &tcpConn{}
	c.roundTrip(request, &conn.httpConn)
	return conn, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	request := c.newConnectRequest(UDPMagicAddress, UDPUserAgent)
	conn := &clientPacketConn{}
	c.roundTrip(request, &conn.httpConn)
	return conn, nil
}

func (c *Client) ListenICMP(ctx context.Context) (*IcmpConn, error) {
	request := c.newConnectRequest(ICMPMagicAddress, ICMPUserAgent)
	conn := &IcmpConn{}
	c.roundTrip(request, &conn.httpConn)
	return conn, nil
}

func (c *Client) Close() error {
	httputils.CloseTransport(c.roundTripper)
	if c.healthCheckTimer != nil {
		c.healthCheckTimer.Stop()
	}
	return nil
}

func (c *Client) ResetConnections() {
	httputils.CloseTransport(c.roundTripper)
	c.resetHealthCheckTimer()
}

func (c *Client) HealthCheck(ctx context.Context) error {
	defer c.resetHealthCheckTimer()
	request := c.newConnectRequest(HealthCheckMagicAddress, HealthCheckUserAgent)
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

type PoolClient struct {
	mutex          sync.Mutex
	maxConnections int
	minStreams     int
	maxStreams     int
	ctx            context.Context
	options        ClientOptions
	clients        []*Client
}

func NewPoolClient(ctx context.Context, options ClientOptions) (*PoolClient, error) {
	maxConnections := options.MaxConnections
	minStreams := options.MinStreams
	maxStreams := options.MaxStreams
	if maxConnections == 0 && minStreams == 0 && maxStreams == 0 {
		maxConnections = 8
		minStreams = 5
	}
	client, err := NewClient(ctx, options) // reserve one client and verify the configuration
	if err != nil {
		return nil, err
	}
	return &PoolClient{
		maxConnections: maxConnections,
		minStreams:     minStreams,
		maxStreams:     maxStreams,
		ctx:            ctx,
		options:        options,
		clients:        []*Client{client},
	}, nil
}

func (c *PoolClient) Dial(ctx context.Context, host string) (net.Conn, error) {
	transport, err := c.getClient()
	if err != nil {
		return nil, err
	}
	return transport.Dial(ctx, host)
}

func (c *PoolClient) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	transport, err := c.getClient()
	if err != nil {
		return nil, err
	}
	return transport.ListenPacket(ctx)
}

func (c *PoolClient) ListenICMP(ctx context.Context) (*IcmpConn, error) {
	transport, err := c.getClient()
	if err != nil {
		return nil, err
	}
	return transport.ListenICMP(ctx)
}

func (c *PoolClient) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var errs []error
	for _, t := range c.clients {
		if err := t.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	c.clients = nil
	return errors.Join(errs...)
}

func (c *PoolClient) getClient() (*Client, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var transport *Client
	for _, t := range c.clients {
		if transport == nil || t.count.Load() < transport.count.Load() {
			transport = t
		}
	}
	if transport == nil {
		return c.newTransportLocked()
	}
	numStreams := int(transport.count.Load())
	if numStreams == 0 {
		return transport, nil
	}
	if c.maxConnections > 0 {
		if len(c.clients) >= c.maxConnections || numStreams < c.minStreams {
			return transport, nil
		}
	} else {
		if c.maxStreams > 0 && numStreams < c.maxStreams {
			return transport, nil
		}
	}
	return c.newTransportLocked()
}

func (c *PoolClient) newTransportLocked() (*Client, error) {
	transport, err := NewClient(c.ctx, c.options)
	if err != nil {
		return nil, err
	}
	c.clients = append(c.clients, transport)
	return transport, nil
}
