// Modified from: https://github.com/Qv2ray/gun-lite
// License: MIT

package gun

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/common/httputils"
	"github.com/metacubex/mihomo/common/pool"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
)

const (
	Http2NextProtoTLS = "h2"
)

var (
	ErrInvalidLength = errors.New("invalid length")
	ErrSmallBuffer   = errors.New("buffer too small")
)

var defaultHeader = http.Header{
	"Content-Type": []string{"application/grpc"},
	"User-Agent":   []string{"grpc-go/1.36.0"},
}

type DialFn = func(ctx context.Context, network, addr string) (net.Conn, error)

type Conn struct {
	initFn func(addr *httputils.NetAddr) (io.ReadCloser, error)
	writer io.Writer // writer must not nil
	closer io.Closer
	httputils.NetAddr

	initOnce sync.Once
	initErr  error
	reader   io.ReadCloser
	remain   int

	closeMutex sync.Mutex
	closed     bool
	onClose    func()

	// deadlines
	deadline *time.Timer
}

type Config struct {
	ServiceName  string
	UserAgent    string
	Host         string
	PingInterval int
}

func (g *Conn) initReader() {
	reader, err := g.initFn(&g.NetAddr)
	if err != nil {
		g.initErr = err
		if closer, ok := g.writer.(io.Closer); ok {
			closer.Close()
		}
		return
	}

	g.closeMutex.Lock()
	defer g.closeMutex.Unlock()
	if g.closed { // if g.Close() be called between g.initFn(), direct close the initFn returned reader
		_ = reader.Close()
		g.initErr = net.ErrClosed
		return
	}

	g.reader = reader
}

func (g *Conn) Init() error {
	g.initOnce.Do(g.initReader)
	return g.initErr
}

func (g *Conn) Read(b []byte) (n int, err error) {
	if err = g.Init(); err != nil {
		return
	}
	return g.read(b)
}

func (g *Conn) read(b []byte) (n int, err error) {
	if g.remain > 0 {
		size := g.remain
		if len(b) < size {
			size = len(b)
		}

		n, err = g.reader.Read(b[:size])
		g.remain -= n
		return
	}

	// 0x00 grpclength(uint32) 0x0A uleb128 payload
	var discard [6]byte
	_, err = io.ReadFull(g.reader, discard[:])
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			err = io.EOF
		}
		return 0, err
	}

	protobufPayloadLen, err := ReadUVariant(g.reader)
	if err != nil {
		return 0, ErrInvalidLength
	}
	g.remain = int(protobufPayloadLen)
	return g.read(b)
}

func (g *Conn) Write(b []byte) (n int, err error) {
	dataLen := len(b)
	varLen := UVarintLen(uint64(dataLen))
	buf := pool.Get(5 + 1 + varLen + dataLen)
	defer pool.Put(buf)
	_ = buf[6] // bounds check hint to compiler
	buf[0] = 0x00
	binary.BigEndian.PutUint32(buf[1:5], uint32(1+varLen+dataLen))
	buf[5] = 0x0A
	binary.PutUvarint(buf[6:], uint64(dataLen))
	copy(buf[6+varLen:], b)

	_, err = g.writer.Write(buf)
	if err == io.ErrClosedPipe {
		if initErr := g.Init(); initErr != nil {
			err = initErr
		}
	}

	if flusher, ok := g.writer.(http.Flusher); ok {
		flusher.Flush()
	}

	return len(b), err
}

func (g *Conn) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	dataLen := buffer.Len()
	varLen := UVarintLen(uint64(dataLen))
	header := buffer.ExtendHeader(6 + varLen)
	_ = header[6] // bounds check hint to compiler
	header[0] = 0x00
	binary.BigEndian.PutUint32(header[1:5], uint32(1+varLen+dataLen))
	header[5] = 0x0A
	binary.PutUvarint(header[6:], uint64(dataLen))
	_, err := g.writer.Write(buffer.Bytes())

	if err == io.ErrClosedPipe {
		if initErr := g.Init(); initErr != nil {
			err = initErr
		}
	}

	if flusher, ok := g.writer.(http.Flusher); ok {
		flusher.Flush()
	}

	return err
}

func (g *Conn) FrontHeadroom() int {
	return 6 + binary.MaxVarintLen64
}

func (g *Conn) Close() error {
	g.closeMutex.Lock()
	defer g.closeMutex.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true

	var errorArr []error

	if closer, ok := g.writer.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			errorArr = append(errorArr, err)
		}
	}

	if reader := g.reader; reader != nil {
		if err := reader.Close(); err != nil {
			errorArr = append(errorArr, err)
		}
	}

	if closer := g.closer; closer != nil {
		if err := closer.Close(); err != nil {
			errorArr = append(errorArr, err)
		}
	}

	if g.onClose != nil {
		g.onClose()
	}

	return errors.Join(errorArr...)
}

func (g *Conn) SetReadDeadline(t time.Time) error  { return g.SetDeadline(t) }
func (g *Conn) SetWriteDeadline(t time.Time) error { return g.SetDeadline(t) }

func (g *Conn) SetDeadline(t time.Time) error {
	if t.IsZero() {
		if g.deadline != nil {
			g.deadline.Stop()
			g.deadline = nil
		}
		return nil
	}
	d := time.Until(t)
	if g.deadline != nil {
		g.deadline.Reset(d)
		return nil
	}
	g.deadline = time.AfterFunc(d, func() {
		g.Close()
	})
	return nil
}

type Transport struct {
	transport *http.Transport
	cfg       *Config
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	count     atomic.Int64
}

func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		t.cancel()
		httputils.CloseTransport(t.transport)
	})
	return nil
}

func NewTransport(dialFn DialFn, tlsConfig *vmess.TLSConfig, gunCfg *Config) *Transport {
	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, C.DefaultTLSTimeout)
		defer cancel()
		pconn, err := dialFn(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		if tlsConfig == nil {
			return pconn, nil
		}

		conn, err := vmess.StreamTLSConn(ctx, pconn, tlsConfig)
		if err != nil {
			_ = pconn.Close()
			return nil, err
		}

		if tlsConfig.ShadowTLS == nil && tlsConfig.Restls == nil && tlsConfig.Reality == nil && tlsConfig.TLSMirror == nil { // shadowtls, restls, reality and tlsmirror don't return the negotiated ALPN
			state := tlsC.GetTLSConnectionState(conn)
			if p := state.NegotiatedProtocol; p != Http2NextProtoTLS {
				_ = conn.Close()
				return nil, fmt.Errorf("http2: unexpected ALPN protocol %s, want %s", p, Http2NextProtoTLS)
			}
		}
		return conn, nil
	}

	// use h2c mode to disallow the net/http fallback to http1.1
	//
	// Note that this usage is only applicable to our own net/http fork.
	// The standard library also needs to mask the tls.Conn type for the conn returned by DialTLSContext,
	// see: https://github.com/golang/go/issues/79293#issuecomment-4426393534
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			wrapped, err := dialFunc(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return wrapped, nil
		},
		Protocols:          protocols,
		DisableCompression: true,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: time.Duration(gunCfg.PingInterval) * time.Second, // If zero, no health check is performed,
			PingTimeout:     0,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	wrap := &Transport{
		transport: transport,
		cfg:       gunCfg,
		ctx:       ctx,
		cancel:    cancel,
	}
	return wrap
}

func ServiceNameToPath(serviceName string) string {
	if strings.HasPrefix(serviceName, "/") { // custom paths
		return serviceName
	}
	return "/" + serviceName + "/Tun"
}

func (t *Transport) Dial() (net.Conn, error) {
	serviceName := "GunService"
	if t.cfg.ServiceName != "" {
		serviceName = t.cfg.ServiceName
	}
	path := ServiceNameToPath(serviceName)

	reader, writer := io.Pipe()

	header := defaultHeader.Clone()
	if t.cfg.UserAgent != "" {
		header.Set("User-Agent", t.cfg.UserAgent)
	}

	request := &http.Request{
		Method: http.MethodPost,
		Body:   reader,
		URL: &url.URL{
			Scheme: "https",
			Host:   t.cfg.Host,
			Path:   path,
			// for unescape path
			Opaque: "//" + t.cfg.Host + path,
		},
		Proto:      "HTTP/2",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     header,
	}
	ctx, cancel := context.WithCancel(t.ctx)
	request = request.WithContext(ctx)
	initStarted := make(chan struct{})

	conn := &Conn{
		initFn: func(addr *httputils.NetAddr) (io.ReadCloser, error) {
			close(initStarted)
			request = request.WithContext(httputils.NewAddrContext(addr, request.Context()))
			response, err := t.transport.RoundTrip(request)
			if err != nil {
				cancel()
				return nil, err
			}
			return response.Body, nil
		},
		writer: writer,
	}

	t.count.Add(1)
	conn.onClose = func() {
		cancel()
		t.count.Add(-1)
	}

	go conn.Init()

	// ensure conn.initOnce.Do has been called before return
	// prevent the race caused by the return side immediately calling conn.Close
	<-initStarted

	return conn, nil
}

type Client struct {
	mutex          sync.Mutex
	maxConnections int
	minStreams     int
	maxStreams     int
	transports     []*Transport
	maker          func() *Transport
}

func NewClient(maker func() *Transport, maxConnections, minStreams, maxStreams int) *Client {
	if maxConnections == 0 && minStreams == 0 && maxStreams == 0 {
		maxConnections = 1
	}
	return &Client{
		maxConnections: maxConnections,
		minStreams:     minStreams,
		maxStreams:     maxStreams,
		maker:          maker,
	}
}

func (c *Client) Dial() (net.Conn, error) {
	return c.getTransport().Dial()
}

func (c *Client) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var errs []error
	for _, t := range c.transports {
		if err := t.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	c.transports = nil
	return errors.Join(errs...)
}

func (c *Client) getTransport() *Transport {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var transport *Transport
	for _, t := range c.transports {
		if transport == nil || t.count.Load() < transport.count.Load() {
			transport = t
		}
	}
	if transport == nil {
		return c.newTransportLocked()
	}
	numStreams := int(transport.count.Load())
	if numStreams == 0 {
		return transport
	}
	if c.maxConnections > 0 {
		if len(c.transports) >= c.maxConnections || numStreams < c.minStreams {
			return transport
		}
	} else {
		if c.maxStreams > 0 && numStreams < c.maxStreams {
			return transport
		}
	}
	return c.newTransportLocked()
}

func (c *Client) newTransportLocked() *Transport {
	transport := c.maker()
	c.transports = append(c.transports, transport)
	return transport
}

func StreamGunWithConn(conn net.Conn, tlsConfig *vmess.TLSConfig, gunCfg *Config) (net.Conn, error) {
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return conn, nil
	}

	transport := NewTransport(dialFn, tlsConfig, gunCfg)
	c, err := transport.Dial()
	if err != nil {
		return nil, err
	}
	if c, ok := c.(*Conn); ok { // The incoming net.Conn should be closed synchronously with the generated gun.Conn
		c.closer = conn
	}
	return c, nil
}
