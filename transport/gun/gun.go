// Modified from: https://github.com/Qv2ray/gun-lite
// License: MIT

package gun

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Dreamacro/clash/common/buf"
	"github.com/Dreamacro/clash/common/pool"

	"go.uber.org/atomic"
	"golang.org/x/net/http2"
)

var (
	ErrInvalidLength = errors.New("invalid length")
	ErrSmallBuffer   = errors.New("buffer too small")
)

var defaultHeader = http.Header{
	"content-type": []string{"application/grpc"},
	"user-agent":   []string{"grpc-go/1.36.0"},
}

type DialFn = func(network, addr string) (net.Conn, error)

type Conn struct {
	response  *http.Response
	request   *http.Request
	transport *TransportWrap
	writer    *io.PipeWriter
	once      sync.Once
	close     *atomic.Bool
	err       error
	remain    int
	br        *bufio.Reader
	// deadlines
	deadline *time.Timer
}

type Config struct {
	ServiceName string
	Host        string
}

func (g *Conn) initRequest() {
	response, err := g.transport.RoundTrip(g.request)
	if err != nil {
		g.err = err
		g.writer.Close()
		return
	}

	if !g.close.Load() {
		g.response = response
		g.br = bufio.NewReader(response.Body)
	} else {
		response.Body.Close()
	}
}

func (g *Conn) Read(b []byte) (n int, err error) {
	g.once.Do(g.initRequest)
	if g.err != nil {
		return 0, g.err
	}

	if g.remain > 0 {
		size := g.remain
		if len(b) < size {
			size = len(b)
		}

		n, err = io.ReadFull(g.br, b[:size])
		g.remain -= n
		return
	} else if g.response == nil {
		return 0, net.ErrClosed
	}

	// 0x00 grpclength(uint32) 0x0A uleb128 payload
	_, err = g.br.Discard(6)
	if err != nil {
		return 0, err
	}

	protobufPayloadLen, err := binary.ReadUvarint(g.br)
	if err != nil {
		return 0, ErrInvalidLength
	}

	size := int(protobufPayloadLen)
	if len(b) < size {
		size = len(b)
	}

	n, err = io.ReadFull(g.br, b[:size])
	if err != nil {
		return
	}

	remain := int(protobufPayloadLen) - n
	if remain > 0 {
		g.remain = remain
	}

	return n, nil
}

func (g *Conn) Write(b []byte) (n int, err error) {
	protobufHeader := [binary.MaxVarintLen64 + 1]byte{0x0A}
	varuintSize := binary.PutUvarint(protobufHeader[1:], uint64(len(b)))
	var grpcHeader [5]byte
	grpcPayloadLen := uint32(varuintSize + 1 + len(b))
	binary.BigEndian.PutUint32(grpcHeader[1:5], grpcPayloadLen)

	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	buf.Write(grpcHeader[:])
	buf.Write(protobufHeader[:varuintSize+1])
	buf.Write(b)

	_, err = g.writer.Write(buf.Bytes())
	if err == io.ErrClosedPipe && g.err != nil {
		err = g.err
	}

	return len(b), err
}

func (g *Conn) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	dataLen := buffer.Len()
	varLen := UVarintLen(uint64(dataLen))
	header := buffer.ExtendHeader(6 + varLen)
	header[0] = 0x00
	binary.BigEndian.PutUint32(header[1:5], uint32(1+varLen+dataLen))
	header[5] = 0x0A
	binary.PutUvarint(header[6:], uint64(dataLen))
	_, err := g.writer.Write(buffer.Bytes())

	if err == io.ErrClosedPipe && g.err != nil {
		err = g.err
	}

	return err
}

func (g *Conn) FrontHeadroom() int {
	return 6 + binary.MaxVarintLen64
}

func (g *Conn) Close() error {
	g.close.Store(true)
	if r := g.response; r != nil {
		r.Body.Close()
	}

	return g.writer.Close()
}

func (g *Conn) LocalAddr() net.Addr                { return g.transport.LocalAddr() }
func (g *Conn) RemoteAddr() net.Addr               { return g.transport.RemoteAddr() }
func (g *Conn) SetReadDeadline(t time.Time) error  { return g.SetDeadline(t) }
func (g *Conn) SetWriteDeadline(t time.Time) error { return g.SetDeadline(t) }

func (g *Conn) SetDeadline(t time.Time) error {
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

func NewHTTP2Client(dialFn DialFn, tlsConfig *tls.Config) *TransportWrap {
	wrap := TransportWrap{}
	dialFunc := func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		pconn, err := dialFn(network, addr)
		if err != nil {
			return nil, err
		}

		wrap.remoteAddr = pconn.RemoteAddr()
		cn := tls.Client(pconn, cfg)
		if err := cn.HandshakeContext(ctx); err != nil {
			pconn.Close()
			return nil, err
		}
		state := cn.ConnectionState()
		if p := state.NegotiatedProtocol; p != http2.NextProtoTLS {
			cn.Close()
			return nil, fmt.Errorf("http2: unexpected ALPN protocol %s, want %s", p, http2.NextProtoTLS)
		}
		return cn, nil
	}

	wrap.Transport = &http2.Transport{
		DialTLSContext:     dialFunc,
		TLSClientConfig:    tlsConfig,
		AllowHTTP:          false,
		DisableCompression: true,
		PingTimeout:        0,
	}

	return &wrap
}

func StreamGunWithTransport(transport *TransportWrap, cfg *Config) (net.Conn, error) {
	serviceName := "GunService"
	if cfg.ServiceName != "" {
		serviceName = cfg.ServiceName
	}

	reader, writer := io.Pipe()
	request := &http.Request{
		Method: http.MethodPost,
		Body:   reader,
		URL: &url.URL{
			Scheme: "https",
			Host:   cfg.Host,
			Path:   fmt.Sprintf("/%s/Tun", serviceName),
			// for unescape path
			Opaque: fmt.Sprintf("//%s/%s/Tun", cfg.Host, serviceName),
		},
		Proto:      "HTTP/2",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     defaultHeader,
	}

	conn := &Conn{
		request:   request,
		transport: transport,
		writer:    writer,
		close:     atomic.NewBool(false),
	}

	go conn.once.Do(conn.initRequest)
	return conn, nil
}

func StreamGunWithConn(conn net.Conn, tlsConfig *tls.Config, cfg *Config) (net.Conn, error) {
	dialFn := func(network, addr string) (net.Conn, error) {
		return conn, nil
	}

	transport := NewHTTP2Client(dialFn, tlsConfig)
	return StreamGunWithTransport(transport, cfg)
}
