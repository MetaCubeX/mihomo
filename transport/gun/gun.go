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

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/common/pool"
	tlsC "github.com/metacubex/mihomo/component/tls"

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
	initFn  func() (io.ReadCloser, error)
	writer  io.Writer
	flusher http.Flusher
	netAddr

	reader io.ReadCloser
	once   sync.Once
	close  atomic.Bool
	err    error
	remain int
	br     *bufio.Reader
	// deadlines
	deadline *time.Timer
}

type Config struct {
	ServiceName       string
	Host              string
	ClientFingerprint string
}

func (g *Conn) initReader() {
	reader, err := g.initFn()
	if err != nil {
		g.err = err
		if closer, ok := g.writer.(io.Closer); ok {
			closer.Close()
		}
		return
	}

	if !g.close.Load() {
		g.reader = reader
		g.br = bufio.NewReader(reader)
	} else {
		reader.Close()
	}
}

func (g *Conn) Init() error {
	g.once.Do(g.initReader)
	return g.err
}

func (g *Conn) Read(b []byte) (n int, err error) {
	if err = g.Init(); err != nil {
		return
	}

	if g.remain > 0 {
		size := g.remain
		if len(b) < size {
			size = len(b)
		}

		n, err = io.ReadFull(g.br, b[:size])
		g.remain -= n
		return
	} else if g.reader == nil {
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

	if g.flusher != nil {
		g.flusher.Flush()
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

	if err == io.ErrClosedPipe && g.err != nil {
		err = g.err
	}

	if g.flusher != nil {
		g.flusher.Flush()
	}

	return err
}

func (g *Conn) FrontHeadroom() int {
	return 6 + binary.MaxVarintLen64
}

func (g *Conn) Close() error {
	g.close.Store(true)
	if reader := g.reader; reader != nil {
		reader.Close()
	}

	if closer, ok := g.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

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

func NewHTTP2Client(dialFn DialFn, tlsConfig *tls.Config, Fingerprint string, realityConfig *tlsC.RealityConfig) *TransportWrap {
	wrap := TransportWrap{}

	dialFunc := func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		pconn, err := dialFn(network, addr)
		if err != nil {
			return nil, err
		}
		wrap.remoteAddr = pconn.RemoteAddr()
		wrap.localAddr = pconn.LocalAddr()

		if tlsConfig == nil {
			return pconn, nil
		}

		if len(Fingerprint) != 0 {
			if realityConfig == nil {
				if fingerprint, exists := tlsC.GetFingerprint(Fingerprint); exists {
					utlsConn := tlsC.UClient(pconn, cfg, fingerprint)
					if err := utlsConn.HandshakeContext(ctx); err != nil {
						pconn.Close()
						return nil, err
					}
					state := utlsConn.ConnectionState()
					if p := state.NegotiatedProtocol; p != http2.NextProtoTLS {
						utlsConn.Close()
						return nil, fmt.Errorf("http2: unexpected ALPN protocol %s, want %s", p, http2.NextProtoTLS)
					}
					return utlsConn, nil
				}
			} else {
				realityConn, err := tlsC.GetRealityConn(ctx, pconn, Fingerprint, cfg, realityConfig)
				if err != nil {
					pconn.Close()
					return nil, err
				}
				//state := realityConn.(*utls.UConn).ConnectionState()
				//if p := state.NegotiatedProtocol; p != http2.NextProtoTLS {
				//	realityConn.Close()
				//	return nil, fmt.Errorf("http2: unexpected ALPN protocol %s, want %s", p, http2.NextProtoTLS)
				//}
				return realityConn, nil
			}
		}
		if realityConfig != nil {
			return nil, errors.New("REALITY is based on uTLS, please set a client-fingerprint")
		}

		conn := tls.Client(pconn, cfg)
		if err := conn.HandshakeContext(ctx); err != nil {
			pconn.Close()
			return nil, err
		}
		state := conn.ConnectionState()
		if p := state.NegotiatedProtocol; p != http2.NextProtoTLS {
			conn.Close()
			return nil, fmt.Errorf("http2: unexpected ALPN protocol %s, want %s", p, http2.NextProtoTLS)
		}
		return conn, nil
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
		initFn: func() (io.ReadCloser, error) {
			response, err := transport.RoundTrip(request)
			if err != nil {
				return nil, err
			}
			return response.Body, nil
		},
		writer:  writer,
		netAddr: transport.netAddr,
	}

	go conn.Init()
	return conn, nil
}

func StreamGunWithConn(conn net.Conn, tlsConfig *tls.Config, cfg *Config, realityConfig *tlsC.RealityConfig) (net.Conn, error) {
	dialFn := func(network, addr string) (net.Conn, error) {
		return conn, nil
	}

	transport := NewHTTP2Client(dialFn, tlsConfig, cfg.ClientFingerprint, realityConfig)
	return StreamGunWithTransport(transport, cfg)
}
