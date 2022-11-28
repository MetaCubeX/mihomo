package tuic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/quic-go"

	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
)

var (
	ClientClosed       = errors.New("tuic: client closed")
	TooManyOpenStreams = errors.New("tuic: too many open streams")
)

type ClientOption struct {
	DialFn func(ctx context.Context, opts ...dialer.Option) (pc net.PacketConn, addr net.Addr, err error)

	TlsConfig             *tls.Config
	QuicConfig            *quic.Config
	Host                  string
	Token                 [32]byte
	UdpRelayMode          string
	CongestionController  string
	ReduceRtt             bool
	RequestTimeout        time.Duration
	MaxUdpRelayPacketSize int
	FastOpen              bool
	MaxOpenStreams        int64
}

type Client struct {
	*ClientOption
	udp bool

	quicConn  quic.Connection
	connMutex sync.Mutex

	openStreams atomic.Int64
	closed      atomic.Bool

	udpInputMap sync.Map

	// only ready for PoolClient
	poolRef     *PoolClient
	optionRef   any
	lastVisited time.Time
}

func (t *Client) getQuicConn(ctx context.Context) (quic.Connection, error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.quicConn != nil {
		return t.quicConn, nil
	}
	pc, addr, err := t.DialFn(ctx)
	if err != nil {
		return nil, err
	}
	var quicConn quic.Connection
	if t.ReduceRtt {
		quicConn, err = quic.DialEarlyContext(ctx, pc, addr, t.Host, t.TlsConfig, t.QuicConfig)
	} else {
		quicConn, err = quic.DialContext(ctx, pc, addr, t.Host, t.TlsConfig, t.QuicConfig)
	}
	if err != nil {
		return nil, err
	}

	SetCongestionController(quicConn, t.CongestionController)

	go func() {
		_ = t.sendAuthentication(quicConn)
	}()

	if t.udp {
		go func() {
			_ = t.parseUDP(quicConn)
		}()
	}

	t.quicConn = quicConn
	t.openStreams.Store(0)
	return quicConn, nil
}

func (t *Client) sendAuthentication(quicConn quic.Connection) (err error) {
	defer func() {
		t.deferQuicConn(quicConn, err)
	}()
	stream, err := quicConn.OpenUniStream()
	if err != nil {
		return err
	}
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	err = NewAuthenticate(t.Token).WriteTo(buf)
	if err != nil {
		return err
	}
	_, err = buf.WriteTo(stream)
	if err != nil {
		return err
	}
	err = stream.Close()
	if err != nil {
		return
	}
	return nil
}

func (t *Client) parseUDP(quicConn quic.Connection) (err error) {
	defer func() {
		t.deferQuicConn(quicConn, err)
	}()
	switch t.UdpRelayMode {
	case "quic":
		for {
			var stream quic.ReceiveStream
			stream, err = quicConn.AcceptUniStream(context.Background())
			if err != nil {
				return err
			}
			go func() (err error) {
				var assocId uint32
				defer func() {
					t.deferQuicConn(quicConn, err)
					if err != nil && assocId != 0 {
						if val, ok := t.udpInputMap.LoadAndDelete(assocId); ok {
							if conn, ok := val.(net.Conn); ok {
								_ = conn.Close()
							}
						}
					}
					stream.CancelRead(0)
				}()
				reader := bufio.NewReader(stream)
				packet, err := ReadPacket(reader)
				if err != nil {
					return
				}
				assocId = packet.ASSOC_ID
				if val, ok := t.udpInputMap.Load(assocId); ok {
					if conn, ok := val.(net.Conn); ok {
						writer := bufio.NewWriterSize(conn, packet.BytesLen())
						_ = packet.WriteTo(writer)
						_ = writer.Flush()
					}
				}
				return
			}()
		}
	default: // native
		for {
			var message []byte
			message, err = quicConn.ReceiveMessage()
			if err != nil {
				return err
			}
			go func() (err error) {
				var assocId uint32
				defer func() {
					t.deferQuicConn(quicConn, err)
					if err != nil && assocId != 0 {
						if val, ok := t.udpInputMap.LoadAndDelete(assocId); ok {
							if conn, ok := val.(net.Conn); ok {
								_ = conn.Close()
							}
						}
					}
				}()
				buffer := bytes.NewBuffer(message)
				packet, err := ReadPacket(buffer)
				if err != nil {
					return
				}
				assocId = packet.ASSOC_ID
				if val, ok := t.udpInputMap.Load(assocId); ok {
					if conn, ok := val.(net.Conn); ok {
						_, _ = conn.Write(message)
					}
				}
				return
			}()
		}
	}
}

func (t *Client) deferQuicConn(quicConn quic.Connection, err error) {
	var netError net.Error
	if err != nil && errors.As(err, &netError) {
		t.connMutex.Lock()
		defer t.connMutex.Unlock()
		if t.quicConn == quicConn {
			t.forceClose(err, true)
		}
	}
}

func (t *Client) forceClose(err error, locked bool) {
	if !locked {
		t.connMutex.Lock()
		defer t.connMutex.Unlock()
	}
	quicConn := t.quicConn
	if quicConn != nil {
		_ = quicConn.CloseWithError(ProtocolError, err.Error())
		t.udpInputMap.Range(func(key, value any) bool {
			if conn, ok := value.(net.Conn); ok {
				_ = conn.Close()
			}
			t.udpInputMap.Delete(key)
			return true
		})
		t.quicConn = nil
	}
}

func (t *Client) Close() {
	t.closed.Store(true)
	if t.openStreams.Load() == 0 {
		t.forceClose(ClientClosed, false)
	}
}

func (t *Client) DialContext(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	quicConn, err := t.getQuicConn(ctx)
	if err != nil {
		return nil, err
	}
	openStreams := t.openStreams.Add(1)
	if openStreams >= t.MaxOpenStreams {
		t.openStreams.Add(-1)
		return nil, TooManyOpenStreams
	}
	stream, err := func() (stream *quicStreamConn, err error) {
		defer func() {
			t.deferQuicConn(quicConn, err)
		}()
		buf := pool.GetBuffer()
		defer pool.PutBuffer(buf)
		err = NewConnect(NewAddress(metadata)).WriteTo(buf)
		if err != nil {
			return nil, err
		}
		quicStream, err := quicConn.OpenStream()
		if err != nil {
			return nil, err
		}
		stream = &quicStreamConn{
			Stream: quicStream,
			lAddr:  quicConn.LocalAddr(),
			rAddr:  quicConn.RemoteAddr(),
			ref:    t,
			closeDeferFn: func() {
				time.AfterFunc(C.DefaultTCPTimeout, func() {
					openStreams := t.openStreams.Add(-1)
					if openStreams == 0 && t.closed.Load() {
						t.forceClose(ClientClosed, false)
					}
				})
			},
		}
		_, err = buf.WriteTo(stream)
		if err != nil {
			_ = stream.Close()
			return nil, err
		}
		return stream, err
	}()
	if err != nil {
		return nil, err
	}

	conn := &earlyConn{BufferedConn: N.NewBufferedConn(stream), RequestTimeout: t.RequestTimeout}
	if !t.FastOpen {
		err = conn.Response()
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

type earlyConn struct {
	*N.BufferedConn
	resOnce sync.Once
	resErr  error

	RequestTimeout time.Duration
}

func (conn *earlyConn) response() error {
	if conn.RequestTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(conn.RequestTimeout))
	}
	response, err := ReadResponse(conn)
	if err != nil {
		_ = conn.Close()
		return err
	}
	if response.IsFailed() {
		_ = conn.Close()
		return errors.New("connect failed")
	}
	_ = conn.SetReadDeadline(time.Time{})
	return nil
}

func (conn *earlyConn) Response() error {
	conn.resOnce.Do(func() {
		conn.resErr = conn.response()
	})
	return conn.resErr
}

func (conn *earlyConn) Read(b []byte) (n int, err error) {
	err = conn.Response()
	if err != nil {
		return 0, err
	}
	return conn.BufferedConn.Read(b)
}

func (t *Client) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error) {
	quicConn, err := t.getQuicConn(ctx)
	if err != nil {
		return nil, err
	}
	openStreams := t.openStreams.Add(1)
	if openStreams >= t.MaxOpenStreams {
		t.openStreams.Add(-1)
		return nil, TooManyOpenStreams
	}

	pipe1, pipe2 := net.Pipe()
	var connId uint32
	for {
		connId = rand.Uint32()
		_, loaded := t.udpInputMap.LoadOrStore(connId, pipe1)
		if !loaded {
			break
		}
	}
	pc := &quicStreamPacketConn{
		connId:                connId,
		quicConn:              quicConn,
		lAddr:                 quicConn.LocalAddr(),
		inputConn:             N.NewBufferedConn(pipe2),
		udpRelayMode:          t.UdpRelayMode,
		maxUdpRelayPacketSize: t.MaxUdpRelayPacketSize,
		ref:                   t,
		deferQuicConnFn:       t.deferQuicConn,
		closeDeferFn: func() {
			t.udpInputMap.Delete(connId)
			time.AfterFunc(C.DefaultUDPTimeout, func() {
				openStreams := t.openStreams.Add(-1)
				if openStreams == 0 && t.closed.Load() {
					t.forceClose(ClientClosed, false)
				}
			})
		},
	}
	return pc, nil
}

func NewClient(clientOption *ClientOption, udp bool) *Client {
	c := &Client{
		ClientOption: clientOption,
		udp:          udp,
	}
	runtime.SetFinalizer(c, closeClient)
	return c
}

func closeClient(client *Client) {
	client.forceClose(ClientClosed, false)
}
