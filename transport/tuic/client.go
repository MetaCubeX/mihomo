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
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

var (
	ClientClosed       = errors.New("tuic: client closed")
	TooManyOpenStreams = errors.New("tuic: too many open streams")
)

type DialFunc func(ctx context.Context, dialer C.Dialer) (pc net.PacketConn, addr net.Addr, err error)

type ClientOption struct {
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

type clientImpl struct {
	*ClientOption
	udp bool

	quicConn  quic.Connection
	connMutex sync.Mutex

	openStreams atomic.Int64
	closed      atomic.Bool

	udpInputMap sync.Map

	// only ready for PoolClient
	dialerRef   C.Dialer
	lastVisited time.Time
}

func (t *clientImpl) getQuicConn(ctx context.Context, dialer C.Dialer, dialFn DialFunc) (quic.Connection, error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.quicConn != nil {
		return t.quicConn, nil
	}
	pc, addr, err := dialFn(ctx, dialer)
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

func (t *clientImpl) sendAuthentication(quicConn quic.Connection) (err error) {
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

func (t *clientImpl) parseUDP(quicConn quic.Connection) (err error) {
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

func (t *clientImpl) deferQuicConn(quicConn quic.Connection, err error) {
	var netError net.Error
	if err != nil && errors.As(err, &netError) {
		t.forceClose(quicConn, err)
	}
}

func (t *clientImpl) forceClose(quicConn quic.Connection, err error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if quicConn == nil {
		quicConn = t.quicConn
	}
	if quicConn != nil {
		if quicConn == t.quicConn {
			t.quicConn = nil
		}
	}
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	if quicConn != nil {
		_ = quicConn.CloseWithError(ProtocolError, errStr)
	}
	udpInputMap := &t.udpInputMap
	udpInputMap.Range(func(key, value any) bool {
		if conn, ok := value.(net.Conn); ok {
			_ = conn.Close()
		}
		udpInputMap.Delete(key)
		return true
	})
}

func (t *clientImpl) Close() {
	t.closed.Store(true)
	if t.openStreams.Load() == 0 {
		t.forceClose(nil, ClientClosed)
	}
}

func (t *clientImpl) DialContextWithDialer(ctx context.Context, metadata *C.Metadata, dialer C.Dialer, dialFn DialFunc) (net.Conn, error) {
	quicConn, err := t.getQuicConn(ctx, dialer, dialFn)
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
			closeDeferFn: func() {
				time.AfterFunc(C.DefaultTCPTimeout, func() {
					openStreams := t.openStreams.Add(-1)
					if openStreams == 0 && t.closed.Load() {
						t.forceClose(quicConn, ClientClosed)
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

func (t *clientImpl) ListenPacketWithDialer(ctx context.Context, metadata *C.Metadata, dialer C.Dialer, dialFn DialFunc) (net.PacketConn, error) {
	quicConn, err := t.getQuicConn(ctx, dialer, dialFn)
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
		inputConn:             N.NewBufferedConn(pipe2),
		udpRelayMode:          t.UdpRelayMode,
		maxUdpRelayPacketSize: t.MaxUdpRelayPacketSize,
		deferQuicConnFn:       t.deferQuicConn,
		closeDeferFn: func() {
			t.udpInputMap.Delete(connId)
			time.AfterFunc(C.DefaultUDPTimeout, func() {
				openStreams := t.openStreams.Add(-1)
				if openStreams == 0 && t.closed.Load() {
					t.forceClose(quicConn, ClientClosed)
				}
			})
		},
	}
	return pc, nil
}

type Client struct {
	*clientImpl // use an independent pointer to let Finalizer can work no matter somewhere handle an influence in clientImpl inner
}

func (t *Client) DialContextWithDialer(ctx context.Context, metadata *C.Metadata, dialer C.Dialer, dialFn DialFunc) (net.Conn, error) {
	conn, err := t.clientImpl.DialContextWithDialer(ctx, metadata, dialer, dialFn)
	if err != nil {
		return nil, err
	}
	return N.NewRefConn(conn, t), err
}

func (t *Client) ListenPacketWithDialer(ctx context.Context, metadata *C.Metadata, dialer C.Dialer, dialFn DialFunc) (net.PacketConn, error) {
	pc, err := t.clientImpl.ListenPacketWithDialer(ctx, metadata, dialer, dialFn)
	if err != nil {
		return nil, err
	}
	return N.NewRefPacketConn(pc, t), nil
}

func (t *Client) forceClose() {
	t.clientImpl.forceClose(nil, ClientClosed)
}

func NewClient(clientOption *ClientOption, udp bool) *Client {
	ci := &clientImpl{
		ClientOption: clientOption,
		udp:          udp,
	}
	c := &Client{ci}
	runtime.SetFinalizer(c, closeClient)
	log.Debugln("New Tuic Client at %p", c)
	return c
}

func closeClient(client *Client) {
	log.Debugln("Close Tuic Client at %p", client)
	client.forceClose()
}
