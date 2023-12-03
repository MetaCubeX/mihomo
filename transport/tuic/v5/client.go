package v5

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	atomic2 "github.com/metacubex/mihomo/common/atomic"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/metacubex/quic-go"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/zhangyunhao116/fastrand"
)

type ClientOption struct {
	TlsConfig             *tls.Config
	QuicConfig            *quic.Config
	Uuid                  [16]byte
	Password              string
	UdpRelayMode          common.UdpRelayMode
	CongestionController  string
	ReduceRtt             bool
	MaxUdpRelayPacketSize int
	MaxOpenStreams        int64
	CWND                  int
}

type clientImpl struct {
	*ClientOption
	udp bool

	quicConn  quic.Connection
	connMutex sync.Mutex

	openStreams atomic.Int64
	closed      atomic.Bool

	udpInputMap xsync.MapOf[uint16, net.Conn]

	// only ready for PoolClient
	dialerRef   C.Dialer
	lastVisited atomic2.TypedValue[time.Time]
}

func (t *clientImpl) OpenStreams() int64 {
	return t.openStreams.Load()
}

func (t *clientImpl) DialerRef() C.Dialer {
	return t.dialerRef
}

func (t *clientImpl) LastVisited() time.Time {
	return t.lastVisited.Load()
}

func (t *clientImpl) SetLastVisited(last time.Time) {
	t.lastVisited.Store(last)
}

func (t *clientImpl) getQuicConn(ctx context.Context, dialer C.Dialer, dialFn common.DialFunc) (quic.Connection, error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.quicConn != nil {
		return t.quicConn, nil
	}
	transport, addr, err := dialFn(ctx, dialer)
	if err != nil {
		return nil, err
	}
	var quicConn quic.Connection
	if t.ReduceRtt {
		quicConn, err = transport.DialEarly(ctx, addr, t.TlsConfig, t.QuicConfig)
	} else {
		quicConn, err = transport.Dial(ctx, addr, t.TlsConfig, t.QuicConfig)
	}
	if err != nil {
		return nil, err
	}

	common.SetCongestionController(quicConn, t.CongestionController, t.CWND)

	go func() {
		_ = t.sendAuthentication(quicConn)
	}()

	if t.udp && t.UdpRelayMode == common.QUIC {
		go func() {
			_ = t.handleUniStream(quicConn)
		}()
	}
	go func() {
		_ = t.handleMessage(quicConn) // always handleMessage because tuicV5 using datagram to send the Heartbeat
	}()

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
	token, err := GenToken(quicConn.ConnectionState(), t.Uuid, t.Password)
	if err != nil {
		return err
	}
	err = NewAuthenticate(t.Uuid, token).WriteTo(buf)
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

func (t *clientImpl) handleUniStream(quicConn quic.Connection) (err error) {
	defer func() {
		t.deferQuicConn(quicConn, err)
	}()
	for {
		var stream quic.ReceiveStream
		stream, err = quicConn.AcceptUniStream(context.Background())
		if err != nil {
			return err
		}
		go func() (err error) {
			var assocId uint16
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
			commandHead, err := ReadCommandHead(reader)
			if err != nil {
				return
			}
			switch commandHead.TYPE {
			case PacketType:
				var packet Packet
				packet, err = ReadPacketWithHead(commandHead, reader)
				if err != nil {
					return
				}
				if t.udp && t.UdpRelayMode == common.QUIC {
					assocId = packet.ASSOC_ID
					if val, ok := t.udpInputMap.Load(assocId); ok {
						if conn, ok := val.(net.Conn); ok {
							writer := bufio.NewWriterSize(conn, packet.BytesLen())
							_ = packet.WriteTo(writer)
							_ = writer.Flush()
						}
					}
				}
			}
			return
		}()
	}
}

func (t *clientImpl) handleMessage(quicConn quic.Connection) (err error) {
	defer func() {
		t.deferQuicConn(quicConn, err)
	}()
	for {
		var message []byte
		message, err = quicConn.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		go func() (err error) {
			var assocId uint16
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
			reader := bytes.NewBuffer(message)
			commandHead, err := ReadCommandHead(reader)
			if err != nil {
				return
			}
			switch commandHead.TYPE {
			case PacketType:
				var packet Packet
				packet, err = ReadPacketWithHead(commandHead, reader)
				if err != nil {
					return
				}
				if t.udp && t.UdpRelayMode == common.NATIVE {
					assocId = packet.ASSOC_ID
					if val, ok := t.udpInputMap.Load(assocId); ok {
						if conn, ok := val.(net.Conn); ok {
							_, _ = conn.Write(message)
						}
					}
				}
			case HeartbeatType:
				var heartbeat Heartbeat
				heartbeat, err = ReadHeartbeatWithHead(commandHead, reader)
				if err != nil {
					return
				}
				heartbeat.BytesLen()
			}
			return
		}()
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
	udpInputMap.Range(func(key uint16, value net.Conn) bool {
		conn := value
		_ = conn.Close()
		udpInputMap.Delete(key)
		return true
	})
}

func (t *clientImpl) Close() {
	t.closed.Store(true)
	if t.openStreams.Load() == 0 {
		t.forceClose(nil, common.ClientClosed)
	}
}

func (t *clientImpl) DialContextWithDialer(ctx context.Context, metadata *C.Metadata, dialer C.Dialer, dialFn common.DialFunc) (net.Conn, error) {
	quicConn, err := t.getQuicConn(ctx, dialer, dialFn)
	if err != nil {
		return nil, err
	}
	openStreams := t.openStreams.Add(1)
	if openStreams >= t.MaxOpenStreams {
		t.openStreams.Add(-1)
		return nil, common.TooManyOpenStreams
	}
	stream, err := func() (stream net.Conn, err error) {
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
		stream = common.NewQuicStreamConn(
			quicStream,
			quicConn.LocalAddr(),
			quicConn.RemoteAddr(),
			func() {
				time.AfterFunc(C.DefaultTCPTimeout, func() {
					openStreams := t.openStreams.Add(-1)
					if openStreams == 0 && t.closed.Load() {
						t.forceClose(quicConn, common.ClientClosed)
					}
				})
			},
		)
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

	return stream, nil
}

func (t *clientImpl) ListenPacketWithDialer(ctx context.Context, metadata *C.Metadata, dialer C.Dialer, dialFn common.DialFunc) (net.PacketConn, error) {
	quicConn, err := t.getQuicConn(ctx, dialer, dialFn)
	if err != nil {
		return nil, err
	}
	openStreams := t.openStreams.Add(1)
	if openStreams >= t.MaxOpenStreams {
		t.openStreams.Add(-1)
		return nil, common.TooManyOpenStreams
	}

	pipe1, pipe2 := net.Pipe()
	var connId uint16
	for {
		connId = uint16(fastrand.Intn(0xFFFF))
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
					t.forceClose(quicConn, common.ClientClosed)
				}
			})
		},
	}
	return pc, nil
}

type Client struct {
	*clientImpl // use an independent pointer to let Finalizer can work no matter somewhere handle an influence in clientImpl inner
}

func (t *Client) DialContextWithDialer(ctx context.Context, metadata *C.Metadata, dialer C.Dialer, dialFn common.DialFunc) (net.Conn, error) {
	conn, err := t.clientImpl.DialContextWithDialer(ctx, metadata, dialer, dialFn)
	if err != nil {
		return nil, err
	}
	return N.NewRefConn(conn, t), err
}

func (t *Client) ListenPacketWithDialer(ctx context.Context, metadata *C.Metadata, dialer C.Dialer, dialFn common.DialFunc) (net.PacketConn, error) {
	pc, err := t.clientImpl.ListenPacketWithDialer(ctx, metadata, dialer, dialFn)
	if err != nil {
		return nil, err
	}
	return N.NewRefPacketConn(pc, t), nil
}

func (t *Client) forceClose() {
	t.clientImpl.forceClose(nil, common.ClientClosed)
}

func NewClient(clientOption *ClientOption, udp bool, dialerRef C.Dialer) *Client {
	ci := &clientImpl{
		ClientOption: clientOption,
		udp:          udp,
		dialerRef:    dialerRef,
		udpInputMap:  *xsync.NewMapOf[uint16, net.Conn](),
	}
	c := &Client{ci}
	runtime.SetFinalizer(c, closeClient)
	log.Debugln("New TuicV5 Client at %p", c)
	return c
}

func closeClient(client *Client) {
	log.Debugln("Close TuicV5 Client at %p", client)
	client.forceClose()
}
