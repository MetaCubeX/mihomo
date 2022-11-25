package tuic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/quic-go"

	N "github.com/Dreamacro/clash/common/net"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/tuic/congestion"
)

type Client struct {
	TlsConfig             *tls.Config
	QuicConfig            *quic.Config
	Host                  string
	Token                 [32]byte
	UdpRelayMode          string
	CongestionController  string
	ReduceRtt             bool
	RequestTimeout        int
	MaxUdpRelayPacketSize int

	LastVisited time.Time

	quicConn  quic.Connection
	connMutex sync.Mutex

	udpInputMap sync.Map
}

func (t *Client) getQuicConn(ctx context.Context, dialFn func(ctx context.Context) (net.PacketConn, net.Addr, error)) (quic.Connection, error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.quicConn != nil {
		return t.quicConn, nil
	}
	pc, addr, err := dialFn(ctx)
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

	switch t.CongestionController {
	case "cubic":
		quicConn.SetCongestionControl(
			congestion.NewCubicSender(
				congestion.DefaultClock{},
				congestion.GetMaxPacketSize(quicConn.RemoteAddr()),
				false,
				nil,
			),
		)
	case "new_reno":
		quicConn.SetCongestionControl(
			congestion.NewCubicSender(
				congestion.DefaultClock{},
				congestion.GetMaxPacketSize(quicConn.RemoteAddr()),
				true,
				nil,
			),
		)
	case "bbr":
		quicConn.SetCongestionControl(
			congestion.NewBBRSender(
				congestion.DefaultClock{},
				congestion.GetMaxPacketSize(quicConn.RemoteAddr()),
				congestion.InitialCongestionWindow,
				congestion.DefaultBBRMaxCongestionWindow,
			),
		)
	}

	sendAuthentication := func(quicConn quic.Connection) (err error) {
		defer func() {
			t.deferQuicConn(quicConn, err)
		}()
		stream, err := quicConn.OpenUniStream()
		if err != nil {
			return err
		}
		buf := &bytes.Buffer{}
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

	go sendAuthentication(quicConn)

	go func(quicConn quic.Connection) (err error) {
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
	}(quicConn)

	t.quicConn = quicConn
	return quicConn, nil
}

func (t *Client) deferQuicConn(quicConn quic.Connection, err error) {
	var netError net.Error
	if err != nil && errors.As(err, &netError) {
		t.connMutex.Lock()
		defer t.connMutex.Unlock()
		if t.quicConn == quicConn {
			t.Close(err)
		}
	}
}

func (t *Client) Close(err error) {
	quicConn := t.quicConn
	if quicConn != nil {
		_ = t.quicConn.CloseWithError(ProtocolError, err.Error())
		t.udpInputMap.Range(func(key, value any) bool {
			if conn, ok := value.(net.Conn); ok {
				_ = conn.Close()
			}
			return true
		})
		t.udpInputMap = sync.Map{} // new one
		t.quicConn = nil
	}
}

func (t *Client) DialContext(ctx context.Context, metadata *C.Metadata, dialFn func(ctx context.Context) (net.PacketConn, net.Addr, error)) (net.Conn, error) {
	quicConn, err := t.getQuicConn(ctx, dialFn)
	if err != nil {
		return nil, err
	}
	stream, err := func() (stream quic.Stream, err error) {
		defer func() {
			t.deferQuicConn(quicConn, err)
		}()
		buf := &bytes.Buffer{}
		err = NewConnect(NewAddress(metadata)).WriteTo(buf)
		if err != nil {
			return nil, err
		}
		stream, err = quicConn.OpenStream()
		if err != nil {
			return nil, err
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

	if t.RequestTimeout > 0 {
		_ = stream.SetReadDeadline(time.Now().Add(time.Duration(t.RequestTimeout) * time.Millisecond))
	}
	conn := N.NewBufferedConn(&quicStreamConn{stream, quicConn.LocalAddr(), quicConn.RemoteAddr(), t})
	response, err := ReadResponse(conn)
	if err != nil {
		return nil, err
	}
	if response.IsFailed() {
		_ = stream.Close()
		return nil, errors.New("connect failed")
	}
	_ = stream.SetReadDeadline(time.Time{})
	return conn, err
}

type quicStreamConn struct {
	quic.Stream
	lAddr  net.Addr
	rAddr  net.Addr
	client *Client
}

func (q *quicStreamConn) LocalAddr() net.Addr {
	return q.lAddr
}

func (q *quicStreamConn) RemoteAddr() net.Addr {
	return q.rAddr
}

var _ net.Conn = &quicStreamConn{}

func (t *Client) ListenPacketContext(ctx context.Context, metadata *C.Metadata, dialFn func(ctx context.Context) (net.PacketConn, net.Addr, error)) (net.PacketConn, error) {
	quicConn, err := t.getQuicConn(ctx, dialFn)
	if err != nil {
		return nil, err
	}

	pipe1, pipe2 := net.Pipe()
	inputCh := make(chan udpData)
	var connId uint32
	for {
		connId = rand.Uint32()
		_, loaded := t.udpInputMap.LoadOrStore(connId, pipe1)
		if !loaded {
			break
		}
	}
	pc := &quicStreamPacketConn{
		connId:    connId,
		quicConn:  quicConn,
		lAddr:     quicConn.LocalAddr(),
		client:    t,
		inputConn: N.NewBufferedConn(pipe2),
		inputCh:   inputCh,
	}
	return pc, nil
}

type udpData struct {
	data []byte
	addr net.Addr
	err  error
}

type quicStreamPacketConn struct {
	connId    uint32
	quicConn  quic.Connection
	lAddr     net.Addr
	client    *Client
	inputConn *N.BufferedConn
	inputCh   chan udpData

	closeOnce sync.Once
	closeErr  error
}

func (q *quicStreamPacketConn) Close() error {
	q.closeOnce.Do(func() {
		q.closeErr = q.close()
	})
	return q.closeErr
}

func (q *quicStreamPacketConn) close() (err error) {
	defer func() {
		q.client.deferQuicConn(q.quicConn, err)
	}()
	buf := &bytes.Buffer{}
	err = NewDissociate(q.connId).WriteTo(buf)
	if err != nil {
		return
	}
	stream, err := q.quicConn.OpenUniStream()
	if err != nil {
		return
	}
	_, err = buf.WriteTo(stream)
	if err != nil {
		return
	}
	err = stream.Close()
	if err != nil {
		return
	}
	return
}

func (q *quicStreamPacketConn) SetDeadline(t time.Time) error {
	//TODO implement me
	return nil
}

func (q *quicStreamPacketConn) SetReadDeadline(t time.Time) error {
	return q.inputConn.SetReadDeadline(t)
}

func (q *quicStreamPacketConn) SetWriteDeadline(t time.Time) error {
	//TODO implement me
	return nil
}

func (q *quicStreamPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, err := ReadPacket(q.inputConn)
	if err != nil {
		return
	}
	n = copy(p, packet.DATA)
	addr = packet.ADDR.UDPAddr()
	return
}

func (q *quicStreamPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p) > q.client.MaxUdpRelayPacketSize {
		return 0, fmt.Errorf("udp packet too large(%d > %d)", len(p), q.client.MaxUdpRelayPacketSize)
	}
	defer func() {
		q.client.deferQuicConn(q.quicConn, err)
	}()
	addr.String()
	buf := &bytes.Buffer{}
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return
	}
	err = NewPacket(q.connId, uint16(len(p)), NewAddressAddrPort(addrPort), p).WriteTo(buf)
	if err != nil {
		return
	}
	switch q.client.UdpRelayMode {
	case "quic":
		var stream quic.SendStream
		stream, err = q.quicConn.OpenUniStream()
		if err != nil {
			return
		}
		_, err = buf.WriteTo(stream)
		if err != nil {
			_ = stream.Close()
			return
		}
		err = stream.Close()
		if err != nil {
			return
		}
	default: // native
		err = q.quicConn.SendMessage(buf.Bytes())
		if err != nil {
			return
		}
	}
	n = len(p)

	return
}

func (q *quicStreamPacketConn) LocalAddr() net.Addr {
	return q.lAddr
}

var _ net.PacketConn = &quicStreamPacketConn{}
