package tuic

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/quic-go"

	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/transport/tuic/congestion"
)

const (
	DefaultStreamReceiveWindow     = 15728640 // 15 MB/s
	DefaultConnectionReceiveWindow = 67108864 // 64 MB/s
)

func SetCongestionController(quicConn quic.Connection, cc string) {
	switch cc {
	case "cubic":
		quicConn.SetCongestionControl(
			congestion.NewCubicSender(
				congestion.DefaultClock{},
				congestion.GetInitialPacketSize(quicConn.RemoteAddr()),
				false,
				nil,
			),
		)
	case "new_reno":
		quicConn.SetCongestionControl(
			congestion.NewCubicSender(
				congestion.DefaultClock{},
				congestion.GetInitialPacketSize(quicConn.RemoteAddr()),
				true,
				nil,
			),
		)
	case "bbr":
		quicConn.SetCongestionControl(
			congestion.NewBBRSender(
				congestion.DefaultClock{},
				congestion.GetInitialPacketSize(quicConn.RemoteAddr()),
				congestion.InitialCongestionWindow*congestion.InitialMaxDatagramSize,
				congestion.DefaultBBRMaxCongestionWindow*congestion.InitialMaxDatagramSize,
			),
		)
	}
}

type quicStreamConn struct {
	quic.Stream
	lock  sync.Mutex
	lAddr net.Addr
	rAddr net.Addr

	closeDeferFn func()

	closeOnce sync.Once
	closeErr  error
}

func (q *quicStreamConn) Write(p []byte) (n int, err error) {
	q.lock.Lock()
	defer q.lock.Unlock()
	return q.Stream.Write(p)
}

func (q *quicStreamConn) Close() error {
	q.closeOnce.Do(func() {
		q.closeErr = q.close()
	})
	return q.closeErr
}

func (q *quicStreamConn) close() error {
	if q.closeDeferFn != nil {
		defer q.closeDeferFn()
	}

	// https://github.com/cloudflare/cloudflared/commit/ed2bac026db46b239699ac5ce4fcf122d7cab2cd
	// Make sure a possible writer does not block the lock forever. We need it, so we can close the writer
	// side of the stream safely.
	_ = q.Stream.SetWriteDeadline(time.Now())

	// This lock is eventually acquired despite Write also acquiring it, because we set a deadline to writes.
	q.lock.Lock()
	defer q.lock.Unlock()

	// We have to clean up the receiving stream ourselves since the Close in the bottom does not handle that.
	q.Stream.CancelRead(0)
	return q.Stream.Close()
}

func (q *quicStreamConn) LocalAddr() net.Addr {
	return q.lAddr
}

func (q *quicStreamConn) RemoteAddr() net.Addr {
	return q.rAddr
}

var _ net.Conn = &quicStreamConn{}

type quicStreamPacketConn struct {
	connId    uint32
	quicConn  quic.Connection
	inputConn *N.BufferedConn

	udpRelayMode          string
	maxUdpRelayPacketSize int

	deferQuicConnFn func(quicConn quic.Connection, err error)
	closeDeferFn    func()
	writeClosed     *atomic.Bool

	closeOnce sync.Once
	closeErr  error
	closed    bool
}

func (q *quicStreamPacketConn) Close() error {
	q.closeOnce.Do(func() {
		q.closed = true
		q.closeErr = q.close()
	})
	return q.closeErr
}

func (q *quicStreamPacketConn) close() (err error) {
	if q.closeDeferFn != nil {
		defer q.closeDeferFn()
	}
	if q.deferQuicConnFn != nil {
		defer func() {
			q.deferQuicConnFn(q.quicConn, err)
		}()
	}
	if q.inputConn != nil {
		_ = q.inputConn.Close()
		q.inputConn = nil

		buf := pool.GetBuffer()
		defer pool.PutBuffer(buf)
		err = NewDissociate(q.connId).WriteTo(buf)
		if err != nil {
			return
		}
		var stream quic.SendStream
		stream, err = q.quicConn.OpenUniStream()
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
	}
	return
}

func (q *quicStreamPacketConn) SetDeadline(t time.Time) error {
	//TODO implement me
	return nil
}

func (q *quicStreamPacketConn) SetReadDeadline(t time.Time) error {
	if q.inputConn != nil {
		return q.inputConn.SetReadDeadline(t)
	}
	return nil
}

func (q *quicStreamPacketConn) SetWriteDeadline(t time.Time) error {
	//TODO implement me
	return nil
}

func (q *quicStreamPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if q.inputConn != nil {
		var packet Packet
		packet, err = ReadPacket(q.inputConn)
		if err != nil {
			return
		}
		n = copy(p, packet.DATA)
		addr = packet.ADDR.UDPAddr()
	} else {
		err = net.ErrClosed
	}
	return
}

func (q *quicStreamPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p) > q.maxUdpRelayPacketSize {
		return 0, fmt.Errorf("udp packet too large(%d > %d)", len(p), q.maxUdpRelayPacketSize)
	}
	if q.closed {
		return 0, net.ErrClosed
	}
	if q.writeClosed != nil && q.writeClosed.Load() {
		_ = q.Close()
		return 0, net.ErrClosed
	}
	if q.deferQuicConnFn != nil {
		defer func() {
			q.deferQuicConnFn(q.quicConn, err)
		}()
	}
	addr.String()
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return
	}
	err = NewPacket(q.connId, uint16(len(p)), NewAddressAddrPort(addrPort), p).WriteTo(buf)
	if err != nil {
		return
	}
	switch q.udpRelayMode {
	case "quic":
		var stream quic.SendStream
		stream, err = q.quicConn.OpenUniStream()
		if err != nil {
			return
		}
		defer stream.Close()
		_, err = buf.WriteTo(stream)
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
	return q.quicConn.LocalAddr()
}

var _ net.PacketConn = &quicStreamPacketConn{}
