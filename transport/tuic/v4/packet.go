package v4

import (
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/metacubex/quic-go"
)

type quicStreamPacketConn struct {
	connId    uint32
	quicConn  quic.Connection
	inputConn *N.BufferedConn

	udpRelayMode          common.UdpRelayMode
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

func (q *quicStreamPacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	if q.inputConn != nil {
		var packet Packet
		packet, err = ReadPacket(q.inputConn)
		if err != nil {
			return
		}
		data = packet.DATA
		addr = packet.ADDR.UDPAddr()
	} else {
		err = net.ErrClosed
	}
	return
}

func (q *quicStreamPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if q.udpRelayMode != common.QUIC && len(p) > q.maxUdpRelayPacketSize {
		return 0, quic.ErrMessageTooLarge(q.maxUdpRelayPacketSize)
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
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	address, err := NewAddressNetAddr(addr)
	if err != nil {
		return
	}
	err = NewPacket(q.connId, uint16(len(p)), address, p).WriteTo(buf)
	if err != nil {
		return
	}
	switch q.udpRelayMode {
	case common.QUIC:
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
		data := buf.Bytes()
		err = q.quicConn.SendDatagram(data)
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

var _ net.PacketConn = (*quicStreamPacketConn)(nil)
