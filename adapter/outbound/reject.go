package outbound

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
)

type Reject struct {
	*Base
	drop bool
}

type RejectOption struct {
	Name string `proxy:"name"`
}

// DialContext implements C.ProxyAdapter
func (r *Reject) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	if r.drop {
		c, _ := net.Pipe()
		_ = c.SetDeadline(time.Now().Add(C.DefaultDropTime))
		return NewConn(c, r), nil
	}
	return NewConn(nopConn{}, r), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (r *Reject) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	if r.drop {
		c, _ := net.Pipe()
		_ = c.SetDeadline(time.Now().Add(C.DefaultDropTime))
		pc := newDropPacketConnWrapper(c)
		return newPacketConn(pc, r), nil

	}
	return newPacketConn(&nopPacketConn{}, r), nil
}

func NewRejectWithOption(option RejectOption) *Reject {
	return &Reject{
		Base: &Base{
			name: option.Name,
			tp:   C.Direct,
			udp:  true,
		},
	}
}

func NewReject() *Reject {
	return &Reject{
		Base: &Base{
			name:   "REJECT",
			tp:     C.Reject,
			udp:    true,
			prefer: C.DualStack,
		},
	}
}

func NewRejectDrop() *Reject {
	return &Reject{
		Base: &Base{
			name:   "REJECT-DROP",
			tp:     C.RejectDrop,
			udp:    true,
			prefer: C.DualStack,
		},
		drop: true,
	}
}

func NewPass() *Reject {
	return &Reject{
		Base: &Base{
			name:   "PASS",
			tp:     C.Pass,
			udp:    true,
			prefer: C.DualStack,
		},
	}
}

type nopConn struct{}

func (rw nopConn) Read(b []byte) (int, error) { return 0, io.EOF }

func (rw nopConn) ReadBuffer(buffer *buf.Buffer) error { return io.EOF }

func (rw nopConn) Write(b []byte) (int, error)          { return 0, io.EOF }
func (rw nopConn) WriteBuffer(buffer *buf.Buffer) error { return io.EOF }
func (rw nopConn) Close() error                         { return nil }
func (rw nopConn) LocalAddr() net.Addr                  { return nil }
func (rw nopConn) RemoteAddr() net.Addr                 { return nil }
func (rw nopConn) SetDeadline(time.Time) error          { return nil }
func (rw nopConn) SetReadDeadline(time.Time) error      { return nil }
func (rw nopConn) SetWriteDeadline(time.Time) error     { return nil }

var udpAddrIPv4Unspecified = &net.UDPAddr{IP: net.IPv4zero, Port: 0}

type nopPacketConn struct{}

func (npc nopPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) { return len(b), nil }
func (npc nopPacketConn) ReadFrom(b []byte) (int, net.Addr, error)           { return 0, nil, io.EOF }
func (npc nopPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	return nil, nil, nil, io.EOF
}
func (npc nopPacketConn) Close() error                     { return nil }
func (npc nopPacketConn) LocalAddr() net.Addr              { return udpAddrIPv4Unspecified }
func (npc nopPacketConn) SetDeadline(time.Time) error      { return nil }
func (npc nopPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (npc nopPacketConn) SetWriteDeadline(time.Time) error { return nil }

type dropPacketConn struct {
	conn net.Conn
}

func newDropPacketConnWrapper(conn net.Conn) net.PacketConn {
	return &dropPacketConn{conn}
}
func (dpc dropPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return len(b), nil
}
func (dpc dropPacketConn) ReadFrom(b []byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (dpc dropPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	return nil, nil, nil, io.EOF
}
func (dpc dropPacketConn) Close() error {
	dpc.conn = nil
	return nil
}
func (dpc dropPacketConn) LocalAddr() net.Addr              { return udpAddrIPv4Unspecified }
func (dpc dropPacketConn) SetDeadline(time.Time) error      { return nil }
func (dpc dropPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (dpc dropPacketConn) SetWriteDeadline(time.Time) error { return nil }
