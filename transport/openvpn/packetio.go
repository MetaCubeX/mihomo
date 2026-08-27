package openvpn

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/metacubex/mihomo/common/pool"
)

// connIO deliberately excludes net.Conn's deadline methods. Physical OpenVPN
// I/O can only be interrupted by closing the connection.
type connIO interface {
	io.ReadWriteCloser
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type PacketIO interface {
	// ReadPacket and WritePacket must not depend on deadline methods. Close
	// must unblock any ReadPacket or WritePacket currently in progress.
	// ReadPacket may return a complete packet and a non-nil error together;
	// the packet precedes the error and must remain valid.
	ReadPacket() ([]byte, error)
	WritePacket(packet []byte) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

var errPacketDropped = errors.New("openvpn packet dropped")

type packetDroppedError struct {
	cause error
}

func (e *packetDroppedError) Error() string {
	return fmt.Sprintf("%v: %v", errPacketDropped, e.cause)
}

func (e *packetDroppedError) Unwrap() error {
	return e.cause
}

func (e *packetDroppedError) Is(target error) bool {
	return target == errPacketDropped
}

type streamPacketIO struct {
	conn connIO
}

type datagramPacketIO struct {
	conn           connIO
	recoverableUDP bool
}

func NewDatagramPacketIO(conn connIO) PacketIO {
	_, recoverableUDP := conn.(syscall.Conn)
	return &datagramPacketIO{conn: conn, recoverableUDP: recoverableUDP}
}

func (d *datagramPacketIO) ReadPacket() ([]byte, error) {
	buf := make([]byte, 64*1024)
	n, err := d.conn.Read(buf)
	return buf[:n], err
}

func (d *datagramPacketIO) WritePacket(packet []byte) error {
	n, err := d.conn.Write(packet)
	if err == nil {
		return nil
	}
	if n != 0 || !d.recoverableUDP || terminalPacketIOError(err) {
		return err
	}
	return &packetDroppedError{cause: err}
}

func (d *datagramPacketIO) Close() error {
	return d.conn.Close()
}

func (d *datagramPacketIO) LocalAddr() net.Addr {
	return d.conn.LocalAddr()
}

func (d *datagramPacketIO) RemoteAddr() net.Addr {
	return d.conn.RemoteAddr()
}

func NewTCPPacketIO(conn connIO) PacketIO {
	return &streamPacketIO{conn: conn}
}

func (s *streamPacketIO) ReadPacket() ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(s.conn, length[:]); err != nil {
		return nil, err
	}
	size := int(length[0])<<8 | int(length[1])
	if size == 0 {
		return nil, errors.New("empty openvpn TCP packet")
	}
	packet := make([]byte, size)
	if _, err := io.ReadFull(s.conn, packet); err != nil {
		return nil, err
	}
	return packet, nil
}

func (s *streamPacketIO) WritePacket(packet []byte) error {
	if len(packet) > 0xffff {
		return fmt.Errorf("openvpn TCP packet too large: %d", len(packet))
	}
	frame := pool.Get(2 + len(packet))
	defer pool.Put(frame)
	frame[0] = byte(len(packet) >> 8)
	frame[1] = byte(len(packet))
	copy(frame[2:], packet)
	_, err := s.conn.Write(frame)
	return err
}

func (s *streamPacketIO) Close() error {
	return s.conn.Close()
}

func (s *streamPacketIO) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *streamPacketIO) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

func terminalPacketIOError(err error) bool {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) ||
		errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
