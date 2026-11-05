package sudoku

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
)

// uotHeaderSize is u16 address length | u16 payload length.
const uotHeaderSize = 4

// WriteDatagram sends a single UDP datagram frame over a reliable stream.
func WriteDatagram(w io.Writer, addr string, payload []byte) error {
	return writeDatagram(w, payload, func(b []byte) ([]byte, error) { return AppendAddress(b, addr) })
}

// writeDatagram sends the whole frame with one write, so it is sealed as one record.
func writeDatagram(w io.Writer, payload []byte, appendAddr func([]byte) ([]byte, error)) error {
	if len(payload) > math.MaxUint16 {
		return fmt.Errorf("payload too large: %d", len(payload))
	}
	buf := pool.Get(uotHeaderSize + socks5.MaxAddrLen + len(payload))
	defer pool.Put(buf)

	frame, err := appendAddr(buf[:uotHeaderSize])
	if err != nil {
		return fmt.Errorf("encode address: %w", err)
	}
	binary.BigEndian.PutUint16(frame, uint16(len(frame)-uotHeaderSize))
	binary.BigEndian.PutUint16(frame[2:], uint16(len(payload)))
	_, err = w.Write(append(frame, payload...))
	return err
}

// UoTReader reads datagram frames from a UoT stream. The header and address are read into
// scratch space owned by the reader, so a frame costs no allocation besides its payload.
type UoTReader struct {
	r   io.Reader
	buf [uotHeaderSize + socks5.MaxAddrLen]byte
}

func NewUoTReader(r io.Reader) *UoTReader {
	return &UoTReader{r: r}
}

// readHeader reads the next frame's header and address and leaves its payload (payloadLen bytes)
// unread. addr is only valid until the next call.
func (u *UoTReader) readHeader() (addr socks5.Addr, payloadLen int, err error) {
	if _, err = io.ReadFull(u.r, u.buf[:uotHeaderSize]); err != nil {
		return nil, 0, err
	}
	addrLen := int(binary.BigEndian.Uint16(u.buf[:2]))
	payloadLen = int(binary.BigEndian.Uint16(u.buf[2:]))
	if addrLen == 0 {
		return nil, 0, fmt.Errorf("invalid address length: %d", addrLen)
	}

	// An encoded address is at most socks5.MaxAddrLen bytes; anything after it is padding.
	n := addrLen
	if n > socks5.MaxAddrLen {
		n = socks5.MaxAddrLen
	}
	if _, err = io.ReadFull(u.r, u.buf[uotHeaderSize:uotHeaderSize+n]); err != nil {
		return nil, 0, err
	}
	if err = discardBytes(u.r, addrLen-n); err != nil {
		return nil, 0, err
	}
	if addr = socks5.SplitAddr(u.buf[uotHeaderSize : uotHeaderSize+n]); addr == nil {
		return nil, 0, errors.New("decode address: invalid address")
	}
	return addr, payloadLen, nil
}

// ReadDatagram reads the next frame. addr is only valid until the next call; payload comes from
// common/pool and must be released with pool.Put.
func (u *UoTReader) ReadDatagram() (socks5.Addr, []byte, error) {
	addr, payloadLen, err := u.readHeader()
	if err != nil {
		return nil, nil, err
	}
	payload := pool.Get(payloadLen)
	if _, err := io.ReadFull(u.r, payload); err != nil {
		_ = pool.Put(payload)
		return nil, nil, err
	}
	return addr, payload, nil
}

// UoTPacketConn adapts a net.Conn with the Sudoku UoT framing to net.PacketConn.
type UoTPacketConn struct {
	conn    net.Conn
	reader  *UoTReader
	writeMu sync.Mutex
}

func NewUoTPacketConn(conn net.Conn) *UoTPacketConn {
	return &UoTPacketConn{conn: conn, reader: NewUoTReader(conn)}
}

func (c *UoTPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		addr, payloadLen, err := c.reader.readHeader()
		if err != nil {
			return 0, nil, err
		}

		udpAddr, err := uotUDPAddr(addr)
		if payloadLen > len(p) {
			if discardErr := discardBytes(c.conn, payloadLen); discardErr != nil {
				return 0, nil, discardErr
			}
			return 0, nil, io.ErrShortBuffer
		}
		if err != nil {
			if discardErr := discardBytes(c.conn, payloadLen); discardErr != nil {
				return 0, nil, discardErr
			}
			log.Debugln("[Sudoku][UoT] discard datagram with invalid address %s: %v", addr, err)
			continue
		}
		if _, err := io.ReadFull(c.conn, p[:payloadLen]); err != nil {
			return 0, nil, err
		}
		return payloadLen, udpAddr, nil
	}
}

func (c *UoTPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, errors.New("address is nil")
	}
	appendAddr := func(b []byte) ([]byte, error) { return AppendAddress(b, addr.String()) }
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if ap := udpAddr.AddrPort(); ap.Addr().IsValid() {
			appendAddr = func(b []byte) ([]byte, error) { return AppendAddrPort(b, ap), nil }
		}
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := writeDatagram(c.conn, p, appendAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *UoTPacketConn) Close() error {
	return c.conn.Close()
}

func (c *UoTPacketConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *UoTPacketConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *UoTPacketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *UoTPacketConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// uotUDPAddr converts a datagram's peer to a *net.UDPAddr. Domain names are not resolved: only
// the IP literals they may spell are accepted.
func uotUDPAddr(addr socks5.Addr) (*net.UDPAddr, error) {
	var ap netip.AddrPort
	switch addr[0] {
	case socks5.AtypIPv4:
		ap = netip.AddrPortFrom(netip.AddrFrom4([4]byte(addr[1:5])), binary.BigEndian.Uint16(addr[5:]))
	case socks5.AtypIPv6:
		ap = netip.AddrPortFrom(netip.AddrFrom16([16]byte(addr[1:17])), binary.BigEndian.Uint16(addr[17:]))
	default:
		var err error
		if ap, err = netip.ParseAddrPort(addr.String()); err != nil {
			return nil, err
		}
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())), nil
}

func discardBytes(r io.Reader, n int) error {
	if n <= 0 {
		return nil
	}
	_, err := io.CopyN(io.Discard, r, int64(n))
	return err
}
