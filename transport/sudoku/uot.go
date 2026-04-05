package sudoku

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

const (
	maxUoTPayload = 64 * 1024
)

// WriteDatagram sends a single UDP datagram frame over a reliable stream.
func WriteDatagram(w io.Writer, addr string, payload []byte) error {
	addrBuf, err := EncodeAddress(addr)
	if err != nil {
		return fmt.Errorf("encode address: %w", err)
	}

	if addrLen := len(addrBuf); addrLen == 0 || addrLen > maxUoTPayload {
		return fmt.Errorf("address too long: %d", len(addrBuf))
	}
	if payloadLen := len(payload); payloadLen > maxUoTPayload {
		return fmt.Errorf("payload too large: %d", payloadLen)
	}

	var header [4]byte
	binary.BigEndian.PutUint16(header[:2], uint16(len(addrBuf)))
	binary.BigEndian.PutUint16(header[2:], uint16(len(payload)))

	return writeAllChunks(w, header[:], addrBuf, payload)
}

// ReadDatagram parses a single UDP datagram frame from the reliable stream.
func ReadDatagram(r io.Reader) (string, []byte, error) {
	addr, payloadLen, err := readDatagramHeaderAndAddress(r)
	if err != nil {
		return "", nil, err
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", nil, err
	}

	return addr, payload, nil
}

// UoTPacketConn adapts a net.Conn with the Sudoku UoT framing to net.PacketConn.
type UoTPacketConn struct {
	conn    net.Conn
	writeMu sync.Mutex
}

func NewUoTPacketConn(conn net.Conn) *UoTPacketConn {
	return &UoTPacketConn{conn: conn}
}

func (c *UoTPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		addrStr, payloadLen, err := readDatagramHeaderAndAddress(c.conn)
		if err != nil {
			return 0, nil, err
		}

		udpAddr, err := parseDatagramUDPAddr(addrStr)
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
			log.Debugln("[Sudoku][UoT] discard datagram with invalid address %s: %v", addrStr, err)
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
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := WriteDatagram(c.conn, addr.String(), p); err != nil {
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

func readDatagramHeaderAndAddress(r io.Reader) (string, int, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return "", 0, err
	}

	addrLen := int(binary.BigEndian.Uint16(header[:2]))
	payloadLen := int(binary.BigEndian.Uint16(header[2:]))
	if addrLen <= 0 || addrLen > maxUoTPayload {
		return "", 0, fmt.Errorf("invalid address length: %d", addrLen)
	}
	if payloadLen < 0 || payloadLen > maxUoTPayload {
		return "", 0, fmt.Errorf("invalid payload length: %d", payloadLen)
	}

	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addrBuf); err != nil {
		return "", 0, err
	}

	addr, err := DecodeAddress(bytes.NewReader(addrBuf))
	if err != nil {
		return "", 0, fmt.Errorf("decode address: %w", err)
	}
	return addr, payloadLen, nil
}

func parseDatagramUDPAddr(addr string) (*net.UDPAddr, error) {
	addrPort, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())), nil
}

func discardBytes(r io.Reader, n int) error {
	if n <= 0 {
		return nil
	}
	_, err := io.CopyN(io.Discard, r, int64(n))
	return err
}
