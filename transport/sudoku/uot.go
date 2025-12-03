package sudoku

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

const (
	UoTMagicByte  byte = 0xEE
	uotVersion         = 0x01
	maxUoTPayload      = 64 * 1024
)

// WritePreface writes the UDP-over-TCP marker and version.
func WritePreface(w io.Writer) error {
	_, err := w.Write([]byte{UoTMagicByte, uotVersion})
	return err
}

func encodeAddress(rawAddr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(rawAddr)
	if err != nil {
		return nil, err
	}

	portInt, err := net.LookupPort("udp", portStr)
	if err != nil {
		return nil, err
	}

	var buf []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, 0x01) // IPv4
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, 0x04) // IPv6
			buf = append(buf, ip...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("domain too long")
		}
		buf = append(buf, 0x03) // domain
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	}

	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(portInt))
	buf = append(buf, portBytes[:]...)
	return buf, nil
}

func decodeAddress(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", err
	}

	switch atyp[0] {
	case 0x01: // IPv4
		var ipBuf [net.IPv4len]byte
		if _, err := io.ReadFull(r, ipBuf[:]); err != nil {
			return "", err
		}
		var portBuf [2]byte
		if _, err := io.ReadFull(r, portBuf[:]); err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(ipBuf[:]).String(), fmt.Sprint(binary.BigEndian.Uint16(portBuf[:]))), nil
	case 0x04: // IPv6
		var ipBuf [net.IPv6len]byte
		if _, err := io.ReadFull(r, ipBuf[:]); err != nil {
			return "", err
		}
		var portBuf [2]byte
		if _, err := io.ReadFull(r, portBuf[:]); err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(ipBuf[:]).String(), fmt.Sprint(binary.BigEndian.Uint16(portBuf[:]))), nil
	case 0x03: // domain
		var lengthBuf [1]byte
		if _, err := io.ReadFull(r, lengthBuf[:]); err != nil {
			return "", err
		}
		l := int(lengthBuf[0])
		hostBuf := make([]byte, l)
		if _, err := io.ReadFull(r, hostBuf); err != nil {
			return "", err
		}
		var portBuf [2]byte
		if _, err := io.ReadFull(r, portBuf[:]); err != nil {
			return "", err
		}
		return net.JoinHostPort(string(hostBuf), fmt.Sprint(binary.BigEndian.Uint16(portBuf[:]))), nil
	default:
		return "", fmt.Errorf("unknown address type: %d", atyp[0])
	}
}

// WriteDatagram sends a single UDP datagram frame over a reliable stream.
func WriteDatagram(w io.Writer, addr string, payload []byte) error {
	addrBuf, err := encodeAddress(addr)
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

	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if _, err := w.Write(addrBuf); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

// ReadDatagram parses a single UDP datagram frame from the reliable stream.
func ReadDatagram(r io.Reader) (string, []byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return "", nil, err
	}

	addrLen := int(binary.BigEndian.Uint16(header[:2]))
	payloadLen := int(binary.BigEndian.Uint16(header[2:]))

	if addrLen <= 0 || addrLen > maxUoTPayload {
		return "", nil, fmt.Errorf("invalid address length: %d", addrLen)
	}
	if payloadLen < 0 || payloadLen > maxUoTPayload {
		return "", nil, fmt.Errorf("invalid payload length: %d", payloadLen)
	}

	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addrBuf); err != nil {
		return "", nil, err
	}

	addr, err := decodeAddress(bytes.NewReader(addrBuf))
	if err != nil {
		return "", nil, fmt.Errorf("decode address: %w", err)
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
		addrStr, payload, err := ReadDatagram(c.conn)
		if err != nil {
			return 0, nil, err
		}

		if len(payload) > len(p) {
			return 0, nil, io.ErrShortBuffer
		}

		udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
		if err != nil {
			log.Debugln("[Sudoku][UoT] discard datagram with invalid address %s: %v", addrStr, err)
			continue
		}

		copy(p, payload)
		return len(payload), udpAddr, nil
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
