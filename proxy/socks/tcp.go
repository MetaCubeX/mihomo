package socks

import (
	"io"
	"net"
	"strconv"

	adapters "github.com/Dreamacro/clash/adapters/inbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel"

	"github.com/Dreamacro/go-shadowsocks2/socks"
)

var (
	tun = tunnel.Instance()
)

// Error represents a SOCKS error
type Error byte

func (err Error) Error() string {
	return "SOCKS error: " + strconv.Itoa(int(err))
}

// SOCKS request commands as defined in RFC 1928 section 4.
const (
	CmdConnect      = 1
	CmdBind         = 2
	CmdUDPAssociate = 3
)

// SOCKS address types as defined in RFC 1928 section 5.
const (
	AtypIPv4       = 1
	AtypDomainName = 3
	AtypIPv6       = 4
)

const MaxAddrLen = 1 + 1 + 255 + 2

// SOCKS errors as defined in RFC 1928 section 6.
const (
	ErrGeneralFailure       = Error(1)
	ErrConnectionNotAllowed = Error(2)
	ErrNetworkUnreachable   = Error(3)
	ErrHostUnreachable      = Error(4)
	ErrConnectionRefused    = Error(5)
	ErrTTLExpired           = Error(6)
	ErrCommandNotSupported  = Error(7)
	ErrAddressNotSupported  = Error(8)
)

type SockListener struct {
	net.Listener
	address string
	closed  bool
}

func NewSocksProxy(addr string) (*SockListener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	sl := &SockListener{l, addr, false}
	go func() {
		log.Infoln("SOCKS proxy listening at: %s", addr)
		for {
			c, err := l.Accept()
			if err != nil {
				if sl.closed {
					break
				}
				continue
			}
			go handleSocks(c)
		}
	}()

	return sl, nil
}

func (l *SockListener) Close() {
	l.closed = true
	l.Listener.Close()
}

func (l *SockListener) Address() string {
	return l.address
}

func handleSocks(conn net.Conn) {
	target, command, err := handshake(conn)
	if err != nil {
		conn.Close()
		return
	}
	conn.(*net.TCPConn).SetKeepAlive(true)
	if command == CmdUDPAssociate {
		tun.Add(adapters.NewSocket(target, conn, C.SOCKS, C.UDP))
		return
	}
	tun.Add(adapters.NewSocket(target, conn, C.SOCKS, C.TCP))
}

// handshake fast-tracks SOCKS initialization to get target address to connect.
func handshake(rw io.ReadWriter) (addr socks.Addr, command int, err error) {
	// Read RFC 1928 for request and reply structure and sizes.
	buf := make([]byte, MaxAddrLen)
	// read VER, NMETHODS, METHODS
	if _, err = io.ReadFull(rw, buf[:2]); err != nil {
		return
	}
	nmethods := buf[1]
	if _, err = io.ReadFull(rw, buf[:nmethods]); err != nil {
		return
	}
	// write VER METHOD
	if _, err = rw.Write([]byte{5, 0}); err != nil {
		return
	}
	// read VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err = io.ReadFull(rw, buf[:3]); err != nil {
		return
	}
	if buf[1] != CmdConnect && buf[1] != CmdUDPAssociate {
		err = ErrCommandNotSupported
		return
	}

	command = int(buf[1])
	addr, err = readAddr(rw, buf)
	if err != nil {
		return
	}
	// write VER REP RSV ATYP BND.ADDR BND.PORT
	_, err = rw.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	return
}

func readAddr(r io.Reader, b []byte) (socks.Addr, error) {
	if len(b) < MaxAddrLen {
		return nil, io.ErrShortBuffer
	}
	_, err := io.ReadFull(r, b[:1]) // read 1st byte for address type
	if err != nil {
		return nil, err
	}

	switch b[0] {
	case AtypDomainName:
		_, err = io.ReadFull(r, b[1:2]) // read 2nd byte for domain length
		if err != nil {
			return nil, err
		}
		_, err = io.ReadFull(r, b[2:2+b[1]+2])
		return b[:1+1+b[1]+2], err
	case AtypIPv4:
		_, err = io.ReadFull(r, b[1:1+net.IPv4len+2])
		return b[:1+net.IPv4len+2], err
	case AtypIPv6:
		_, err = io.ReadFull(r, b[1:1+net.IPv6len+2])
		return b[:1+net.IPv6len+2], err
	}

	return nil, ErrAddressNotSupported
}
