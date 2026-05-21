package snell

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
	"github.com/metacubex/mihomo/transport/socks5"
)

const (
	Version1            = 1
	Version2            = 2
	Version3            = 3
	Version4            = 4
	Version5            = 5
	DefaultSnellVersion = Version1

	// max packet length
	maxLength = 0x3FFF
)

const (
	CommandPing       byte = 0
	CommandConnect    byte = 1
	CommandConnectV2  byte = 5
	CommandUDP        byte = 6
	CommondUDPForward byte = 1

	CommandTunnel byte = 0
	CommandPong   byte = 1
	CommandError  byte = 2

	Version byte = 1
)

var endSignal = []byte{}

type packetFrameWriter interface {
	WritePacketFrame([]byte) (int, error)
}

type Snell struct {
	net.Conn
	buffer [1]byte
	reply  bool
}

func (s *Snell) Read(b []byte) (int, error) {
	if err := s.ReadReply(); err != nil {
		return 0, err
	}
	return s.Conn.Read(b)
}

func (s *Snell) ReadReply() error {
	if s.reply {
		return nil
	}

	if _, err := io.ReadFull(s.Conn, s.buffer[:]); err != nil {
		return err
	}
	s.reply = true

	if s.buffer[0] == CommandTunnel {
		return nil
	} else if s.buffer[0] != CommandError {
		return errors.New("command not support")
	}

	// CommandError
	// 1 byte error code
	if _, err := io.ReadFull(s.Conn, s.buffer[:]); err != nil {
		return err
	}
	errcode := int(s.buffer[0])

	// 1 byte error message length
	if _, err := io.ReadFull(s.Conn, s.buffer[:]); err != nil {
		return err
	}
	length := int(s.buffer[0])
	msg := make([]byte, length)

	if _, err := io.ReadFull(s.Conn, msg); err != nil {
		return err
	}

	return fmt.Errorf("server reported code: %d, message: %s", errcode, string(msg))
}

func WriteHeader(conn net.Conn, host string, port uint, version int) error {
	return WriteHeaderWithReuse(conn, host, port, version, false)
}

func WriteHeaderWithReuse(conn net.Conn, host string, port uint, version int, reuse bool) error {
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	buf.WriteByte(Version)
	if version == Version2 || reuse {
		buf.WriteByte(CommandConnectV2)
	} else {
		buf.WriteByte(CommandConnect)
	}

	// clientID length & id
	buf.WriteByte(0)

	// host & port
	buf.WriteByte(uint8(len(host)))
	buf.WriteString(host)
	binary.Write(buf, binary.BigEndian, uint16(port))

	if _, err := conn.Write(buf.Bytes()); err != nil {
		return err
	}

	return nil
}

func WriteUDPHeader(conn net.Conn, version int) error {
	if version < Version3 {
		return errors.New("unsupport UDP version")
	}

	// version, command, clientID length
	_, err := conn.Write([]byte{Version, CommandUDP, 0x00})
	return err
}

func writeZeroChunk(conn net.Conn) error {
	if _, err := conn.Write(endSignal); err != nil {
		return err
	}
	return nil
}

// HalfClose only works after the request negotiated the reuse command.
func HalfClose(conn net.Conn) error {
	if err := writeZeroChunk(conn); err != nil {
		return err
	}
	if s, ok := conn.(*Snell); ok {
		s.reply = false
	}
	return nil
}

func StreamConn(conn net.Conn, psk []byte, version int) *Snell {
	if version >= Version4 {
		return &Snell{Conn: newV4Conn(conn, psk)}
	}

	var cipher shadowaead.Cipher
	if version != Version1 {
		cipher = NewAES128GCM(psk)
	} else {
		cipher = NewChacha20Poly1305(psk)
	}
	return &Snell{Conn: shadowaead.NewConn(conn, cipher)}
}

func ServerStreamConn(conn net.Conn, psk []byte, version int) *Snell {
	stream := StreamConn(conn, psk, version)
	stream.reply = true
	return stream
}

func PacketConn(conn net.Conn) net.PacketConn {
	return &packetConn{
		Conn: conn,
	}
}

func (s *Snell) WritePacketFrame(b []byte) (int, error) {
	if fw, ok := s.Conn.(packetFrameWriter); ok {
		return fw.WritePacketFrame(b)
	}
	return s.Conn.Write(b)
}

func writePacket(w io.Writer, socks5Addr, payload []byte) (int, error) {
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	// compose snell UDP address format (refer: icpz/snell-server-reversed)
	// a brand new wheel to replace socks5 address format, well done Yachen
	buf.WriteByte(CommondUDPForward)
	switch socks5Addr[0] {
	case socks5.AtypDomainName:
		hostLen := socks5Addr[1]
		if len(socks5Addr) < 1+1+int(hostLen)+2 {
			return 0, errors.New("snell UDP address invalid")
		}
		buf.Write(socks5Addr[1 : 1+1+hostLen+2])
	case socks5.AtypIPv4:
		if len(socks5Addr) < 1+net.IPv4len+2 {
			return 0, errors.New("snell UDP address invalid")
		}
		buf.Write([]byte{0x00, 0x04})
		buf.Write(socks5Addr[1 : 1+net.IPv4len+2])
	case socks5.AtypIPv6:
		if len(socks5Addr) < 1+net.IPv6len+2 {
			return 0, errors.New("snell UDP address invalid")
		}
		buf.Write([]byte{0x00, 0x06})
		buf.Write(socks5Addr[1 : 1+net.IPv6len+2])
	default:
		return 0, errors.New("snell UDP address invalid")
	}

	buf.Write(payload)
	if fw, ok := w.(packetFrameWriter); ok {
		_, err := fw.WritePacketFrame(buf.Bytes())
		if err != nil {
			return 0, err
		}
		return len(payload), nil
	}

	_, err := w.Write(buf.Bytes())
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

func WritePacket(w io.Writer, socks5Addr, payload []byte) (int, error) {
	maxPayloadLength := maxLength - UdpRequestHeaderLength(socks5Addr)
	if maxPayloadLength <= 0 {
		return 0, errors.New("snell UDP address too large")
	}
	if len(payload) <= maxPayloadLength {
		return writePacket(w, socks5Addr, payload)
	}
	return 0, errors.New("snell UDP payload too large")
}

func WritePacketResponse(w io.Writer, addr net.Addr, payload []byte) (int, error) {
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	socks5Addr := socks5.ParseAddrToSocksAddr(addr)
	if len(socks5Addr) == 0 {
		return 0, errors.New("snell UDP response address invalid")
	}
	switch socks5Addr[0] {
	case socks5.AtypIPv4:
		if len(socks5Addr) < 1+net.IPv4len+2 {
			return 0, errors.New("snell UDP response address invalid")
		}
		buf.WriteByte(0x04)
		buf.Write(socks5Addr[1 : 1+net.IPv4len+2])
	case socks5.AtypIPv6:
		if len(socks5Addr) < 1+net.IPv6len+2 {
			return 0, errors.New("snell UDP response address invalid")
		}
		buf.WriteByte(0x06)
		buf.Write(socks5Addr[1 : 1+net.IPv6len+2])
	default:
		return 0, errors.New("snell UDP response address invalid")
	}
	buf.Write(payload)

	var err error
	if fw, ok := w.(packetFrameWriter); ok {
		_, err = fw.WritePacketFrame(buf.Bytes())
	} else {
		_, err = w.Write(buf.Bytes())
	}
	if err != nil {
		return 0, err
	}
	return len(payload), nil
}

type UDPRequest struct {
	Host    string
	Ip      netip.Addr
	Port    uint16
	Payload []byte
}

func ParseUDPRequest(packet []byte) (UDPRequest, error) {
	if len(packet) < 2 || packet[0] != CommondUDPForward {
		return UDPRequest{}, errors.New("snell invalid UDP request")
	}
	if hostLen := int(packet[1]); hostLen != 0 {
		if len(packet) <= 2+hostLen+2 {
			return UDPRequest{}, errors.New("snell invalid UDP domain request")
		}
		offset := 2 + hostLen
		return UDPRequest{
			Host:    string(packet[2:offset]),
			Port:    binary.BigEndian.Uint16(packet[offset : offset+2]),
			Payload: packet[offset+2:],
		}, nil
	}
	if len(packet) < 3 {
		return UDPRequest{}, errors.New("snell invalid UDP IP request")
	}
	switch packet[2] {
	case 0x04:
		if len(packet) < 3+net.IPv4len+2 {
			return UDPRequest{}, errors.New("snell invalid UDP IPv4 request")
		}
		offset := 3 + net.IPv4len
		ip, _ := netip.AddrFromSlice(packet[3:offset])
		return UDPRequest{
			Ip:      ip.Unmap(),
			Port:    binary.BigEndian.Uint16(packet[offset : offset+2]),
			Payload: packet[offset+2:],
		}, nil
	case 0x06:
		if len(packet) < 3+net.IPv6len+2 {
			return UDPRequest{}, errors.New("snell invalid UDP IPv6 request")
		}
		offset := 3 + net.IPv6len
		ip, _ := netip.AddrFromSlice(packet[3:offset])
		return UDPRequest{
			Ip:      ip.Unmap(),
			Port:    binary.BigEndian.Uint16(packet[offset : offset+2]),
			Payload: packet[offset+2:],
		}, nil
	default:
		return UDPRequest{}, errors.New("snell invalid UDP address type")
	}
}

func UdpRequestHeaderLength(socks5Addr []byte) int {
	if len(socks5Addr) == 0 {
		return maxLength + 1
	}
	switch socks5Addr[0] {
	case socks5.AtypDomainName:
		if len(socks5Addr) < 2 {
			return maxLength + 1
		}
		return 1 + 1 + int(socks5Addr[1]) + 2
	case socks5.AtypIPv4:
		return 1 + 2 + net.IPv4len + 2
	case socks5.AtypIPv6:
		return 1 + 2 + net.IPv6len + 2
	default:
		return maxLength + 1
	}
}

func ReadPacket(r io.Reader, payload []byte) (net.Addr, int, error) {
	buf := pool.Get(pool.UDPBufferSize)
	defer pool.Put(buf)

	n, err := r.Read(buf)
	headLen := 1
	if err != nil {
		return nil, 0, err
	}
	if n < headLen {
		return nil, 0, errors.New("insufficient UDP length")
	}

	// parse snell UDP response address format
	switch buf[0] {
	case 0x04:
		headLen += net.IPv4len + 2
		if n < headLen {
			err = errors.New("insufficient UDP length")
			break
		}
		buf[0] = socks5.AtypIPv4
	case 0x06:
		headLen += net.IPv6len + 2
		if n < headLen {
			err = errors.New("insufficient UDP length")
			break
		}
		buf[0] = socks5.AtypIPv6
	default:
		err = errors.New("ip version invalid")
	}

	if err != nil {
		return nil, 0, err
	}

	addr := socks5.SplitAddr(buf[0:])
	if addr == nil {
		return nil, 0, errors.New("remote address invalid")
	}
	uAddr := addr.UDPAddr()
	if uAddr == nil {
		return nil, 0, errors.New("parse addr error")
	}

	length := len(payload)
	if n-headLen < length {
		length = n - headLen
	}
	copy(payload[:], buf[headLen:headLen+length])

	return uAddr, length, nil
}

type packetConn struct {
	net.Conn
	rMux sync.Mutex
	wMux sync.Mutex
}

func (pc *packetConn) WritePacketFrame(b []byte) (int, error) {
	if s, ok := pc.Conn.(*Snell); ok {
		if fw, ok := s.Conn.(packetFrameWriter); ok {
			return fw.WritePacketFrame(b)
		}
	}
	return pc.Conn.Write(b)
}

func (pc *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	pc.wMux.Lock()
	defer pc.wMux.Unlock()

	return WritePacket(pc, socks5.ParseAddrToSocksAddr(addr), b)
}

func (pc *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	pc.rMux.Lock()
	defer pc.rMux.Unlock()

	addr, n, err := ReadPacket(pc.Conn, b)
	if err != nil {
		return 0, nil, err
	}

	return n, addr, nil
}
