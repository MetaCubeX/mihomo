package trojan

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"sync"

	"github.com/Dreamacro/clash/component/socks5"
)

var (
	defaultALPN = []string{"h2", "http/1.1"}
	crlf        = []byte{'\r', '\n'}

	bufPool = sync.Pool{New: func() interface{} { return &bytes.Buffer{} }}
)

type Command = byte

var (
	CommandTCP byte = 1
	CommandUDP byte = 3
)

type Option struct {
	Password           string
	ALPN               []string
	ServerName         string
	SkipCertVerify     bool
	ClientSessionCache tls.ClientSessionCache
}

type Trojan struct {
	option      *Option
	hexPassword []byte
}

func (t *Trojan) StreamConn(conn net.Conn) (net.Conn, error) {
	alpn := defaultALPN
	if len(t.option.ALPN) != 0 {
		alpn = t.option.ALPN
	}

	tlsConfig := &tls.Config{
		NextProtos:         alpn,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: t.option.SkipCertVerify,
		ServerName:         t.option.ServerName,
		ClientSessionCache: t.option.ClientSessionCache,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	return tlsConn, nil
}

func (t *Trojan) WriteHeader(conn net.Conn, command Command, socks5Addr []byte) error {
	buf := bufPool.Get().(*bytes.Buffer)
	defer buf.Reset()
	defer bufPool.Put(buf)

	buf.Write(t.hexPassword)
	buf.Write(crlf)

	buf.WriteByte(command)
	buf.Write(socks5Addr)
	buf.Write(crlf)

	_, err := conn.Write(buf.Bytes())
	return err
}

func (t *Trojan) PacketConn(conn net.Conn) net.PacketConn {
	return &PacketConn{conn}
}

func WritePacket(conn net.Conn, socks5Addr, payload []byte) (int, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer buf.Reset()
	defer bufPool.Put(buf)

	buf.Write(socks5Addr)
	binary.Write(buf, binary.BigEndian, uint16(len(payload)))
	buf.Write(crlf)
	buf.Write(payload)

	return conn.Write(buf.Bytes())
}

func DecodePacket(payload []byte) (net.Addr, []byte, error) {
	addr := socks5.SplitAddr(payload)
	if addr == nil {
		return nil, nil, errors.New("split addr error")
	}

	buf := payload[len(addr):]
	if len(buf) <= 4 {
		return nil, nil, errors.New("packet invalid")
	}

	length := binary.BigEndian.Uint16(buf[:2])
	if len(buf) < 4+int(length) {
		return nil, nil, errors.New("packet invalid")
	}

	return addr.UDPAddr(), buf[4 : 4+length], nil
}

func New(option *Option) *Trojan {
	return &Trojan{option, hexSha224([]byte(option.Password))}
}

type PacketConn struct {
	net.Conn
}

func (pc *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return WritePacket(pc, socks5.ParseAddr(addr.String()), b)
}

func (pc *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := pc.Conn.Read(b)
	addr, payload, err := DecodePacket(b)
	if err != nil {
		return n, nil, err
	}

	copy(b, payload)
	return len(payload), addr, nil
}

func hexSha224(data []byte) []byte {
	buf := make([]byte, 56)
	hash := sha256.New224()
	hash.Write(data)
	hex.Encode(buf, hash.Sum(nil))
	return buf
}
