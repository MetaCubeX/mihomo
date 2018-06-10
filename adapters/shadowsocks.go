package adapters

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"

	C "github.com/Dreamacro/clash/constant"

	"github.com/riobard/go-shadowsocks2/core"
	"github.com/riobard/go-shadowsocks2/socks"
)

// ShadowsocksAdapter is a shadowsocks adapter
type ShadowsocksAdapter struct {
	conn net.Conn
}

// Writer is used to output network traffic
func (ss *ShadowsocksAdapter) Writer() io.Writer {
	return ss.conn
}

// Reader is used to input network traffic
func (ss *ShadowsocksAdapter) Reader() io.Reader {
	return ss.conn
}

// Close is used to close connection
func (ss *ShadowsocksAdapter) Close() {
	ss.conn.Close()
}

type ShadowSocks struct {
	server   string
	cipher   string
	password string
}

func (ss *ShadowSocks) Generator(addr *C.Addr) (adapter C.ProxyAdapter, err error) {
	var key []byte
	ciph, _ := core.PickCipher(ss.cipher, key, ss.password)
	c, err := net.Dial("tcp", ss.server)
	if err != nil {
		return nil, fmt.Errorf("%s connect error", ss.server)
	}
	c.(*net.TCPConn).SetKeepAlive(true)
	c = ciph.StreamConn(c)
	_, err = c.Write(serializesSocksAddr(addr))
	return &ShadowsocksAdapter{conn: c}, err
}

func NewShadowSocks(ssURL string) *ShadowSocks {
	server, cipher, password, _ := parseURL(ssURL)
	return &ShadowSocks{
		server:   server,
		cipher:   cipher,
		password: password,
	}
}

func parseURL(s string) (addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}

func serializesSocksAddr(addr *C.Addr) []byte {
	var buf [][]byte
	aType := uint8(addr.AddrType)
	p, _ := strconv.Atoi(addr.Port)
	port := []byte{uint8(p >> 8), uint8(p & 0xff)}
	switch addr.AddrType {
	case socks.AtypDomainName:
		len := uint8(len(addr.Host))
		host := []byte(addr.Host)
		buf = [][]byte{[]byte{aType, len}, host, port}
	case socks.AtypIPv4:
		host := net.ParseIP(addr.Host).To4()
		buf = [][]byte{[]byte{aType}, host, port}
	case socks.AtypIPv6:
		host := net.ParseIP(addr.Host).To16()
		buf = [][]byte{[]byte{aType}, host, port}
	}
	return bytes.Join(buf, []byte(""))
}
