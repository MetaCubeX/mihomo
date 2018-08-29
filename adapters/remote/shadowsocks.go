package adapters

import (
	"bytes"
	"fmt"
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

// Close is used to close connection
func (ss *ShadowsocksAdapter) Close() {
	ss.conn.Close()
}

func (ss *ShadowsocksAdapter) Conn() net.Conn {
	return ss.conn
}

type ShadowSocks struct {
	server string
	name   string
	cipher core.Cipher
}

func (ss *ShadowSocks) Name() string {
	return ss.name
}

func (ss *ShadowSocks) Type() C.AdapterType {
	return C.Shadowsocks
}

func (ss *ShadowSocks) Generator(addr *C.Addr) (adapter C.ProxyAdapter, err error) {
	c, err := net.Dial("tcp", ss.server)
	if err != nil {
		return nil, fmt.Errorf("%s connect error", ss.server)
	}
	tcpKeepAlive(c)
	c = ss.cipher.StreamConn(c)
	_, err = c.Write(serializesSocksAddr(addr))
	return &ShadowsocksAdapter{conn: c}, err
}

func NewShadowSocks(name string, ssURL string) (*ShadowSocks, error) {
	var key []byte
	server, cipher, password, _ := parseURL(ssURL)
	ciph, err := core.PickCipher(cipher, key, password)
	if err != nil {
		return nil, fmt.Errorf("ss %s initialize error: %s", server, err.Error())
	}
	return &ShadowSocks{
		server: server,
		name:   name,
		cipher: ciph,
	}, nil
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
		buf = [][]byte{{aType, len}, host, port}
	case socks.AtypIPv4:
		host := addr.IP.To4()
		buf = [][]byte{{aType}, host, port}
	case socks.AtypIPv6:
		host := addr.IP.To16()
		buf = [][]byte{{aType}, host, port}
	}
	return bytes.Join(buf, []byte(""))
}
