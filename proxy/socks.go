package proxy

import (
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/tunnel"

	"github.com/riobard/go-shadowsocks2/socks"
	log "github.com/sirupsen/logrus"
)

var (
	tun = tunnel.GetInstance()
)

func NewSocksProxy(port string) {
	l, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	defer l.Close()
	if err != nil {
		return
	}
	log.Infof("SOCKS proxy :%s", port)
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go handleSocks(c)
	}
}

func handleSocks(conn net.Conn) {
	target, err := socks.Handshake(conn)
	if err != nil {

	}
	conn.(*net.TCPConn).SetKeepAlive(true)
	tun.Add(NewSocks(target, conn))
}

type SocksAdapter struct {
	conn net.Conn
	addr *constant.Addr
}

func (s *SocksAdapter) Writer() io.Writer {
	return s.conn
}

func (s *SocksAdapter) Reader() io.Reader {
	return s.conn
}

func (s *SocksAdapter) Close() {
	s.conn.Close()
}

func (s *SocksAdapter) Addr() *constant.Addr {
	return s.addr
}

func parseSocksAddr(target socks.Addr) *constant.Addr {
	var host, port string
	var ip net.IP

	switch target[0] {
	case socks.AtypDomainName:
		host = string(target[2 : 2+target[1]])
		port = strconv.Itoa((int(target[2+target[1]]) << 8) | int(target[2+target[1]+1]))
		ipAddr, err := net.ResolveIPAddr("ip", host)
		if err == nil {
			ip = ipAddr.IP
		}
	case socks.AtypIPv4:
		ip = net.IP(target[1 : 1+net.IPv4len])
		port = strconv.Itoa((int(target[1+net.IPv4len]) << 8) | int(target[1+net.IPv4len+1]))
	case socks.AtypIPv6:
		ip = net.IP(target[1 : 1+net.IPv6len])
		port = strconv.Itoa((int(target[1+net.IPv6len]) << 8) | int(target[1+net.IPv6len+1]))
	}

	return &constant.Addr{
		AddrType: int(target[0]),
		Host:     host,
		IP:       &ip,
		Port:     port,
	}
}

func NewSocks(target socks.Addr, conn net.Conn) *SocksAdapter {
	return &SocksAdapter{
		conn: conn,
		addr: parseSocksAddr(target),
	}
}
