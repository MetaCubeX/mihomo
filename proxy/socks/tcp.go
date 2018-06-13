package socks

import (
	"fmt"
	"io"
	"net"
	"strconv"

	C "github.com/Dreamacro/clash/constant"
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
		conn.Close()
		return
	}
	conn.(*net.TCPConn).SetKeepAlive(true)
	tun.Add(NewSocks(target, conn))
}

type SocksAdapter struct {
	conn net.Conn
	addr *C.Addr
}

func (s *SocksAdapter) Close() {
	s.conn.Close()
}

func (s *SocksAdapter) Addr() *C.Addr {
	return s.addr
}

func (s *SocksAdapter) Connect(proxy C.ProxyAdapter) {
	go io.Copy(s.conn, proxy.ReadWriter())
	io.Copy(proxy.ReadWriter(), s.conn)
}

func parseSocksAddr(target socks.Addr) *C.Addr {
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

	return &C.Addr{
		NetWork:  C.TCP,
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
