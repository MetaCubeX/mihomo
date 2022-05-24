package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
)

type Socks5 struct {
	*Base
	user           string
	pass           string
	tls            bool
	skipCertVerify bool
	tlsConfig      *tls.Config
}

type Socks5Option struct {
	BasicOption
	Name           string `proxy:"name"`
	Server         string `proxy:"server"`
	Port           int    `proxy:"port"`
	UserName       string `proxy:"username,omitempty"`
	Password       string `proxy:"password,omitempty"`
	TLS            bool   `proxy:"tls,omitempty"`
	UDP            bool   `proxy:"udp,omitempty"`
	SkipCertVerify bool   `proxy:"skip-cert-verify,omitempty"`
}

// StreamConn implements C.ProxyAdapter
func (ss *Socks5) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	var err error
	c, _, err = ss.streamConn(c, metadata)

	return c, err
}

func (ss *Socks5) StreamSocks5PacketConn(c net.Conn, pc net.PacketConn, metadata *C.Metadata) (net.PacketConn, error) {
	if c == nil {
		return pc, fmt.Errorf("%s connect error: parameter net.Conn is nil", ss.addr)
	}

	if pc == nil {
		return pc, fmt.Errorf("%s connect error: parameter net.PacketConn is nil", ss.addr)
	}

	cc, bindAddr, err := ss.streamConn(c, metadata)
	if err != nil {
		return pc, err
	}

	c = cc

	go func() {
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
		// A UDP association terminates when the TCP connection that the UDP
		// ASSOCIATE request arrived on terminates. RFC1928
		_ = pc.Close()
	}()

	// Support unspecified UDP bind address.
	bindUDPAddr := bindAddr.UDPAddr()
	if bindUDPAddr == nil {
		return pc, errors.New("invalid UDP bind address")
	} else if bindUDPAddr.IP.IsUnspecified() {
		serverAddr, err := resolveUDPAddr("udp", ss.Addr())
		if err != nil {
			return pc, err
		}

		bindUDPAddr.IP = serverAddr.IP
	}

	return &socksPacketConn{PacketConn: pc, rAddr: bindUDPAddr, tcpConn: c}, nil
}

func (ss *Socks5) streamConn(c net.Conn, metadata *C.Metadata) (_ net.Conn, bindAddr socks5.Addr, err error) {
	if ss.tls {
		cc := tls.Client(c, ss.tlsConfig)
		err := cc.Handshake()
		c = cc
		if err != nil {
			return c, nil, fmt.Errorf("%s connect error: %w", ss.addr, err)
		}
	}

	var user *socks5.User
	if ss.user != "" {
		user = &socks5.User{
			Username: ss.user,
			Password: ss.pass,
		}
	}

	if metadata.NetWork == C.UDP {
		bindAddr, err = socks5.ClientHandshake(c, serializesSocksAddr(metadata), socks5.CmdUDPAssociate, user)
	} else {
		bindAddr, err = socks5.ClientHandshake(c, serializesSocksAddr(metadata), socks5.CmdConnect, user)
	}

	return c, bindAddr, err
}

// DialContext implements C.ProxyAdapter
func (ss *Socks5) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	c, err := dialer.DialContext(ctx, "tcp", ss.addr, ss.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", ss.addr, err)
	}
	tcpKeepAlive(c)

	defer safeConnClose(c, err)

	c, err = ss.StreamConn(c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, ss), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (ss *Socks5) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	c, err := dialer.DialContext(ctx, "tcp", ss.addr, ss.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", ss.addr, err)
	}

	defer safeConnClose(c, err)

	pc, err := dialer.ListenPacket(ctx, "udp", "", ss.Base.DialOptions(opts...)...)
	if err != nil {
		return
	}

	tcpKeepAlive(c)

	pc, err = ss.StreamSocks5PacketConn(c, pc, metadata)
	if err != nil {
		return
	}

	return NewPacketConn(pc, ss), nil
}

func NewSocks5(option Socks5Option) *Socks5 {
	var tlsConfig *tls.Config
	if option.TLS {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: option.SkipCertVerify,
			ServerName:         option.Server,
		}
	}

	return &Socks5{
		Base: &Base{
			name:  option.Name,
			addr:  net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:    C.Socks5,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		user:           option.UserName,
		pass:           option.Password,
		tls:            option.TLS,
		skipCertVerify: option.SkipCertVerify,
		tlsConfig:      tlsConfig,
	}
}

type socksPacketConn struct {
	net.PacketConn
	rAddr   net.Addr
	tcpConn net.Conn
}

func (uc *socksPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return
	}
	return uc.PacketConn.WriteTo(packet, uc.rAddr)
}

func (uc *socksPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, e := uc.PacketConn.ReadFrom(b)
	if e != nil {
		return 0, nil, e
	}
	addr, payload, err := socks5.DecodeUDPPacket(b)
	if err != nil {
		return 0, nil, err
	}

	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return 0, nil, errors.New("parse udp addr error")
	}

	// due to DecodeUDPPacket is mutable, record addr length
	copy(b, payload)
	return n - len(addr) - 3, udpAddr, nil
}

func (uc *socksPacketConn) Close() error {
	_ = uc.tcpConn.Close()
	return uc.PacketConn.Close()
}
