package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowstream"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/ssr/obfs"
	"github.com/metacubex/mihomo/transport/ssr/protocol"
)

type ShadowSocksR struct {
	*Base
	option   *ShadowSocksROption
	cipher   core.Cipher
	obfs     obfs.Obfs
	protocol protocol.Protocol
}

type ShadowSocksROption struct {
	BasicOption
	Name          string `proxy:"name"`
	Server        string `proxy:"server"`
	Port          int    `proxy:"port"`
	Password      string `proxy:"password"`
	Cipher        string `proxy:"cipher"`
	Obfs          string `proxy:"obfs"`
	ObfsParam     string `proxy:"obfs-param,omitempty"`
	Protocol      string `proxy:"protocol"`
	ProtocolParam string `proxy:"protocol-param,omitempty"`
	UDP           bool   `proxy:"udp,omitempty"`
}

// StreamConnContext implements C.ProxyAdapter
func (ssr *ShadowSocksR) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	c = ssr.obfs.StreamConn(c)
	c = ssr.cipher.StreamConn(c)
	var (
		iv  []byte
		err error
	)
	switch conn := c.(type) {
	case *shadowstream.Conn:
		iv, err = conn.ObtainWriteIV()
		if err != nil {
			return nil, err
		}
	case *shadowaead.Conn:
		return nil, fmt.Errorf("invalid connection type")
	}
	c = ssr.protocol.StreamConn(c, iv)
	_, err = c.Write(serializesSocksAddr(metadata))
	return c, err
}

// DialContext implements C.ProxyAdapter
func (ssr *ShadowSocksR) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	return ssr.DialContextWithDialer(ctx, dialer.NewDialer(ssr.Base.DialOptions(opts...)...), metadata)
}

// DialContextWithDialer implements C.ProxyAdapter
func (ssr *ShadowSocksR) DialContextWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.Conn, err error) {
	if len(ssr.option.DialerProxy) > 0 {
		dialer, err = proxydialer.NewByName(ssr.option.DialerProxy, dialer)
		if err != nil {
			return nil, err
		}
	}
	c, err := dialer.DialContext(ctx, "tcp", ssr.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", ssr.addr, err)
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = ssr.StreamConnContext(ctx, c, metadata)
	return NewConn(c, ssr), err
}

// ListenPacketContext implements C.ProxyAdapter
func (ssr *ShadowSocksR) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	return ssr.ListenPacketWithDialer(ctx, dialer.NewDialer(ssr.Base.DialOptions(opts...)...), metadata)
}

// ListenPacketWithDialer implements C.ProxyAdapter
func (ssr *ShadowSocksR) ListenPacketWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if len(ssr.option.DialerProxy) > 0 {
		dialer, err = proxydialer.NewByName(ssr.option.DialerProxy, dialer)
		if err != nil {
			return nil, err
		}
	}
	addr, err := resolveUDPAddrWithPrefer(ctx, "udp", ssr.addr, ssr.prefer)
	if err != nil {
		return nil, err
	}

	pc, err := dialer.ListenPacket(ctx, "udp", "", addr.AddrPort())
	if err != nil {
		return nil, err
	}

	epc := ssr.cipher.PacketConn(N.NewEnhancePacketConn(pc))
	epc = ssr.protocol.PacketConn(epc)
	return newPacketConn(&ssrPacketConn{EnhancePacketConn: epc, rAddr: addr}, ssr), nil
}

// SupportWithDialer implements C.ProxyAdapter
func (ssr *ShadowSocksR) SupportWithDialer() C.NetWork {
	return C.ALLNet
}

func NewShadowSocksR(option ShadowSocksROption) (*ShadowSocksR, error) {
	// SSR protocol compatibility
	// https://github.com/metacubex/mihomo/pull/2056
	if option.Cipher == "none" {
		option.Cipher = "dummy"
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	cipher := option.Cipher
	password := option.Password
	coreCiph, err := core.PickCipher(cipher, nil, password)
	if err != nil {
		return nil, fmt.Errorf("ssr %s initialize error: %w", addr, err)
	}
	var (
		ivSize int
		key    []byte
	)

	if option.Cipher == "dummy" {
		ivSize = 0
		key = core.Kdf(option.Password, 16)
	} else {
		ciph, ok := coreCiph.(*core.StreamCipher)
		if !ok {
			return nil, fmt.Errorf("%s is not none or a supported stream cipher in ssr", cipher)
		}
		ivSize = ciph.IVSize()
		key = ciph.Key
	}

	obfs, obfsOverhead, err := obfs.PickObfs(option.Obfs, &obfs.Base{
		Host:   option.Server,
		Port:   option.Port,
		Key:    key,
		IVSize: ivSize,
		Param:  option.ObfsParam,
	})
	if err != nil {
		return nil, fmt.Errorf("ssr %s initialize obfs error: %w", addr, err)
	}

	protocol, err := protocol.PickProtocol(option.Protocol, &protocol.Base{
		Key:      key,
		Overhead: obfsOverhead,
		Param:    option.ProtocolParam,
	})
	if err != nil {
		return nil, fmt.Errorf("ssr %s initialize protocol error: %w", addr, err)
	}

	return &ShadowSocksR{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.ShadowsocksR,
			udp:    option.UDP,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		option:   &option,
		cipher:   coreCiph,
		obfs:     obfs,
		protocol: protocol,
	}, nil
}

type ssrPacketConn struct {
	N.EnhancePacketConn
	rAddr net.Addr
}

func (spc *ssrPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return
	}
	return spc.EnhancePacketConn.WriteTo(packet[3:], spc.rAddr)
}

func (spc *ssrPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, e := spc.EnhancePacketConn.ReadFrom(b)
	if e != nil {
		return 0, nil, e
	}

	addr := socks5.SplitAddr(b[:n])
	if addr == nil {
		return 0, nil, errors.New("parse addr error")
	}

	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return 0, nil, errors.New("parse addr error")
	}

	copy(b, b[len(addr):])
	return n - len(addr), udpAddr, e
}

func (spc *ssrPacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	data, put, _, err = spc.EnhancePacketConn.WaitReadFrom()
	if err != nil {
		return nil, nil, nil, err
	}

	_addr := socks5.SplitAddr(data)
	if _addr == nil {
		if put != nil {
			put()
		}
		return nil, nil, nil, errors.New("parse addr error")
	}

	addr = _addr.UDPAddr()
	if addr == nil {
		if put != nil {
			put()
		}
		return nil, nil, nil, errors.New("parse addr error")
	}

	data = data[len(_addr):]
	return
}
