package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/echtunnel"
)

type ECHTunnel struct {
	*Base
	option *ECHTunnelOption
	client *echtunnel.Client
}

type ECHTunnelOption struct {
	BasicOption
	Name      string `proxy:"name"`
	Server    string `proxy:"server"`
	Port      int    `proxy:"port"`
	WSPath    string `proxy:"ws-path,omitempty"`
	Token     string `proxy:"token,omitempty"`
	ECHDomain string `proxy:"ech-domain,omitempty"`
	DNS       string `proxy:"dns,omitempty"`
	IP        string `proxy:"ip,omitempty"`
	UDP       bool   `proxy:"udp,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (e *ECHTunnel) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	// 使用 ECH-Tunnel 客户端建立连接
	c, err := e.client.DialContext(ctx, metadata.RemoteAddress())
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", e.addr, err)
	}

	return NewConn(c, e), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (e *ECHTunnel) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if !e.option.UDP {
		return nil, fmt.Errorf("UDP not supported")
	}

	// ECH-Tunnel 的 UDP 实现
	c, err := e.client.DialContext(ctx, metadata.RemoteAddress())
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", e.addr, err)
	}

	pc := echtunnel.NewPacketConn(c)
	return newPacketConn(pc, e), nil
}

// SupportUOT implements C.ProxyAdapter
func (e *ECHTunnel) SupportUOT() bool {
	return false
}

// ProxyInfo implements C.ProxyAdapter
func (e *ECHTunnel) ProxyInfo() C.ProxyInfo {
	info := e.Base.ProxyInfo()
	info.DialerProxy = e.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (e *ECHTunnel) Close() error {
	if e.client != nil {
		return e.client.Close()
	}
	return nil
}

func NewECHTunnel(option ECHTunnelOption) (*ECHTunnel, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	client, err := echtunnel.NewClient(echtunnel.Config{
		Server:    option.Server,
		Port:      option.Port,
		WSPath:    option.WSPath,
		Token:     option.Token,
		ECHDomain: option.ECHDomain,
		DNS:       option.DNS,
		IP:        option.IP,
	})

	if err != nil {
		return nil, err
	}

	e := &ECHTunnel{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.ECHTunnel,
			pdName: option.ProviderName,
			udp:    option.UDP,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: option.IPVersion,
		},
		option: &option,
		client: client,
	}
	e.dialer = option.NewDialer(e.DialOptions())

	return e, nil
}
