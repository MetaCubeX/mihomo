package outbound

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/congestion"
	M "github.com/sagernet/sing/common/metadata"

	CN "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	hyCongestion "github.com/metacubex/mihomo/transport/hysteria/congestion"
	"github.com/metacubex/mihomo/transport/hysteria/core"
	"github.com/metacubex/mihomo/transport/hysteria/obfs"
	"github.com/metacubex/mihomo/transport/hysteria/pmtud_fix"
	"github.com/metacubex/mihomo/transport/hysteria/transport"
	"github.com/metacubex/mihomo/transport/hysteria/utils"
)

const (
	mbpsToBps = 125000

	DefaultStreamReceiveWindow     = 15728640 // 15 MB/s
	DefaultConnectionReceiveWindow = 67108864 // 64 MB/s

	DefaultALPN        = "hysteria"
	DefaultProtocol    = "udp"
	DefaultHopInterval = 10
)

type Hysteria struct {
	*Base

	option *HysteriaOption
	client *core.Client

	closeCh chan struct{} // for test
}

func (h *Hysteria) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	tcpConn, err := h.client.DialTCP(metadata.String(), metadata.DstPort, h.genHdc(ctx, opts...))
	if err != nil {
		return nil, err
	}

	return NewConn(CN.NewRefConn(tcpConn, h), h), nil
}

func (h *Hysteria) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	udpConn, err := h.client.DialUDP(h.genHdc(ctx, opts...))
	if err != nil {
		return nil, err
	}
	return newPacketConn(CN.NewRefPacketConn(&hyPacketConn{udpConn}, h), h), nil
}

func (h *Hysteria) genHdc(ctx context.Context, opts ...dialer.Option) utils.PacketDialer {
	return &hyDialerWithContext{
		ctx: context.Background(),
		hyDialer: func(network string, rAddr net.Addr) (net.PacketConn, error) {
			var err error
			var cDialer C.Dialer = dialer.NewDialer(h.Base.DialOptions(opts...)...)
			if len(h.option.DialerProxy) > 0 {
				cDialer, err = proxydialer.NewByName(h.option.DialerProxy, cDialer)
				if err != nil {
					return nil, err
				}
			}
			rAddrPort, _ := netip.ParseAddrPort(rAddr.String())
			return cDialer.ListenPacket(ctx, network, "", rAddrPort)
		},
		remoteAddr: func(addr string) (net.Addr, error) {
			return resolveUDPAddrWithPrefer(ctx, "udp", addr, h.prefer)
		},
	}
}

type HysteriaOption struct {
	BasicOption
	Name                string   `proxy:"name"`
	Server              string   `proxy:"server"`
	Port                int      `proxy:"port,omitempty"`
	Ports               string   `proxy:"ports,omitempty"`
	Protocol            string   `proxy:"protocol,omitempty"`
	ObfsProtocol        string   `proxy:"obfs-protocol,omitempty"` // compatible with Stash
	Up                  string   `proxy:"up"`
	UpSpeed             int      `proxy:"up-speed,omitempty"` // compatible with Stash
	Down                string   `proxy:"down"`
	DownSpeed           int      `proxy:"down-speed,omitempty"` // compatible with Stash
	Auth                string   `proxy:"auth,omitempty"`
	AuthString          string   `proxy:"auth-str,omitempty"`
	Obfs                string   `proxy:"obfs,omitempty"`
	SNI                 string   `proxy:"sni,omitempty"`
	SkipCertVerify      bool     `proxy:"skip-cert-verify,omitempty"`
	Fingerprint         string   `proxy:"fingerprint,omitempty"`
	ALPN                []string `proxy:"alpn,omitempty"`
	CustomCA            string   `proxy:"ca,omitempty"`
	CustomCAString      string   `proxy:"ca-str,omitempty"`
	ReceiveWindowConn   int      `proxy:"recv-window-conn,omitempty"`
	ReceiveWindow       int      `proxy:"recv-window,omitempty"`
	DisableMTUDiscovery bool     `proxy:"disable-mtu-discovery,omitempty"`
	FastOpen            bool     `proxy:"fast-open,omitempty"`
	HopInterval         int      `proxy:"hop-interval,omitempty"`
}

func (c *HysteriaOption) Speed() (uint64, uint64, error) {
	var up, down uint64
	up = StringToBps(c.Up)
	if up == 0 {
		return 0, 0, fmt.Errorf("invaild upload speed: %s", c.Up)
	}

	down = StringToBps(c.Down)
	if down == 0 {
		return 0, 0, fmt.Errorf("invaild download speed: %s", c.Down)
	}

	return up, down, nil
}

func NewHysteria(option HysteriaOption) (*Hysteria, error) {
	clientTransport := &transport.ClientTransport{}
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	ports := option.Ports

	serverName := option.Server
	if option.SNI != "" {
		serverName = option.SNI
	}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: option.SkipCertVerify,
		MinVersion:         tls.VersionTLS13,
	}

	var err error
	tlsConfig, err = ca.GetTLSConfig(tlsConfig, option.Fingerprint, option.CustomCA, option.CustomCAString)
	if err != nil {
		return nil, err
	}

	if len(option.ALPN) > 0 {
		tlsConfig.NextProtos = option.ALPN
	} else {
		tlsConfig.NextProtos = []string{DefaultALPN}
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     uint64(option.ReceiveWindowConn),
		MaxStreamReceiveWindow:         uint64(option.ReceiveWindowConn),
		InitialConnectionReceiveWindow: uint64(option.ReceiveWindow),
		MaxConnectionReceiveWindow:     uint64(option.ReceiveWindow),
		KeepAlivePeriod:                10 * time.Second,
		DisablePathMTUDiscovery:        option.DisableMTUDiscovery,
		EnableDatagrams:                true,
	}
	if option.ObfsProtocol != "" {
		option.Protocol = option.ObfsProtocol
	}
	if option.Protocol == "" {
		option.Protocol = DefaultProtocol
	}
	if option.HopInterval == 0 {
		option.HopInterval = DefaultHopInterval
	}
	hopInterval := time.Duration(int64(option.HopInterval)) * time.Second
	if option.ReceiveWindow == 0 {
		quicConfig.InitialStreamReceiveWindow = DefaultStreamReceiveWindow / 10
		quicConfig.MaxStreamReceiveWindow = DefaultStreamReceiveWindow
	}
	if option.ReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = DefaultConnectionReceiveWindow / 10
		quicConfig.MaxConnectionReceiveWindow = DefaultConnectionReceiveWindow
	}
	if !quicConfig.DisablePathMTUDiscovery && pmtud_fix.DisablePathMTUDiscovery {
		log.Infoln("hysteria: Path MTU Discovery is not yet supported on this platform")
	}

	var auth = []byte(option.AuthString)
	if option.Auth != "" {
		auth, err = base64.StdEncoding.DecodeString(option.Auth)
		if err != nil {
			return nil, err
		}
	}
	var obfuscator obfs.Obfuscator
	if len(option.Obfs) > 0 {
		obfuscator = obfs.NewXPlusObfuscator([]byte(option.Obfs))
	}

	up, down, err := option.Speed()
	if err != nil {
		return nil, err
	}
	if option.UpSpeed != 0 {
		up = uint64(option.UpSpeed * mbpsToBps)
	}
	if option.DownSpeed != 0 {
		down = uint64(option.DownSpeed * mbpsToBps)
	}
	client, err := core.NewClient(
		addr, ports, option.Protocol, auth, tlsConfig, quicConfig, clientTransport, up, down, func(refBPS uint64) congestion.CongestionControl {
			return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
		}, obfuscator, hopInterval, option.FastOpen,
	)
	if err != nil {
		return nil, fmt.Errorf("hysteria %s create error: %w", addr, err)
	}
	outbound := &Hysteria{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Hysteria,
			udp:    true,
			tfo:    option.FastOpen,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		option: &option,
		client: client,
	}
	runtime.SetFinalizer(outbound, closeHysteria)

	return outbound, nil
}

func closeHysteria(h *Hysteria) {
	if h.client != nil {
		_ = h.client.Close()
	}
	if h.closeCh != nil {
		close(h.closeCh)
	}
}

type hyPacketConn struct {
	core.UDPConn
}

func (c *hyPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	b, addrStr, err := c.UDPConn.ReadFrom()
	if err != nil {
		return
	}
	n = copy(p, b)
	addr = M.ParseSocksaddr(addrStr).UDPAddr()
	return
}

func (c *hyPacketConn) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	b, addrStr, err := c.UDPConn.ReadFrom()
	if err != nil {
		return
	}
	data = b
	addr = M.ParseSocksaddr(addrStr).UDPAddr()
	return
}

func (c *hyPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = c.UDPConn.WriteTo(p, M.SocksaddrFromNet(addr).String())
	if err != nil {
		return
	}
	n = len(p)
	return
}

type hyDialerWithContext struct {
	hyDialer   func(network string, rAddr net.Addr) (net.PacketConn, error)
	ctx        context.Context
	remoteAddr func(host string) (net.Addr, error)
}

func (h *hyDialerWithContext) ListenPacket(rAddr net.Addr) (net.PacketConn, error) {
	network := "udp"
	if addrPort, err := netip.ParseAddrPort(rAddr.String()); err == nil {
		network = dialer.ParseNetwork(network, addrPort.Addr())
	}
	return h.hyDialer(network, rAddr)
}

func (h *hyDialerWithContext) Context() context.Context {
	return h.ctx
}

func (h *hyDialerWithContext) RemoteAddr(host string) (net.Addr, error) {
	return h.remoteAddr(host)
}
