package outbound

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/congestion"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/Dreamacro/clash/component/dialer"
	tlsC "github.com/Dreamacro/clash/component/tls"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	hyCongestion "github.com/Dreamacro/clash/transport/hysteria/congestion"
	"github.com/Dreamacro/clash/transport/hysteria/core"
	"github.com/Dreamacro/clash/transport/hysteria/obfs"
	"github.com/Dreamacro/clash/transport/hysteria/pmtud_fix"
	"github.com/Dreamacro/clash/transport/hysteria/transport"
)

const (
	mbpsToBps = 125000

	DefaultStreamReceiveWindow     = 15728640 // 15 MB/s
	DefaultConnectionReceiveWindow = 67108864 // 64 MB/s

	DefaultALPN        = "hysteria"
	DefaultProtocol    = "udp"
	DefaultHopInterval = 10
)

var rateStringRegexp = regexp.MustCompile(`^(\d+)\s*([KMGT]?)([Bb])ps$`)

type Hysteria struct {
	*Base

	client *core.Client
}

func (h *Hysteria) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	hdc := hyDialerWithContext{
		ctx: context.Background(),
		hyDialer: func(network string) (net.PacketConn, error) {
			return dialer.ListenPacket(ctx, network, "", h.Base.DialOptions(opts...)...)
		},
		remoteAddr: func(addr string) (net.Addr, error) {
			return resolveUDPAddrWithPrefer(ctx, "udp", addr, h.prefer)
		},
	}

	tcpConn, err := h.client.DialTCP(metadata.RemoteAddress(), &hdc)
	if err != nil {
		return nil, err
	}

	return NewConn(tcpConn, h), nil
}

func (h *Hysteria) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	hdc := hyDialerWithContext{
		ctx: context.Background(),
		hyDialer: func(network string) (net.PacketConn, error) {
			return dialer.ListenPacket(ctx, network, "", h.Base.DialOptions(opts...)...)
		},
		remoteAddr: func(addr string) (net.Addr, error) {
			return resolveUDPAddrWithPrefer(ctx, "udp", addr, h.prefer)
		},
	}
	udpConn, err := h.client.DialUDP(&hdc)
	if err != nil {
		return nil, err
	}
	return newPacketConn(&hyPacketConn{udpConn}, h), nil
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
	up = stringToBps(c.Up)
	if up == 0 {
		return 0, 0, fmt.Errorf("invaild upload speed: %s", c.Up)
	}

	down = stringToBps(c.Down)
	if down == 0 {
		return 0, 0, fmt.Errorf("invaild download speed: %s", c.Down)
	}

	return up, down, nil
}

func NewHysteria(option HysteriaOption) (*Hysteria, error) {
	clientTransport := &transport.ClientTransport{
		Dialer: &net.Dialer{
			Timeout: 8 * time.Second,
		},
	}
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

	var bs []byte
	var err error
	if len(option.CustomCA) > 0 {
		bs, err = os.ReadFile(option.CustomCA)
		if err != nil {
			return nil, fmt.Errorf("hysteria %s load ca error: %w", addr, err)
		}
	} else if option.CustomCAString != "" {
		bs = []byte(option.CustomCAString)
	}

	if len(bs) > 0 {
		block, _ := pem.Decode(bs)
		if block == nil {
			return nil, fmt.Errorf("CA cert is not PEM")
		}

		fpBytes := sha256.Sum256(block.Bytes)
		if len(option.Fingerprint) == 0 {
			option.Fingerprint = hex.EncodeToString(fpBytes[:])
		}
	}

	if len(option.Fingerprint) != 0 {
		var err error
		tlsConfig, err = tlsC.GetSpecifiedFingerprintTLSConfig(tlsConfig, option.Fingerprint)
		if err != nil {
			return nil, err
		}
	} else {
		tlsConfig = tlsC.GetGlobalFingerprintTLCConfig(tlsConfig)
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
	return &Hysteria{
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
		client: client,
	}, nil
}

func stringToBps(s string) uint64 {
	if s == "" {
		return 0
	}

	// when have not unit, use Mbps
	if v, err := strconv.Atoi(s); err == nil {
		return stringToBps(fmt.Sprintf("%d Mbps", v))
	}

	m := rateStringRegexp.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	var n uint64
	switch m[2] {
	case "K":
		n = 1 << 10
	case "M":
		n = 1 << 20
	case "G":
		n = 1 << 30
	case "T":
		n = 1 << 40
	default:
		n = 1
	}
	v, _ := strconv.ParseUint(m[1], 10, 64)
	n = v * n
	if m[3] == "b" {
		// Bits, need to convert to bytes
		n = n >> 3
	}
	return n
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

func (c *hyPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = c.UDPConn.WriteTo(p, M.SocksaddrFromNet(addr).String())
	if err != nil {
		return
	}
	n = len(p)
	return
}

type hyDialerWithContext struct {
	hyDialer   func(network string) (net.PacketConn, error)
	ctx        context.Context
	remoteAddr func(host string) (net.Addr, error)
}

func (h *hyDialerWithContext) ListenPacket(rAddr net.Addr) (net.PacketConn, error) {
	network := "udp"
	if addrPort, err := netip.ParseAddrPort(rAddr.String()); err == nil {
		network = dialer.ParseNetwork(network, addrPort.Addr())
	}
	return h.hyDialer(network)
}

func (h *hyDialerWithContext) Context() context.Context {
	return h.ctx
}

func (h *hyDialerWithContext) RemoteAddr(host string) (net.Addr, error) {
	return h.remoteAddr(host)
}
