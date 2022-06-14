package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/congestion"
	M "github.com/sagernet/sing/common/metadata"
	hyCongestion "github.com/tobyxdd/hysteria/pkg/congestion"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"github.com/tobyxdd/hysteria/pkg/pmtud_fix"
	"github.com/tobyxdd/hysteria/pkg/transport"
)

const (
	mbpsToBps   = 125000
	minSpeedBPS = 16384

	DefaultStreamReceiveWindow     = 15728640 // 15 MB/s
	DefaultConnectionReceiveWindow = 67108864 // 64 MB/s
	DefaultMaxIncomingStreams      = 1024

	DefaultALPN     = "hysteria"
	DefaultProtocol = "udp"
)

var rateStringRegexp = regexp.MustCompile(`^(\d+)\s*([KMGT]?)([Bb])ps$`)

type Hysteria struct {
	*Base

	client          *core.Client
	clientTransport *transport.ClientTransport
}

func (h *Hysteria) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	tcpConn, err := h.client.DialTCP(metadata.RemoteAddress(), hyDialer(func() (net.PacketConn, error) {
		return dialer.ListenPacket(ctx, "udp", "", h.Base.DialOptions(opts...)...)
	}))
	if err != nil {
		return nil, err
	}
	return NewConn(tcpConn, h), nil
}

func (h *Hysteria) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	udpConn, err := h.client.DialUDP(hyDialer(func() (net.PacketConn, error) {
		return dialer.ListenPacket(ctx, "udp", "", h.Base.DialOptions(opts...)...)
	}))
	if err != nil {
		return nil, err
	}
	return newPacketConn(&hyPacketConn{udpConn}, h), nil
}

type HysteriaOption struct {
	BasicOption
	Name                string `proxy:"name"`
	Server              string `proxy:"server"`
	Port                int    `proxy:"port"`
	Protocol            string `proxy:"protocol,omitempty"`
	Up                  string `proxy:"up"`
	Down                string `proxy:"down"`
	AuthString          string `proxy:"auth_str,omitempty"`
	Obfs                string `proxy:"obfs,omitempty"`
	SNI                 string `proxy:"sni,omitempty"`
	SkipCertVerify      bool   `proxy:"skip-cert-verify,omitempty"`
	ALPN                string `proxy:"alpn,omitempty"`
	CustomCA            string `proxy:"ca,omitempty"`
	CustomCAString      string `proxy:"ca_str,omitempty"`
	ReceiveWindowConn   int    `proxy:"recv_window_conn,omitempty"`
	ReceiveWindow       int    `proxy:"recv_window,omitempty"`
	DisableMTUDiscovery bool   `proxy:"disable_mtu_discovery,omitempty"`
}

func (c *HysteriaOption) Speed() (uint64, uint64, error) {
	var up, down uint64
	up = stringToBps(c.Up)
	if up == 0 {
		return 0, 0, fmt.Errorf("invaild upload speed: %s", c.Up)
	}

	down = stringToBps(c.Down)
	if up == 0 {
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
	serverName := option.Server
	if option.SNI != "" {
		serverName = option.SNI
	}
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: option.SkipCertVerify,
		MinVersion:         tls.VersionTLS13,
	}
	if len(option.ALPN) > 0 {
		tlsConfig.NextProtos = []string{option.ALPN}
	} else {
		tlsConfig.NextProtos = []string{DefaultALPN}
	}
	if len(option.CustomCA) > 0 {
		bs, err := ioutil.ReadFile(option.CustomCA)
		if err != nil {
			return nil, fmt.Errorf("hysteria %s load ca error: %w", addr, err)
		}
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(bs) {
			return nil, fmt.Errorf("hysteria %s failed to parse ca_str", addr)
		}
		tlsConfig.RootCAs = cp
	} else if option.CustomCAString != "" {
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM([]byte(option.CustomCAString)) {
			return nil, fmt.Errorf("hysteria %s failed to parse ca_str", addr)
		}
		tlsConfig.RootCAs = cp
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     uint64(option.ReceiveWindowConn),
		MaxStreamReceiveWindow:         uint64(option.ReceiveWindowConn),
		InitialConnectionReceiveWindow: uint64(option.ReceiveWindow),
		MaxConnectionReceiveWindow:     uint64(option.ReceiveWindow),
		KeepAlive:                      true,
		DisablePathMTUDiscovery:        option.DisableMTUDiscovery,
		EnableDatagrams:                true,
	}
	if option.Protocol == "" {
		option.Protocol = DefaultProtocol
	}
	if option.ReceiveWindowConn == 0 {
		quicConfig.InitialStreamReceiveWindow = DefaultStreamReceiveWindow
		quicConfig.MaxStreamReceiveWindow = DefaultStreamReceiveWindow
	}
	if option.ReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = DefaultConnectionReceiveWindow
		quicConfig.MaxConnectionReceiveWindow = DefaultConnectionReceiveWindow
	}
	if !quicConfig.DisablePathMTUDiscovery && pmtud_fix.DisablePathMTUDiscovery {
		log.Infoln("hysteria: Path MTU Discovery is not yet supported on this platform")
	}

	var auth = []byte(option.AuthString)
	var obfuscator obfs.Obfuscator
	if len(option.Obfs) > 0 {
		obfuscator = obfs.NewXPlusObfuscator([]byte(option.Obfs))
	}

	up, down, err := option.Speed()
	if err != nil {
		return nil, err
	}

	client, err := core.NewClient(
		addr, option.Protocol, auth, tlsConfig, quicConfig, clientTransport, up, down, func(refBPS uint64) congestion.CongestionControl {
			return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
		}, obfuscator,
	)
	if err != nil {
		return nil, fmt.Errorf("hysteria %s create error: %w", addr, err)
	}
	return &Hysteria{
		Base: &Base{
			name:  option.Name,
			addr:  addr,
			tp:    C.Hysteria,
			udp:   true,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		client:          client,
		clientTransport: clientTransport,
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

type hyDialer func() (net.PacketConn, error)

func (h hyDialer) ListenPacket() (net.PacketConn, error) {
	return h()
}
