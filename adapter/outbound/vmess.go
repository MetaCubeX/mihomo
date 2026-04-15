package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/gun"
	mihomoVMess "github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	vmess "github.com/metacubex/sing-vmess"
	"github.com/metacubex/sing-vmess/packetaddr"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

var ErrUDPRemoteAddrMismatch = errors.New("udp packet dropped due to mismatched remote address")

type Vmess struct {
	*Base
	client *vmess.Client
	option *VmessOption

	// for gun mux
	gunClient *gun.Client

	realityConfig *tlsC.RealityConfig
	echConfig     *ech.Config
}

type VmessOption struct {
	BasicOption
	Name                string         `proxy:"name"`
	Server              string         `proxy:"server"`
	Port                int            `proxy:"port"`
	UUID                string         `proxy:"uuid"`
	AlterID             int            `proxy:"alterId"`
	Cipher              string         `proxy:"cipher"`
	UDP                 bool           `proxy:"udp,omitempty"`
	Network             string         `proxy:"network,omitempty"`
	TLS                 bool           `proxy:"tls,omitempty"`
	ALPN                []string       `proxy:"alpn,omitempty"`
	SkipCertVerify      bool           `proxy:"skip-cert-verify,omitempty"`
	Fingerprint         string         `proxy:"fingerprint,omitempty"`
	Certificate         string         `proxy:"certificate,omitempty"`
	PrivateKey          string         `proxy:"private-key,omitempty"`
	ServerName          string         `proxy:"servername,omitempty"`
	ECHOpts             ECHOptions     `proxy:"ech-opts,omitempty"`
	RealityOpts         RealityOptions `proxy:"reality-opts,omitempty"`
	HTTPOpts            HTTPOptions    `proxy:"http-opts,omitempty"`
	HTTP2Opts           HTTP2Options   `proxy:"h2-opts,omitempty"`
	GrpcOpts            GrpcOptions    `proxy:"grpc-opts,omitempty"`
	WSOpts              WSOptions      `proxy:"ws-opts,omitempty"`
	PacketAddr          bool           `proxy:"packet-addr,omitempty"`
	XUDP                bool           `proxy:"xudp,omitempty"`
	PacketEncoding      string         `proxy:"packet-encoding,omitempty"`
	GlobalPadding       bool           `proxy:"global-padding,omitempty"`
	AuthenticatedLength bool           `proxy:"authenticated-length,omitempty"`
	ClientFingerprint   string         `proxy:"client-fingerprint,omitempty"`
}

type HTTPOptions struct {
	Method  string              `proxy:"method,omitempty"`
	Path    []string            `proxy:"path,omitempty"`
	Headers map[string][]string `proxy:"headers,omitempty"`
}

type HTTP2Options struct {
	Host []string `proxy:"host,omitempty"`
	Path string   `proxy:"path,omitempty"`
}

type GrpcOptions struct {
	GrpcServiceName string `proxy:"grpc-service-name,omitempty"`
	GrpcUserAgent   string `proxy:"grpc-user-agent,omitempty"`
	PingInterval    int    `proxy:"ping-interval,omitempty"`
	MaxConnections  int    `proxy:"max-connections,omitempty"`
	MinStreams      int    `proxy:"min-streams,omitempty"`
	MaxStreams      int    `proxy:"max-streams,omitempty"`
}

type WSOptions struct {
	Path                     string            `proxy:"path,omitempty"`
	Headers                  map[string]string `proxy:"headers,omitempty"`
	MaxEarlyData             int               `proxy:"max-early-data,omitempty"`
	EarlyDataHeaderName      string            `proxy:"early-data-header-name,omitempty"`
	V2rayHttpUpgrade         bool              `proxy:"v2ray-http-upgrade,omitempty"`
	V2rayHttpUpgradeFastOpen bool              `proxy:"v2ray-http-upgrade-fast-open,omitempty"`
}

func (v *Vmess) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ net.Conn, err error) {
	switch v.option.Network {
	case "ws":
		host, port, _ := net.SplitHostPort(v.addr)
		wsOpts := &mihomoVMess.WebsocketConfig{
			Host:                     host,
			Port:                     port,
			Path:                     v.option.WSOpts.Path,
			MaxEarlyData:             v.option.WSOpts.MaxEarlyData,
			EarlyDataHeaderName:      v.option.WSOpts.EarlyDataHeaderName,
			V2rayHttpUpgrade:         v.option.WSOpts.V2rayHttpUpgrade,
			V2rayHttpUpgradeFastOpen: v.option.WSOpts.V2rayHttpUpgradeFastOpen,
			ClientFingerprint:        v.option.ClientFingerprint,
			ECHConfig:                v.echConfig,
			Headers:                  http.Header{},
		}

		if len(v.option.WSOpts.Headers) != 0 {
			for key, value := range v.option.WSOpts.Headers {
				wsOpts.Headers.Add(key, value)
			}
		}

		if v.option.TLS {
			wsOpts.TLS = true
			wsOpts.TLSConfig, err = ca.GetTLSConfig(ca.Option{
				TLSConfig: &tls.Config{
					ServerName:         host,
					InsecureSkipVerify: v.option.SkipCertVerify,
					NextProtos:         []string{"http/1.1"},
				},
				Fingerprint: v.option.Fingerprint,
				Certificate: v.option.Certificate,
				PrivateKey:  v.option.PrivateKey,
			})
			if err != nil {
				return nil, err
			}

			if v.option.ServerName != "" {
				wsOpts.TLSConfig.ServerName = v.option.ServerName
			} else if host := wsOpts.Headers.Get("Host"); host != "" {
				wsOpts.TLSConfig.ServerName = host
			}
		}
		c, err = mihomoVMess.StreamWebsocketConn(ctx, c, wsOpts)
	case "http":
		// readability first, so just copy default TLS logic
		c, err = v.streamTLSConn(ctx, c, false)
		if err != nil {
			return nil, err
		}

		host, _, _ := net.SplitHostPort(v.addr)
		httpOpts := &mihomoVMess.HTTPConfig{
			Host:    host,
			Method:  v.option.HTTPOpts.Method,
			Path:    v.option.HTTPOpts.Path,
			Headers: v.option.HTTPOpts.Headers,
		}

		c = mihomoVMess.StreamHTTPConn(c, httpOpts)
	case "h2":
		c, err = v.streamTLSConn(ctx, c, true)
		if err != nil {
			return nil, err
		}

		h2Opts := &mihomoVMess.H2Config{
			Hosts: v.option.HTTP2Opts.Host,
			Path:  v.option.HTTP2Opts.Path,
		}

		c, err = mihomoVMess.StreamH2Conn(ctx, c, h2Opts)
	case "grpc":
		break // already handle in dialContext
	default:
		// default tcp network
		// handle TLS
		c, err = v.streamTLSConn(ctx, c, false)
	}

	if err != nil {
		return nil, err
	}
	return v.streamConnContext(ctx, c, metadata)
}

func (v *Vmess) streamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (conn net.Conn, err error) {
	useEarly := N.NeedHandshake(c)
	if !useEarly {
		if ctx.Done() != nil {
			done := N.SetupContextForConn(ctx, c)
			defer done(&err)
		}
	}
	if metadata.NetWork == C.UDP {
		if v.option.XUDP {
			var globalID [8]byte
			if metadata.SourceValid() {
				globalID = utils.GlobalID(metadata.SourceAddress())
			}
			if useEarly {
				conn = v.client.DialEarlyXUDPPacketConn(c,
					globalID,
					M.SocksaddrFromNet(metadata.UDPAddr()))
			} else {
				conn, err = v.client.DialXUDPPacketConn(c,
					globalID,
					M.SocksaddrFromNet(metadata.UDPAddr()))
			}
		} else if v.option.PacketAddr {
			if useEarly {
				conn = v.client.DialEarlyPacketConn(c,
					M.ParseSocksaddrHostPort(packetaddr.SeqPacketMagicAddress, 443))
			} else {
				conn, err = v.client.DialPacketConn(c,
					M.ParseSocksaddrHostPort(packetaddr.SeqPacketMagicAddress, 443))
			}
			conn = packetaddr.NewBindConn(conn)
		} else {
			if useEarly {
				conn = v.client.DialEarlyPacketConn(c,
					M.SocksaddrFromNet(metadata.UDPAddr()))
			} else {
				conn, err = v.client.DialPacketConn(c,
					M.SocksaddrFromNet(metadata.UDPAddr()))
			}
		}
	} else {
		if useEarly {
			conn = v.client.DialEarlyConn(c,
				M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
		} else {
			conn, err = v.client.DialConn(c,
				M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
		}
	}
	if err != nil {
		conn = nil
	}
	return
}

func (v *Vmess) streamTLSConn(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error) {
	if v.option.TLS {
		host, _, _ := net.SplitHostPort(v.addr)

		tlsOpts := mihomoVMess.TLSConfig{
			Host:              host,
			SkipCertVerify:    v.option.SkipCertVerify,
			FingerPrint:       v.option.Fingerprint,
			Certificate:       v.option.Certificate,
			PrivateKey:        v.option.PrivateKey,
			ClientFingerprint: v.option.ClientFingerprint,
			ECH:               v.echConfig,
			Reality:           v.realityConfig,
			NextProtos:        v.option.ALPN,
		}

		if isH2 {
			tlsOpts.NextProtos = []string{"h2"}
		}

		if v.option.ServerName != "" {
			tlsOpts.Host = v.option.ServerName
		}

		return mihomoVMess.StreamTLSConn(ctx, conn, &tlsOpts)
	}

	return conn, nil
}

func (v *Vmess) dialContext(ctx context.Context) (c net.Conn, err error) {
	switch v.option.Network {
	case "grpc": // gun transport
		return v.gunClient.Dial()
	default:
	}
	return v.dialer.DialContext(ctx, "tcp", v.addr)
}

// DialContext implements C.ProxyAdapter
func (v *Vmess) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := v.dialContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = v.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}
	return NewConn(c, v), err
}

// ListenPacketContext implements C.ProxyAdapter
func (v *Vmess) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = v.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	c, err := v.dialContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = v.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}

	if pc, ok := c.(net.PacketConn); ok {
		return newPacketConn(N.NewThreadSafePacketConn(pc), v), nil
	}
	return newPacketConn(&vmessPacketConn{Conn: c, rAddr: metadata.UDPAddr()}, v), nil
}

// ProxyInfo implements C.ProxyAdapter
func (v *Vmess) ProxyInfo() C.ProxyInfo {
	info := v.Base.ProxyInfo()
	info.DialerProxy = v.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (v *Vmess) Close() error {
	var errs []error
	if v.gunClient != nil {
		if err := v.gunClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// SupportUOT implements C.ProxyAdapter
func (v *Vmess) SupportUOT() bool {
	return true
}

func NewVmess(option VmessOption) (*Vmess, error) {
	security := strings.ToLower(option.Cipher)
	var options []vmess.ClientOption
	if option.GlobalPadding {
		options = append(options, vmess.ClientWithGlobalPadding())
	}
	if option.AuthenticatedLength {
		options = append(options, vmess.ClientWithAuthenticatedLength())
	}
	options = append(options, vmess.ClientWithTimeFunc(ntp.Now))
	client, err := vmess.NewClient(option.UUID, security, option.AlterID, options...)
	if err != nil {
		return nil, err
	}

	switch option.PacketEncoding {
	case "packetaddr", "packet":
		option.PacketAddr = true
	case "xudp":
		option.XUDP = true
	}
	if option.XUDP {
		option.PacketAddr = false
	}

	v := &Vmess{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.Vmess,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			XUDP:         option.XUDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		client: client,
		option: &option,
	}
	v.dialer = option.NewDialer(v.DialOptions())

	v.realityConfig, err = v.option.RealityOpts.Parse()
	if err != nil {
		return nil, err
	}

	v.echConfig, err = v.option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}

	switch option.Network {
	case "h2":
		if len(option.HTTP2Opts.Host) == 0 {
			option.HTTP2Opts.Host = append(option.HTTP2Opts.Host, "www.example.com")
		}
	case "grpc":
		dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := v.dialer.DialContext(ctx, "tcp", v.addr)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
			}
			return c, nil
		}

		gunConfig := &gun.Config{
			ServiceName:  option.GrpcOpts.GrpcServiceName,
			UserAgent:    option.GrpcOpts.GrpcUserAgent,
			Host:         option.ServerName,
			PingInterval: option.GrpcOpts.PingInterval,
		}
		if option.ServerName == "" {
			gunConfig.Host = v.addr
		}
		var tlsConfig *mihomoVMess.TLSConfig
		if option.TLS {
			tlsConfig = &mihomoVMess.TLSConfig{
				Host:              option.ServerName,
				SkipCertVerify:    option.SkipCertVerify,
				FingerPrint:       option.Fingerprint,
				Certificate:       option.Certificate,
				PrivateKey:        option.PrivateKey,
				ClientFingerprint: option.ClientFingerprint,
				NextProtos:        []string{"h2"},
				ECH:               v.echConfig,
				Reality:           v.realityConfig,
			}
			if option.ServerName == "" {
				host, _, _ := net.SplitHostPort(v.addr)
				tlsConfig.Host = host
			}
		}

		v.gunClient = gun.NewClient(
			func() *gun.Transport {
				return gun.NewTransport(dialFn, tlsConfig, gunConfig)
			},
			option.GrpcOpts.MaxConnections,
			option.GrpcOpts.MinStreams,
			option.GrpcOpts.MaxStreams,
		)
	}

	return v, nil
}

type vmessPacketConn struct {
	net.Conn
	rAddr  net.Addr
	access sync.Mutex
}

// WriteTo implments C.PacketConn.WriteTo
// Since VMess doesn't support full cone NAT by design, we verify if addr matches uc.rAddr, and drop the packet if not.
func (uc *vmessPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	allowedAddr := uc.rAddr
	destAddr := addr
	if allowedAddr.String() != destAddr.String() {
		return 0, ErrUDPRemoteAddrMismatch
	}
	uc.access.Lock()
	defer uc.access.Unlock()
	return uc.Conn.Write(b)
}

func (uc *vmessPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := uc.Conn.Read(b)
	return n, uc.rAddr, err
}
