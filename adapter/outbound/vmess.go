package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/component/proxydialer"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/gun"
	mihomoVMess "github.com/metacubex/mihomo/transport/vmess"
	"github.com/metacubex/mihomo/transport/xhttp"

	vmess "github.com/metacubex/sing-vmess"
	"github.com/metacubex/sing-vmess/packetaddr"
	M "github.com/metacubex/sing/common/metadata"
)

var ErrUDPRemoteAddrMismatch = errors.New("udp packet dropped due to mismatched remote address")

type Vmess struct {
	*Base
	client *vmess.Client
	option *VmessOption

	// for gun mux
	gunTLSConfig *tls.Config
	gunConfig    *gun.Config
	transport    *gun.TransportWrap

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
	XHttpOpts           *xhttp.Config  `proxy:"xhttp-opts,omitempty"`
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
}

type WSOptions struct {
	Path                     string            `proxy:"path,omitempty"`
	Headers                  map[string]string `proxy:"headers,omitempty"`
	MaxEarlyData             int               `proxy:"max-early-data,omitempty"`
	EarlyDataHeaderName      string            `proxy:"early-data-header-name,omitempty"`
	V2rayHttpUpgrade         bool              `proxy:"v2ray-http-upgrade,omitempty"`
	V2rayHttpUpgradeFastOpen bool              `proxy:"v2ray-http-upgrade-fast-open,omitempty"`
}

// StreamConnContext implements C.ProxyAdapter
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
		if v.option.TLS {
			host, _, _ := net.SplitHostPort(v.addr)
			tlsOpts := &mihomoVMess.TLSConfig{
				Host:              host,
				SkipCertVerify:    v.option.SkipCertVerify,
				ClientFingerprint: v.option.ClientFingerprint,
				ECH:               v.echConfig,
				Reality:           v.realityConfig,
				NextProtos:        v.option.ALPN,
			}

			if v.option.ServerName != "" {
				tlsOpts.Host = v.option.ServerName
			}
			c, err = mihomoVMess.StreamTLSConn(ctx, c, tlsOpts)
			if err != nil {
				return nil, err
			}
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
		host, _, _ := net.SplitHostPort(v.addr)
		tlsOpts := mihomoVMess.TLSConfig{
			Host:              host,
			SkipCertVerify:    v.option.SkipCertVerify,
			FingerPrint:       v.option.Fingerprint,
			Certificate:       v.option.Certificate,
			PrivateKey:        v.option.PrivateKey,
			NextProtos:        []string{"h2"},
			ClientFingerprint: v.option.ClientFingerprint,
			Reality:           v.realityConfig,
		}

		if v.option.ServerName != "" {
			tlsOpts.Host = v.option.ServerName
		}

		c, err = mihomoVMess.StreamTLSConn(ctx, c, &tlsOpts)
		if err != nil {
			return nil, err
		}

		h2Opts := &mihomoVMess.H2Config{
			Hosts: v.option.HTTP2Opts.Host,
			Path:  v.option.HTTP2Opts.Path,
		}

		c, err = mihomoVMess.StreamH2Conn(ctx, c, h2Opts)
	case "grpc":
		c, err = gun.StreamGunWithConn(c, v.gunTLSConfig, v.gunConfig, v.echConfig, v.realityConfig)
	default:
		// handle TLS
		if v.option.TLS {
			host, _, _ := net.SplitHostPort(v.addr)
			tlsOpts := &mihomoVMess.TLSConfig{
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

			if v.option.ServerName != "" {
				tlsOpts.Host = v.option.ServerName
			}

			c, err = mihomoVMess.StreamTLSConn(ctx, c, tlsOpts)
		}
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

// DialContext implements C.ProxyAdapter
func (v *Vmess) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	var c net.Conn
	// gun transport
	if v.transport != nil {
		c, err = gun.StreamGunWithTransport(v.transport, v.gunConfig)
		if err != nil {
			return nil, err
		}
		defer func(c net.Conn) {
			safeConnClose(c, err)
		}(c)

		c, err = v.streamConnContext(ctx, c, metadata)
		if err != nil {
			return nil, err
		}

		return NewConn(c, v), nil
	}
	return v.DialContextWithDialer(ctx, dialer.NewDialer(v.DialOptions()...), metadata)
}

// DialContextWithDialer implements C.ProxyAdapter
func (v *Vmess) DialContextWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.Conn, err error) {
	if len(v.option.DialerProxy) > 0 {
		dialer, err = proxydialer.NewByName(v.option.DialerProxy, dialer)
		if err != nil {
			return nil, err
		}
	}

	if v.option.Network == "xhttp" {
		c, err := v.dialXHTTP(ctx, dialer)
		if err != nil {
			return nil, err
		}
		defer func(conn net.Conn) {
			safeConnClose(conn, err)
		}(c)
		c, err = v.streamConnContext(ctx, c, metadata)
		return NewConn(c, v), err
	}

	c, err := dialer.DialContext(ctx, "tcp", v.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = v.StreamConnContext(ctx, c, metadata)
	return NewConn(c, v), err
}

// ListenPacketContext implements C.ProxyAdapter
func (v *Vmess) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = v.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	var c net.Conn
	// gun transport
	if v.transport != nil {
		c, err = gun.StreamGunWithTransport(v.transport, v.gunConfig)
		if err != nil {
			return nil, err
		}
		defer func(c net.Conn) {
			safeConnClose(c, err)
		}(c)

		c, err = v.streamConnContext(ctx, c, metadata)
		if err != nil {
			return nil, fmt.Errorf("new vmess client error: %v", err)
		}
		return v.ListenPacketOnStreamConn(ctx, c, metadata)
	}
	return v.ListenPacketWithDialer(ctx, dialer.NewDialer(v.DialOptions()...), metadata)
}

// ListenPacketWithDialer implements C.ProxyAdapter
func (v *Vmess) ListenPacketWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if len(v.option.DialerProxy) > 0 {
		dialer, err = proxydialer.NewByName(v.option.DialerProxy, dialer)
		if err != nil {
			return nil, err
		}
	}

	if err = v.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	c, err := dialer.DialContext(ctx, "tcp", v.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = v.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, fmt.Errorf("new vmess client error: %v", err)
	}
	return v.ListenPacketOnStreamConn(ctx, c, metadata)
}

// SupportWithDialer implements C.ProxyAdapter
func (v *Vmess) SupportWithDialer() C.NetWork {
	return C.ALLNet
}

// ProxyInfo implements C.ProxyAdapter
func (v *Vmess) ProxyInfo() C.ProxyInfo {
	info := v.Base.ProxyInfo()
	info.DialerProxy = v.option.DialerProxy
	return info
}

func (v *Vmess) dialXHTTP(ctx context.Context, d C.Dialer) (net.Conn, error) {
	cfg := v.option.XHttpOpts
	if cfg == nil {
		cfg = &xhttp.Config{}
	} else {
		cfg = cfg.Clone()
	}
	scheme := "http"
	if v.option.TLS || v.realityConfig != nil {
		scheme = "https"
	}
	hostHeader := cfg.Host
	if hostHeader == "" {
		hostHeader = v.option.ServerName
		if hostHeader == "" {
			if host, _, err := net.SplitHostPort(v.addr); err == nil {
				hostHeader = host
			} else {
				hostHeader = v.addr
			}
		}
	}
	httpVersion := "1.1"
	if scheme == "https" {
		httpVersion = "2"
	}
	if len(v.option.ALPN) == 1 && v.option.ALPN[0] == "http/1.1" {
		httpVersion = "1.1"
	}
	cfg.EnsureHTTP3TLS(hostHeader, v.option.SkipCertVerify)

	dialFn := func(ctx context.Context, network string) (net.Conn, error) {
		if network == "" {
			network = "tcp"
		}
		conn, err := d.DialContext(ctx, network, v.addr)
		if err != nil {
			return nil, err
		}
		if network != "tcp" {
			return conn, nil
		}
		if scheme == "https" || v.realityConfig != nil || v.option.TLS {
			tlsHost := v.option.ServerName
			if tlsHost == "" {
				tlsHost = hostHeader
			}
			if tlsHost == "" {
				if host, _, err := net.SplitHostPort(v.addr); err == nil {
					tlsHost = host
				}
			}
			tlsCfg := &mihomoVMess.TLSConfig{
				Host:              tlsHost,
				SkipCertVerify:    v.option.SkipCertVerify,
				FingerPrint:       v.option.Fingerprint,
				Certificate:       v.option.Certificate,
				PrivateKey:        v.option.PrivateKey,
				ClientFingerprint: v.option.ClientFingerprint,
				ECH:               v.echConfig,
				Reality:           v.realityConfig,
				NextProtos:        []string{"h2"},
			}
			if httpVersion == "1.1" {
				tlsCfg.NextProtos = []string{"http/1.1"}
			}
			conn, err = mihomoVMess.StreamTLSConn(ctx, conn, tlsCfg)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
		}
		return conn, nil
	}
	return xhttp.Dial(ctx, xhttp.Options{
		Dial:         dialFn,
		Config:       cfg,
		Scheme:       scheme,
		HostHeader:   hostHeader,
		Address:      v.addr,
		HTTPVersion:  httpVersion,
		PreferStream: v.realityConfig != nil,
		Tag:          fmt.Sprintf("vmess[%s]", v.Name()),
	})
}

// Close implements C.ProxyAdapter
func (v *Vmess) Close() error {
	if v.transport != nil {
		return v.transport.Close()
	}
	return nil
}

// ListenPacketOnStreamConn implements C.ProxyAdapter
func (v *Vmess) ListenPacketOnStreamConn(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = v.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	if pc, ok := c.(net.PacketConn); ok {
		return newPacketConn(N.NewThreadSafePacketConn(pc), v), nil
	}
	return newPacketConn(&vmessPacketConn{Conn: c, rAddr: metadata.UDPAddr()}, v), nil
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
		Base: &Base{
			name:   option.Name,
			addr:   net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:     C.Vmess,
			udp:    option.UDP,
			xudp:   option.XUDP,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		client: client,
		option: &option,
	}

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
			var err error
			var cDialer C.Dialer = dialer.NewDialer(v.DialOptions()...)
			if len(v.option.DialerProxy) > 0 {
				cDialer, err = proxydialer.NewByName(v.option.DialerProxy, cDialer)
				if err != nil {
					return nil, err
				}
			}
			c, err := cDialer.DialContext(ctx, "tcp", v.addr)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
			}
			return c, nil
		}

		gunConfig := &gun.Config{
			ServiceName:       v.option.GrpcOpts.GrpcServiceName,
			Host:              v.option.ServerName,
			ClientFingerprint: v.option.ClientFingerprint,
		}
		if option.ServerName == "" {
			gunConfig.Host = v.addr
		}
		var tlsConfig *tls.Config
		if option.TLS {
			tlsConfig, err = ca.GetTLSConfig(ca.Option{
				TLSConfig: &tls.Config{
					InsecureSkipVerify: v.option.SkipCertVerify,
					ServerName:         v.option.ServerName,
				},
				Fingerprint: v.option.Fingerprint,
				Certificate: v.option.Certificate,
				PrivateKey:  v.option.PrivateKey,
			})
			if err != nil {
				return nil, err
			}
			if option.ServerName == "" {
				host, _, _ := net.SplitHostPort(v.addr)
				tlsConfig.ServerName = host
			}
		}

		v.gunTLSConfig = tlsConfig
		v.gunConfig = gunConfig

		v.transport = gun.NewHTTP2Client(dialFn, tlsConfig, v.option.ClientFingerprint, v.echConfig, v.realityConfig)
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
