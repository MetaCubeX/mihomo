package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/metacubex/mihomo/common/convert"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/gun"
	"github.com/metacubex/mihomo/transport/vless"
	"github.com/metacubex/mihomo/transport/vless/encryption"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	vmessSing "github.com/metacubex/sing-vmess"
	"github.com/metacubex/sing-vmess/packetaddr"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

type Vless struct {
	*Base
	client *vless.Client
	option *VlessOption

	encryption *encryption.ClientInstance

	// for gun mux
	gunTLSConfig *tls.Config
	gunConfig    *gun.Config
	transport    *gun.TransportWrap

	realityConfig *tlsC.RealityConfig
	echConfig     *ech.Config
}

type VlessOption struct {
	BasicOption
	Name              string            `proxy:"name"`
	Server            string            `proxy:"server"`
	Port              int               `proxy:"port"`
	UUID              string            `proxy:"uuid"`
	Flow              string            `proxy:"flow,omitempty"`
	TLS               bool              `proxy:"tls,omitempty"`
	ALPN              []string          `proxy:"alpn,omitempty"`
	UDP               bool              `proxy:"udp,omitempty"`
	PacketAddr        bool              `proxy:"packet-addr,omitempty"`
	XUDP              bool              `proxy:"xudp,omitempty"`
	PacketEncoding    string            `proxy:"packet-encoding,omitempty"`
	Encryption        string            `proxy:"encryption,omitempty"`
	Network           string            `proxy:"network,omitempty"`
	ECHOpts           ECHOptions        `proxy:"ech-opts,omitempty"`
	RealityOpts       RealityOptions    `proxy:"reality-opts,omitempty"`
	HTTPOpts          HTTPOptions       `proxy:"http-opts,omitempty"`
	HTTP2Opts         HTTP2Options      `proxy:"h2-opts,omitempty"`
	GrpcOpts          GrpcOptions       `proxy:"grpc-opts,omitempty"`
	WSOpts            WSOptions         `proxy:"ws-opts,omitempty"`
	WSHeaders         map[string]string `proxy:"ws-headers,omitempty"`
	SkipCertVerify    bool              `proxy:"skip-cert-verify,omitempty"`
	Fingerprint       string            `proxy:"fingerprint,omitempty"`
	Certificate       string            `proxy:"certificate,omitempty"`
	PrivateKey        string            `proxy:"private-key,omitempty"`
	ServerName        string            `proxy:"servername,omitempty"`
	ClientFingerprint string            `proxy:"client-fingerprint,omitempty"`
}

func (v *Vless) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ net.Conn, err error) {
	switch v.option.Network {
	case "ws":
		host, port, _ := net.SplitHostPort(v.addr)
		wsOpts := &vmess.WebsocketConfig{
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
					MinVersion:         tls.VersionTLS12,
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
		} else {
			if host := wsOpts.Headers.Get("Host"); host == "" {
				wsOpts.Headers.Set("Host", convert.RandHost())
				convert.SetUserAgent(wsOpts.Headers)
			}
		}
		c, err = vmess.StreamWebsocketConn(ctx, c, wsOpts)
	case "http":
		// readability first, so just copy default TLS logic
		c, err = v.streamTLSConn(ctx, c, false)
		if err != nil {
			return nil, err
		}

		host, _, _ := net.SplitHostPort(v.addr)
		httpOpts := &vmess.HTTPConfig{
			Host:    host,
			Method:  v.option.HTTPOpts.Method,
			Path:    v.option.HTTPOpts.Path,
			Headers: v.option.HTTPOpts.Headers,
		}

		c = vmess.StreamHTTPConn(c, httpOpts)
	case "h2":
		c, err = v.streamTLSConn(ctx, c, true)
		if err != nil {
			return nil, err
		}

		h2Opts := &vmess.H2Config{
			Hosts: v.option.HTTP2Opts.Host,
			Path:  v.option.HTTP2Opts.Path,
		}

		c, err = vmess.StreamH2Conn(ctx, c, h2Opts)
	case "grpc":
		c, err = gun.StreamGunWithConn(c, v.gunTLSConfig, v.gunConfig, v.echConfig, v.realityConfig)
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

func (v *Vless) streamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (conn net.Conn, err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}
	if v.encryption != nil {
		c, err = v.encryption.Handshake(c)
		if err != nil {
			return
		}
	}
	if metadata.NetWork == C.UDP {
		if v.option.PacketAddr {
			metadata = &C.Metadata{
				NetWork: C.UDP,
				Host:    packetaddr.SeqPacketMagicAddress,
				DstPort: 443,
			}
		} else {
			metadata = &C.Metadata{ // a clear metadata only contains ip
				NetWork: C.UDP,
				DstIP:   metadata.DstIP,
				DstPort: metadata.DstPort,
			}
		}
		conn, err = v.client.StreamConn(c, parseVlessAddr(metadata, v.option.XUDP))
	} else {
		conn, err = v.client.StreamConn(c, parseVlessAddr(metadata, false))
	}
	if err != nil {
		conn = nil
	}
	return
}

func (v *Vless) streamTLSConn(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error) {
	if v.option.TLS {
		host, _, _ := net.SplitHostPort(v.addr)

		tlsOpts := vmess.TLSConfig{
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

		return vmess.StreamTLSConn(ctx, conn, &tlsOpts)
	}

	return conn, nil
}

// DialContext implements C.ProxyAdapter
func (v *Vless) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
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
	c, err = v.dialer.DialContext(ctx, "tcp", v.addr)
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
func (v *Vless) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
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
			return nil, fmt.Errorf("new vless client error: %v", err)
		}

		return v.ListenPacketOnStreamConn(ctx, c, metadata)
	}

	if err = v.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	c, err = v.dialer.DialContext(ctx, "tcp", v.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = v.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, fmt.Errorf("new vless client error: %v", err)
	}

	return v.ListenPacketOnStreamConn(ctx, c, metadata)
}

// ListenPacketOnStreamConn implements C.ProxyAdapter
func (v *Vless) ListenPacketOnStreamConn(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = v.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	if v.option.XUDP {
		var globalID [8]byte
		if metadata.SourceValid() {
			globalID = utils.GlobalID(metadata.SourceAddress())
		}
		return newPacketConn(N.NewThreadSafePacketConn(
			vmessSing.NewXUDPConn(c,
				globalID,
				M.SocksaddrFromNet(metadata.UDPAddr())),
		), v), nil
	} else if v.option.PacketAddr {
		return newPacketConn(N.NewThreadSafePacketConn(
			packetaddr.NewConn(v.client.PacketConn(c, metadata.UDPAddr()),
				M.SocksaddrFromNet(metadata.UDPAddr())),
		), v), nil
	}
	return newPacketConn(N.NewThreadSafePacketConn(v.client.PacketConn(c, metadata.UDPAddr())), v), nil
}

// SupportUOT implements C.ProxyAdapter
func (v *Vless) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (v *Vless) ProxyInfo() C.ProxyInfo {
	info := v.Base.ProxyInfo()
	info.DialerProxy = v.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (v *Vless) Close() error {
	if v.transport != nil {
		return v.transport.Close()
	}
	return nil
}

func parseVlessAddr(metadata *C.Metadata, xudp bool) *vless.DstAddr {
	var addrType byte
	var addr []byte
	switch metadata.AddrType() {
	case C.AtypIPv4:
		addrType = vless.AtypIPv4
		addr = make([]byte, net.IPv4len)
		copy(addr[:], metadata.DstIP.AsSlice())
	case C.AtypIPv6:
		addrType = vless.AtypIPv6
		addr = make([]byte, net.IPv6len)
		copy(addr[:], metadata.DstIP.AsSlice())
	case C.AtypDomainName:
		addrType = vless.AtypDomainName
		addr = make([]byte, len(metadata.Host)+1)
		addr[0] = byte(len(metadata.Host))
		copy(addr[1:], metadata.Host)
	}

	return &vless.DstAddr{
		UDP:      metadata.NetWork == C.UDP,
		AddrType: addrType,
		Addr:     addr,
		Port:     metadata.DstPort,
		Mux:      metadata.NetWork == C.UDP && xudp,
	}
}

func NewVless(option VlessOption) (*Vless, error) {
	var addons *vless.Addons
	if len(option.Flow) >= 16 {
		option.Flow = option.Flow[:16]
		if option.Flow != vless.XRV {
			return nil, fmt.Errorf("unsupported xtls flow type: %s", option.Flow)
		}
		addons = &vless.Addons{
			Flow: option.Flow,
		}
	}

	switch option.PacketEncoding {
	case "packetaddr", "packet":
		option.PacketAddr = true
		option.XUDP = false
	default: // https://github.com/XTLS/Xray-core/pull/1567#issuecomment-1407305458
		if !option.PacketAddr {
			option.XUDP = true
		}
	}
	if option.XUDP {
		option.PacketAddr = false
	}

	client, err := vless.NewClient(option.UUID, addons)
	if err != nil {
		return nil, err
	}

	v := &Vless{
		Base: &Base{
			name:   option.Name,
			addr:   net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:     C.Vless,
			pdName: option.ProviderName,
			udp:    option.UDP,
			xudp:   option.XUDP,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: option.IPVersion,
		},
		client: client,
		option: &option,
	}
	v.dialer = option.NewDialer(v.DialOptions())

	v.encryption, err = encryption.NewClient(option.Encryption)
	if err != nil {
		return nil, err
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
			c, err := v.dialer.DialContext(ctx, "tcp", v.addr)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
			}
			return c, nil
		}

		gunConfig := &gun.Config{
			ServiceName:       v.option.GrpcOpts.GrpcServiceName,
			UserAgent:         v.option.GrpcOpts.GrpcUserAgent,
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
