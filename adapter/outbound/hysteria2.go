package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	CN "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	tuicCommon "github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/sing-quic/hysteria2"
	M "github.com/metacubex/sing/common/metadata"
)

func init() {
	hysteria2.SetCongestionController = tuicCommon.SetCongestionController
}

const minHopInterval = 5
const defaultHopInterval = 30

type Hysteria2 struct {
	*Base

	option *Hysteria2Option
	client *hysteria2.Client
	dialer proxydialer.SingDialer
}

type Hysteria2Option struct {
	BasicOption
	Name           string     `proxy:"name"`
	Server         string     `proxy:"server"`
	Port           int        `proxy:"port,omitempty"`
	Ports          string     `proxy:"ports,omitempty"`
	HopInterval    int        `proxy:"hop-interval,omitempty"`
	Up             string     `proxy:"up,omitempty"`
	Down           string     `proxy:"down,omitempty"`
	Password       string     `proxy:"password,omitempty"`
	Obfs           string     `proxy:"obfs,omitempty"`
	ObfsPassword   string     `proxy:"obfs-password,omitempty"`
	SNI            string     `proxy:"sni,omitempty"`
	ECHOpts        ECHOptions `proxy:"ech-opts,omitempty"`
	SkipCertVerify bool       `proxy:"skip-cert-verify,omitempty"`
	Fingerprint    string     `proxy:"fingerprint,omitempty"`
	ALPN           []string   `proxy:"alpn,omitempty"`
	CustomCA       string     `proxy:"ca,omitempty"`
	CustomCAString string     `proxy:"ca-str,omitempty"`
	CWND           int        `proxy:"cwnd,omitempty"`
	UdpMTU         int        `proxy:"udp-mtu,omitempty"`

	// quic-go special config
	InitialStreamReceiveWindow     uint64 `proxy:"initial-stream-receive-window,omitempty"`
	MaxStreamReceiveWindow         uint64 `proxy:"max-stream-receive-window,omitempty"`
	InitialConnectionReceiveWindow uint64 `proxy:"initial-connection-receive-window,omitempty"`
	MaxConnectionReceiveWindow     uint64 `proxy:"max-connection-receive-window,omitempty"`
}

func (h *Hysteria2) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := h.client.DialConn(ctx, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	if err != nil {
		return nil, err
	}
	return NewConn(c, h), nil
}

func (h *Hysteria2) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = h.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc, err := h.client.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, errors.New("packetConn is nil")
	}
	return newPacketConn(CN.NewThreadSafePacketConn(pc), h), nil
}

// Close implements C.ProxyAdapter
func (h *Hysteria2) Close() error {
	if h.client != nil {
		return h.client.CloseWithError(errors.New("proxy removed"))
	}
	return nil
}

// ProxyInfo implements C.ProxyAdapter
func (h *Hysteria2) ProxyInfo() C.ProxyInfo {
	info := h.Base.ProxyInfo()
	info.DialerProxy = h.option.DialerProxy
	return info
}

func NewHysteria2(option Hysteria2Option) (*Hysteria2, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &Hysteria2{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Hysteria2,
			udp:    true,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		option: &option,
	}

	singDialer := proxydialer.NewByNameSingDialer(option.DialerProxy, dialer.NewDialer(outbound.DialOptions()...))
	outbound.dialer = singDialer

	var salamanderPassword string
	if len(option.Obfs) > 0 {
		if option.ObfsPassword == "" {
			return nil, errors.New("missing obfs password")
		}
		switch option.Obfs {
		case hysteria2.ObfsTypeSalamander:
			salamanderPassword = option.ObfsPassword
		default:
			return nil, fmt.Errorf("unknown obfs type: %s", option.Obfs)
		}
	}

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

	if option.ALPN != nil { // structure's Decode will ensure value not nil when input has value even it was set an empty array
		tlsConfig.NextProtos = option.ALPN
	}

	tlsClientConfig := tlsC.UConfig(tlsConfig)
	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}

	if option.UdpMTU == 0 {
		// "1200" from quic-go's MaxDatagramSize
		// "-3" from quic-go's DatagramFrame.MaxDataLen
		option.UdpMTU = 1200 - 3
	}

	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     option.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         option.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: option.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     option.MaxConnectionReceiveWindow,
	}

	clientOptions := hysteria2.ClientOptions{
		Context:            context.TODO(),
		Dialer:             singDialer,
		Logger:             log.SingLogger,
		SendBPS:            StringToBps(option.Up),
		ReceiveBPS:         StringToBps(option.Down),
		SalamanderPassword: salamanderPassword,
		Password:           option.Password,
		TLSConfig:          tlsClientConfig,
		QUICConfig:         quicConfig,
		UDPDisabled:        false,
		CWND:               option.CWND,
		UdpMTU:             option.UdpMTU,
		ServerAddress: func(ctx context.Context) (*net.UDPAddr, error) {
			udpAddr, err := resolveUDPAddr(ctx, "udp", addr, C.NewDNSPrefer(option.IPVersion))
			if err != nil {
				return nil, err
			}
			err = echConfig.ClientHandle(ctx, tlsClientConfig)
			if err != nil {
				return nil, err
			}
			return udpAddr, nil
		},
	}

	var ranges utils.IntRanges[uint16]
	var serverPorts []uint16
	if option.Ports != "" {
		ranges, err = utils.NewUnsignedRanges[uint16](option.Ports)
		if err != nil {
			return nil, err
		}
		ranges.Range(func(port uint16) bool {
			serverPorts = append(serverPorts, port)
			return true
		})
		if len(serverPorts) > 0 {
			if option.HopInterval == 0 {
				option.HopInterval = defaultHopInterval
			} else if option.HopInterval < minHopInterval {
				option.HopInterval = minHopInterval
			}
			clientOptions.HopInterval = time.Duration(option.HopInterval) * time.Second
			clientOptions.ServerPorts = serverPorts
		}
	}
	if option.Port == 0 && len(serverPorts) == 0 {
		return nil, errors.New("invalid port")
	}

	client, err := hysteria2.NewClient(clientOptions)
	if err != nil {
		return nil, err
	}
	outbound.client = client

	return outbound, nil
}
