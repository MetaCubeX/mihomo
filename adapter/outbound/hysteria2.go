package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"

	CN "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	tuicCommon "github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/metacubex/sing-quic/hysteria2"

	M "github.com/sagernet/sing/common/metadata"
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
	Name           string   `proxy:"name"`
	Server         string   `proxy:"server"`
	Port           int      `proxy:"port"`
	Ports          string   `proxy:"ports,omitempty"`
	HopInterval    int      `proxy:"hop-interval,omitempty"`
	Up             string   `proxy:"up,omitempty"`
	Down           string   `proxy:"down,omitempty"`
	Password       string   `proxy:"password,omitempty"`
	Obfs           string   `proxy:"obfs,omitempty"`
	ObfsPassword   string   `proxy:"obfs-password,omitempty"`
	SNI            string   `proxy:"sni,omitempty"`
	SkipCertVerify bool     `proxy:"skip-cert-verify,omitempty"`
	Fingerprint    string   `proxy:"fingerprint,omitempty"`
	ALPN           []string `proxy:"alpn,omitempty"`
	CustomCA       string   `proxy:"ca,omitempty"`
	CustomCAString string   `proxy:"ca-str,omitempty"`
	CWND           int      `proxy:"cwnd,omitempty"`
	UdpMTU         int      `proxy:"udp-mtu,omitempty"`
}

func (h *Hysteria2) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	options := h.Base.DialOptions(opts...)
	h.dialer.SetDialer(dialer.NewDialer(options...))
	c, err := h.client.DialConn(ctx, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	if err != nil {
		return nil, err
	}
	return NewConn(CN.NewRefConn(c, h), h), nil
}

func (h *Hysteria2) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	options := h.Base.DialOptions(opts...)
	h.dialer.SetDialer(dialer.NewDialer(options...))
	pc, err := h.client.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, errors.New("packetConn is nil")
	}
	return newPacketConn(CN.NewRefPacketConn(CN.NewThreadSafePacketConn(pc), h), h), nil
}

func closeHysteria2(h *Hysteria2) {
	if h.client != nil {
		_ = h.client.CloseWithError(errors.New("proxy removed"))
	}
}

func parsePorts(portStr string) (ports []uint16) {
	portStrs := strings.Split(portStr, ",")
	for _, portStr := range portStrs {
		if strings.Contains(portStr, "-") {
			// Port range
			portRange := strings.Split(portStr, "-")
			if len(portRange) != 2 {
				return nil
			}
			start, err := strconv.ParseUint(portRange[0], 10, 16)
			if err != nil {
				return nil
			}
			end, err := strconv.ParseUint(portRange[1], 10, 16)
			if err != nil {
				return nil
			}
			if start > end {
				start, end = end, start
			}
			for i := start; i <= end; i++ {
				ports = append(ports, uint16(i))
			}
		} else {
			// Single port
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				return nil
			}
			ports = append(ports, uint16(port))
		}
	}
	return ports
}

func NewHysteria2(option Hysteria2Option) (*Hysteria2, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
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

	if len(option.ALPN) > 0 {
		tlsConfig.NextProtos = option.ALPN
	}

	if option.UdpMTU == 0 {
		// "1200" from quic-go's MaxDatagramSize
		// "-3" from quic-go's DatagramFrame.MaxDataLen
		option.UdpMTU = 1200 - 3
	}

	singDialer := proxydialer.NewByNameSingDialer(option.DialerProxy, dialer.NewDialer())

	clientOptions := hysteria2.ClientOptions{
		Context:            context.TODO(),
		Dialer:             singDialer,
		Logger:             log.SingLogger,
		ServerAddress:      M.ParseSocksaddrHostPort(option.Server, uint16(option.Port)),
		SendBPS:            StringToBps(option.Up),
		ReceiveBPS:         StringToBps(option.Down),
		SalamanderPassword: salamanderPassword,
		Password:           option.Password,
		TLSConfig:          tlsConfig,
		UDPDisabled:        false,
		CWND:               option.CWND,
		UdpMTU:             option.UdpMTU,
	}

	if option.Ports != "" {
		ports := parsePorts(option.Ports)
		if len(ports) > 0 {
			for _, port := range ports {
				clientOptions.ServerAddresses = append(clientOptions.ServerAddresses, M.ParseSocksaddrHostPort(option.Server, port))
			}
			clientOptions.ServerAddress = clientOptions.ServerAddresses[rand.Intn(len(clientOptions.ServerAddresses))]

			if option.HopInterval == 0 {
				option.HopInterval = defaultHopInterval
			} else if option.HopInterval < minHopInterval {
				option.HopInterval = minHopInterval
			}
			clientOptions.HopInterval = time.Duration(option.HopInterval) * time.Second
		}
	}

	client, err := hysteria2.NewClient(clientOptions)
	if err != nil {
		return nil, err
	}

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
		client: client,
		dialer: singDialer,
	}
	runtime.SetFinalizer(outbound, closeHysteria2)

	return outbound, nil
}
