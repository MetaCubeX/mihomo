package outbound

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/hysteria2/app/cmd"
	hy2client "github.com/metacubex/mihomo/transport/hysteria2/core/client"
)

const minHopInterval = 5
const defaultHopInterval = 30

type Hysteria2 struct {
	*Base

	option *Hysteria2Option
	client hy2client.Client
}

type Hysteria2Option struct {
	BasicOption
	Name           string        `proxy:"name"`
	Server         string        `proxy:"server"`
	Port           uint16        `proxy:"port,omitempty"`
	Ports          string        `proxy:"ports,omitempty"`
	HopInterval    time.Duration `proxy:"hop-interval,omitempty"`
	Up             string        `proxy:"up"`
	Down           string        `proxy:"down"`
	Password       string        `proxy:"password,omitempty"`
	Obfs           string        `proxy:"obfs,omitempty"`
	ObfsPassword   string        `proxy:"obfs-password,omitempty"`
	SNI            string        `proxy:"sni,omitempty"`
	SkipCertVerify bool          `proxy:"skip-cert-verify,omitempty"`
	Fingerprint    string        `proxy:"fingerprint,omitempty"`
	ALPN           []string      `proxy:"alpn,omitempty"`
	CustomCA       string        `proxy:"ca,omitempty"`
	CustomCAString string        `proxy:"ca-str,omitempty"`
	CWND           int           `proxy:"cwnd,omitempty"`
	FastOpen       bool          `proxy:"fast-open,omitempty"`
	Lazy           bool          `proxy:"lazy,omitempty"`
}

func (h *Hysteria2) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	tcpConn, err := h.client.TCP(net.JoinHostPort(metadata.String(), strconv.Itoa(int(metadata.DstPort))))
	if err != nil {
		return nil, err
	}

	return NewConn(tcpConn, h), nil
}

func (h *Hysteria2) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	udpConn, err := h.client.UDP()
	if err != nil {
		return nil, err
	}
	return newPacketConn(udpConn, h), nil
}

func NewHysteria2(option Hysteria2Option) (*Hysteria2, error) {
	var server string
	if option.Ports != "" {
		server = net.JoinHostPort(option.Server, option.Ports)
	} else {
		server = net.JoinHostPort(option.Server, strconv.Itoa(int(option.Port)))
	}

	if option.HopInterval == 0 {
		option.HopInterval = defaultHopInterval
	} else if option.HopInterval < minHopInterval {
		option.HopInterval = minHopInterval
	}
	option.HopInterval *= time.Second

	config := cmd.ClientConfig{
		Server: server,
		Auth:   option.Password,
		Transport: cmd.ClientConfigTransport{
			UDP: cmd.ClientConfigTransportUDP{
				HopInterval: option.HopInterval,
			},
		},
		TLS: cmd.ClientConfigTLS{
			SNI:       option.SNI,
			Insecure:  option.SkipCertVerify,
			PinSHA256: option.Fingerprint,
			CA:        option.CustomCA,
			CAString:  option.CustomCAString,
		},
		FastOpen: option.FastOpen,
		Lazy:     option.Lazy,
	}

	if option.ObfsPassword != "" {
		config.Obfs.Type = "salamander"
		config.Obfs.Salamander.Password = option.ObfsPassword
	} else if option.Obfs != "" {
		config.Obfs.Type = "salamander"
		config.Obfs.Salamander.Password = option.Obfs
	}

	last := option.Up[len(option.Up)-1]
	if '0' <= last && last <= '9' {
		option.Up += "m"
	}
	config.Bandwidth.Up = option.Up
	last = option.Down[len(option.Down)-1]
	if '0' <= last && last <= '9' {
		option.Down += "m"
	}
	config.Bandwidth.Down = option.Down

	client, err := hy2client.NewReconnectableClient(
		config.Config,
		func(c hy2client.Client, info *hy2client.HandshakeInfo, count int) {},
		option.Lazy)
	if err != nil {
		return nil, err
	}

	outbound := &Hysteria2{
		Base: &Base{
			name:   option.Name,
			addr:   server,
			tp:     C.Hysteria2,
			udp:    true,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		option: &option,
		client: client,
	}

	return outbound, nil
}
