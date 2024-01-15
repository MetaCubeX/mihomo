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
	"sync/atomic"
	"time"

	CN "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	tuicCommon "github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/metacubex/sing-quic/hysteria2"

	M "github.com/sagernet/sing/common/metadata"
)

const minHopInterval = 5
const defaultHopInterval = 30

var closedForPortHopping = errors.New("hopping port")

func init() {
	hysteria2.SetCongestionController = tuicCommon.SetCongestionController
}

type Hysteria2 struct {
	*Base

	option        *Hysteria2Option
	clientOptions *hysteria2.ClientOptions
	client        *hysteria2.Client
	dialer        proxydialer.SingDialer

	ports       []uint16
	lastHopTime int64
}

type Hysteria2Option struct {
	BasicOption
	Name           string   `proxy:"name"`
	Server         string   `proxy:"server"`
	Port           uint16   `proxy:"port"`
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
}

func (h *Hysteria2) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	now := time.Now().UnixMilli()
	if now > h.lastHopTime+int64(h.option.HopInterval*1000) { // convert to milliseconds
		if atomic.CompareAndSwapInt64(&h.lastHopTime, h.lastHopTime, now) {
			h.option.Port = h.ports[rand.Intn(len(h.ports))]
			h.clientOptions.ServerAddress = M.ParseSocksaddrHostPort(h.option.Server, h.option.Port)

			client, err := hysteria2.NewClient(*h.clientOptions)
			if err == nil {
				h.client.CloseWithError(closedForPortHopping)
				h.client = client
				h.addr = net.JoinHostPort(h.option.Server, strconv.Itoa(int(h.option.Port)))
				log.Infoln("[%s] hopped to port %d", h.name, h.option.Port)
			} else {
				log.Errorln("[%s] failed to hop port: %v", h.name, err)
			}
		}
		// the concurrent CAS will fail, but it's safe to use the previous client
	}
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

func NewHysteria2(option Hysteria2Option) (*Hysteria2, error) {
	var ports []uint16
	if option.Ports != "" {
		ps, err := utils.ParsePorts(option.Ports)
		if err == nil {
			if option.HopInterval == 0 {
				option.HopInterval = defaultHopInterval
			} else if option.HopInterval < minHopInterval {
				option.HopInterval = minHopInterval
			}
			option.Port = ps[rand.Intn(len(ps))]
			ports = ps
		}
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(int(option.Port)))
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

	singDialer := proxydialer.NewByNameSingDialer(option.DialerProxy, dialer.NewDialer())

	clientOptions := hysteria2.ClientOptions{
		Context:            context.TODO(),
		Dialer:             singDialer,
		ServerAddress:      M.ParseSocksaddrHostPort(option.Server, option.Port),
		SendBPS:            StringToBps(option.Up),
		ReceiveBPS:         StringToBps(option.Down),
		SalamanderPassword: salamanderPassword,
		Password:           option.Password,
		TLSConfig:          tlsConfig,
		UDPDisabled:        false,
		CWND:               option.CWND,
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
		option:        &option,
		clientOptions: &clientOptions,
		client:        client,
		dialer:        singDialer,
		ports:         ports,
		lastHopTime:   time.Now().UnixMilli(),
	}
	runtime.SetFinalizer(outbound, closeHysteria2)

	return outbound, nil
}
