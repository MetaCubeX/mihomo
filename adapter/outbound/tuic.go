package outbound

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/metacubex/quic-go"

	"github.com/Dreamacro/clash/component/dialer"
	tlsC "github.com/Dreamacro/clash/component/tls"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/tuic"
)

type Tuic struct {
	*Base
	client *tuic.PoolClient
}

type TuicOption struct {
	BasicOption
	Name                  string   `proxy:"name"`
	Server                string   `proxy:"server"`
	Port                  int      `proxy:"port"`
	Token                 string   `proxy:"token"`
	Ip                    string   `proxy:"ip,omitempty"`
	HeartbeatInterval     int      `proxy:"heartbeat-interval,omitempty"`
	ALPN                  []string `proxy:"alpn,omitempty"`
	ReduceRtt             bool     `proxy:"reduce-rtt,omitempty"`
	RequestTimeout        int      `proxy:"request-timeout,omitempty"`
	UdpRelayMode          string   `proxy:"udp-relay-mode,omitempty"`
	CongestionController  string   `proxy:"congestion-controller,omitempty"`
	DisableSni            bool     `proxy:"disable-sni,omitempty"`
	MaxUdpRelayPacketSize int      `proxy:"max-udp-relay-packet-size,omitempty"`

	FastOpen            bool   `proxy:"fast-open,omitempty"`
	MaxOpenStreams      int    `proxy:"max-open-streams,omitempty"`
	SkipCertVerify      bool   `proxy:"skip-cert-verify,omitempty"`
	Fingerprint         string `proxy:"fingerprint,omitempty"`
	CustomCA            string `proxy:"ca,omitempty"`
	CustomCAString      string `proxy:"ca-str,omitempty"`
	ReceiveWindowConn   int    `proxy:"recv-window-conn,omitempty"`
	ReceiveWindow       int    `proxy:"recv-window,omitempty"`
	DisableMTUDiscovery bool   `proxy:"disable-mtu-discovery,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (t *Tuic) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	return t.DialContextWithDialer(ctx, dialer.NewDialer(t.Base.DialOptions(opts...)...), metadata)
}

// DialContextWithDialer implements C.ProxyAdapter
func (t *Tuic) DialContextWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (C.Conn, error) {
	conn, err := t.client.DialContextWithDialer(ctx, metadata, dialer, t.dialWithDialer)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, t), err
}

// ListenPacketContext implements C.ProxyAdapter
func (t *Tuic) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	return t.ListenPacketWithDialer(ctx, dialer.NewDialer(t.Base.DialOptions(opts...)...), metadata)
}

// ListenPacketWithDialer implements C.ProxyAdapter
func (t *Tuic) ListenPacketWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.PacketConn, err error) {
	pc, err := t.client.ListenPacketWithDialer(ctx, metadata, dialer, t.dialWithDialer)
	if err != nil {
		return nil, err
	}
	return newPacketConn(pc, t), nil
}

// SupportWithDialer implements C.ProxyAdapter
func (t *Tuic) SupportWithDialer() bool {
	return true
}

func (t *Tuic) dial(ctx context.Context, opts ...dialer.Option) (pc net.PacketConn, addr net.Addr, err error) {
	return t.dialWithDialer(ctx, dialer.NewDialer(opts...))
}

func (t *Tuic) dialWithDialer(ctx context.Context, dialer C.Dialer) (pc net.PacketConn, addr net.Addr, err error) {
	udpAddr, err := resolveUDPAddrWithPrefer(ctx, "udp", t.addr, t.prefer)
	if err != nil {
		return nil, nil, err
	}
	addr = udpAddr
	pc, err = dialer.ListenPacket(ctx, "udp", "", udpAddr.AddrPort())
	if err != nil {
		return nil, nil, err
	}
	return
}

func NewTuic(option TuicOption) (*Tuic, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	serverName := option.Server

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
			return nil, fmt.Errorf("tuic %s load ca error: %w", addr, err)
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
		tlsConfig = tlsC.GetGlobalTLSConfig(tlsConfig)
	}

	if len(option.ALPN) > 0 {
		tlsConfig.NextProtos = option.ALPN
	} else {
		tlsConfig.NextProtos = []string{"h3"}
	}

	if option.RequestTimeout == 0 {
		option.RequestTimeout = 8000
	}

	if option.HeartbeatInterval <= 0 {
		option.HeartbeatInterval = 10000
	}

	if option.UdpRelayMode != "quic" {
		option.UdpRelayMode = "native"
	}

	if option.MaxUdpRelayPacketSize == 0 {
		option.MaxUdpRelayPacketSize = 1252
	}

	if option.MaxOpenStreams == 0 {
		option.MaxOpenStreams = 100
	}

	// ensure server's incoming stream can handle correctly, increase to 1.1x
	quicMaxOpenStreams := int64(option.MaxOpenStreams)
	quicMaxOpenStreams = quicMaxOpenStreams + int64(math.Ceil(float64(quicMaxOpenStreams)/10.0))
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     uint64(option.ReceiveWindowConn),
		MaxStreamReceiveWindow:         uint64(option.ReceiveWindowConn),
		InitialConnectionReceiveWindow: uint64(option.ReceiveWindow),
		MaxConnectionReceiveWindow:     uint64(option.ReceiveWindow),
		MaxIncomingStreams:             quicMaxOpenStreams,
		MaxIncomingUniStreams:          quicMaxOpenStreams,
		KeepAlivePeriod:                time.Duration(option.HeartbeatInterval) * time.Millisecond,
		DisablePathMTUDiscovery:        option.DisableMTUDiscovery,
		EnableDatagrams:                true,
	}
	if option.ReceiveWindowConn == 0 {
		quicConfig.InitialStreamReceiveWindow = tuic.DefaultStreamReceiveWindow / 10
		quicConfig.MaxStreamReceiveWindow = tuic.DefaultStreamReceiveWindow
	}
	if option.ReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = tuic.DefaultConnectionReceiveWindow / 10
		quicConfig.MaxConnectionReceiveWindow = tuic.DefaultConnectionReceiveWindow
	}

	if len(option.Ip) > 0 {
		addr = net.JoinHostPort(option.Ip, strconv.Itoa(option.Port))
	}
	host := option.Server
	if option.DisableSni {
		host = ""
		tlsConfig.ServerName = ""
	}
	tkn := tuic.GenTKN(option.Token)

	t := &Tuic{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Tuic,
			udp:    true,
			tfo:    option.FastOpen,
			iface:  option.Interface,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
	}

	clientMaxOpenStreams := int64(option.MaxOpenStreams)

	// to avoid tuic's "too many open streams", decrease to 0.9x
	if clientMaxOpenStreams == 100 {
		clientMaxOpenStreams = clientMaxOpenStreams - int64(math.Ceil(float64(clientMaxOpenStreams)/10.0))
	}

	if clientMaxOpenStreams < 1 {
		clientMaxOpenStreams = 1
	}
	clientOption := &tuic.ClientOption{
		TlsConfig:             tlsConfig,
		QuicConfig:            quicConfig,
		Host:                  host,
		Token:                 tkn,
		UdpRelayMode:          option.UdpRelayMode,
		CongestionController:  option.CongestionController,
		ReduceRtt:             option.ReduceRtt,
		RequestTimeout:        time.Duration(option.RequestTimeout) * time.Millisecond,
		MaxUdpRelayPacketSize: option.MaxUdpRelayPacketSize,
		FastOpen:              option.FastOpen,
		MaxOpenStreams:        clientMaxOpenStreams,
	}

	t.client = tuic.NewPoolClient(clientOption)

	return t, nil
}
