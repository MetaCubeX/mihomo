package outbound

import (
	"context"
	"fmt"
	"math"
	"net"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/tuic"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
	"github.com/metacubex/tls"
)

type Tuic struct {
	*Base
	option *TuicOption
	client *tuic.PoolClient

	tlsConfig *tls.Config
	echConfig *ech.Config
}

type TuicOption struct {
	BasicOption
	Name                  string   `proxy:"name"`
	Server                string   `proxy:"server"`
	Port                  int      `proxy:"port"`
	Token                 string   `proxy:"token,omitempty"`
	UUID                  string   `proxy:"uuid,omitempty"`
	Password              string   `proxy:"password,omitempty"`
	Ip                    string   `proxy:"ip,omitempty"`
	HeartbeatInterval     int      `proxy:"heartbeat-interval,omitempty"`
	ALPN                  []string `proxy:"alpn,omitempty"`
	ReduceRtt             bool     `proxy:"reduce-rtt,omitempty"`
	RequestTimeout        int      `proxy:"request-timeout,omitempty"`
	UdpRelayMode          string   `proxy:"udp-relay-mode,omitempty"`
	CongestionController  string   `proxy:"congestion-controller,omitempty"`
	DisableSni            bool     `proxy:"disable-sni,omitempty"`
	MaxUdpRelayPacketSize int      `proxy:"max-udp-relay-packet-size,omitempty"`

	FastOpen             bool       `proxy:"fast-open,omitempty"`
	MaxOpenStreams       int        `proxy:"max-open-streams,omitempty"`
	CWND                 int        `proxy:"cwnd,omitempty"`
	SkipCertVerify       bool       `proxy:"skip-cert-verify,omitempty"`
	Fingerprint          string     `proxy:"fingerprint,omitempty"`
	Certificate          string     `proxy:"certificate,omitempty"`
	PrivateKey           string     `proxy:"private-key,omitempty"`
	ReceiveWindowConn    int        `proxy:"recv-window-conn,omitempty"`
	ReceiveWindow        int        `proxy:"recv-window,omitempty"`
	DisableMTUDiscovery  bool       `proxy:"disable-mtu-discovery,omitempty"`
	MaxDatagramFrameSize int        `proxy:"max-datagram-frame-size,omitempty"`
	SNI                  string     `proxy:"sni,omitempty"`
	ECHOpts              ECHOptions `proxy:"ech-opts,omitempty"`

	UDPOverStream        bool `proxy:"udp-over-stream,omitempty"`
	UDPOverStreamVersion int  `proxy:"udp-over-stream-version,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (t *Tuic) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	conn, err := t.client.DialContext(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, t), err
}

// ListenPacketContext implements C.ProxyAdapter
func (t *Tuic) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	if t.option.UDPOverStream {
		uotDestination := uot.RequestDestination(uint8(t.option.UDPOverStreamVersion))
		uotMetadata := *metadata
		uotMetadata.Host = uotDestination.Fqdn
		uotMetadata.DstPort = uotDestination.Port
		c, err := t.DialContext(ctx, &uotMetadata)
		if err != nil {
			return nil, err
		}

		// tuic uos use stream-oriented udp with a special address, so we need a net.UDPAddr

		destination := M.SocksaddrFromNet(metadata.UDPAddr())
		if t.option.UDPOverStreamVersion == uot.LegacyVersion {
			return newPacketConn(uot.NewConn(c, uot.Request{Destination: destination}), t), nil
		} else {
			return newPacketConn(uot.NewLazyConn(c, uot.Request{Destination: destination}), t), nil
		}
	}
	pc, err := t.client.ListenPacket(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return newPacketConn(pc, t), nil
}

func (t *Tuic) dial(ctx context.Context) (transport *quic.Transport, addr net.Addr, err error) {
	udpAddr, err := resolveUDPAddr(ctx, "udp", t.addr, t.prefer)
	if err != nil {
		return nil, nil, err
	}
	err = t.echConfig.ClientHandle(ctx, t.tlsConfig)
	if err != nil {
		return nil, nil, err
	}
	addr = udpAddr
	var pc net.PacketConn
	pc, err = t.dialer.ListenPacket(ctx, "udp", "", udpAddr.AddrPort())
	if err != nil {
		return nil, nil, err
	}
	transport = &quic.Transport{Conn: pc}
	transport.SetCreatedConn(true) // auto close conn
	transport.SetSingleUse(true)   // auto close transport
	return
}

// ProxyInfo implements C.ProxyAdapter
func (t *Tuic) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

func NewTuic(option TuicOption) (*Tuic, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	serverName := option.Server
	if option.SNI != "" {
		serverName = option.SNI
	}

	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: option.SkipCertVerify,
			MinVersion:         tls.VersionTLS13,
		},
		Fingerprint: option.Fingerprint,
		Certificate: option.Certificate,
		PrivateKey:  option.PrivateKey,
	})
	if err != nil {
		return nil, err
	}

	if option.ALPN != nil { // structure's Decode will ensure value not nil when input has value even it was set an empty array
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

	udpRelayMode := tuic.QUIC
	if option.UdpRelayMode != "quic" {
		udpRelayMode = tuic.NATIVE
	}

	if option.MaxUdpRelayPacketSize == 0 {
		option.MaxUdpRelayPacketSize = 1252
	}

	if option.MaxOpenStreams == 0 {
		option.MaxOpenStreams = 100
	}

	if option.CWND == 0 {
		option.CWND = 32
	}

	packetOverHead := tuic.PacketOverHeadV4
	if len(option.Token) == 0 {
		packetOverHead = tuic.PacketOverHeadV5
	}

	if option.MaxDatagramFrameSize == 0 {
		option.MaxDatagramFrameSize = option.MaxUdpRelayPacketSize + packetOverHead
	}

	if option.MaxDatagramFrameSize > 1400 {
		option.MaxDatagramFrameSize = 1400
	}
	option.MaxUdpRelayPacketSize = option.MaxDatagramFrameSize - packetOverHead

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
		MaxDatagramFrameSize:           int64(option.MaxDatagramFrameSize),
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
	if option.DisableSni {
		tlsConfig.ServerName = ""
		tlsConfig.InsecureSkipVerify = true // tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config
	}

	tlsClientConfig := tlsConfig
	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}

	switch option.UDPOverStreamVersion {
	case uot.Version, uot.LegacyVersion:
	case 0:
		option.UDPOverStreamVersion = uot.LegacyVersion
	default:
		return nil, fmt.Errorf("tuic %s unknown udp over stream protocol version: %d", addr, option.UDPOverStreamVersion)
	}

	t := &Tuic{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Tuic,
			pdName: option.ProviderName,
			udp:    true,
			tfo:    option.FastOpen,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: option.IPVersion,
		},
		option:    &option,
		tlsConfig: tlsClientConfig,
		echConfig: echConfig,
	}
	t.dialer = option.NewDialer(t.DialOptions())

	clientMaxOpenStreams := int64(option.MaxOpenStreams)

	// to avoid tuic's "too many open streams", decrease to 0.9x
	if clientMaxOpenStreams == 100 {
		clientMaxOpenStreams = clientMaxOpenStreams - int64(math.Ceil(float64(clientMaxOpenStreams)/10.0))
	}

	if clientMaxOpenStreams < 1 {
		clientMaxOpenStreams = 1
	}

	if len(option.Token) > 0 {
		tkn := tuic.GenTKN(option.Token)
		clientOption := &tuic.ClientOptionV4{
			TlsConfig:             tlsClientConfig,
			QuicConfig:            quicConfig,
			Token:                 tkn,
			UdpRelayMode:          udpRelayMode,
			CongestionController:  option.CongestionController,
			ReduceRtt:             option.ReduceRtt,
			RequestTimeout:        time.Duration(option.RequestTimeout) * time.Millisecond,
			MaxUdpRelayPacketSize: option.MaxUdpRelayPacketSize,
			FastOpen:              option.FastOpen,
			MaxOpenStreams:        clientMaxOpenStreams,
			CWND:                  option.CWND,
		}

		t.client = tuic.NewPoolClientV4(clientOption, t.dial)
	} else {
		maxUdpRelayPacketSize := option.MaxUdpRelayPacketSize
		if maxUdpRelayPacketSize > tuic.MaxFragSizeV5 {
			maxUdpRelayPacketSize = tuic.MaxFragSizeV5
		}
		clientOption := &tuic.ClientOptionV5{
			TlsConfig:             tlsClientConfig,
			QuicConfig:            quicConfig,
			Uuid:                  uuid.FromStringOrNil(option.UUID),
			Password:              option.Password,
			UdpRelayMode:          udpRelayMode,
			CongestionController:  option.CongestionController,
			ReduceRtt:             option.ReduceRtt,
			MaxUdpRelayPacketSize: maxUdpRelayPacketSize,
			MaxOpenStreams:        clientMaxOpenStreams,
			CWND:                  option.CWND,
		}

		t.client = tuic.NewPoolClientV5(clientOption, t.dial)
	}

	return t, nil
}
