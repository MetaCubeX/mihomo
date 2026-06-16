package inbound

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_hysteria2"
	"github.com/metacubex/mihomo/log"
)

type Hysteria2Option struct {
	BaseOption
	Users                 map[string]string `inbound:"users,omitempty"`
	Obfs                  string            `inbound:"obfs,omitempty"`
	ObfsPassword          string            `inbound:"obfs-password,omitempty"`
	ObfsMinPacketSize     int               `inbound:"obfs-min-packet-size,omitempty"`
	ObfsMaxPacketSize     int               `inbound:"obfs-max-packet-size,omitempty"`
	Certificate           string            `inbound:"certificate"`
	PrivateKey            string            `inbound:"private-key"`
	ClientAuthType        string            `inbound:"client-auth-type,omitempty"`
	ClientAuthCert        string            `inbound:"client-auth-cert,omitempty"`
	EchKey                string            `inbound:"ech-key,omitempty"`
	MaxIdleTime           int               `inbound:"max-idle-time,omitempty"`
	ALPN                  []string          `inbound:"alpn,omitempty"`
	Up                    string            `inbound:"up,omitempty"`
	Down                  string            `inbound:"down,omitempty"`
	IgnoreClientBandwidth bool              `inbound:"ignore-client-bandwidth,omitempty"`
	Masquerade            string            `inbound:"masquerade,omitempty"`
	CWND                  int               `inbound:"cwnd,omitempty"`
	BBRProfile            string            `inbound:"bbr-profile,omitempty"`
	UdpMTU                int               `inbound:"udp-mtu,omitempty"`
	MuxOption             MuxOption         `inbound:"mux-option,omitempty"`

	RealmOpts Hysteria2RealmOption `inbound:"realm-opts,omitempty"`

	// quic-go special config
	InitialStreamReceiveWindow     uint64 `inbound:"initial-stream-receive-window,omitempty"`
	MaxStreamReceiveWindow         uint64 `inbound:"max-stream-receive-window,omitempty"`
	InitialConnectionReceiveWindow uint64 `inbound:"initial-connection-receive-window,omitempty"`
	MaxConnectionReceiveWindow     uint64 `inbound:"max-connection-receive-window,omitempty"`
}

type Hysteria2RealmOption struct {
	Enable      bool     `inbound:"enable,omitempty"`
	ServerURL   string   `inbound:"server-url,omitempty"`
	Token       string   `inbound:"token,omitempty"`
	RealmID     string   `inbound:"realm-id,omitempty"`
	STUNServers []string `inbound:"stun-servers,omitempty"`

	// for ServerURL
	SNI            string   `inbound:"sni,omitempty"`
	SkipCertVerify bool     `inbound:"skip-cert-verify,omitempty"`
	Fingerprint    string   `inbound:"fingerprint,omitempty"`
	Certificate    string   `inbound:"certificate,omitempty"`
	PrivateKey     string   `inbound:"private-key,omitempty"`
	ALPN           []string `inbound:"alpn,omitempty"`
	Proxy          string   `inbound:"proxy,omitempty"`
}

func (o Hysteria2RealmOption) Build() LC.Hysteria2RealmOption {
	return LC.Hysteria2RealmOption{
		Enable:         o.Enable,
		ServerURL:      o.ServerURL,
		Token:          o.Token,
		RealmID:        o.RealmID,
		STUNServers:    o.STUNServers,
		SNI:            o.SNI,
		SkipCertVerify: o.SkipCertVerify,
		Fingerprint:    o.Fingerprint,
		Certificate:    o.Certificate,
		PrivateKey:     o.PrivateKey,
		ALPN:           o.ALPN,
		Proxy:          o.Proxy,
	}
}

func (o Hysteria2Option) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Hysteria2 struct {
	*Base
	config *Hysteria2Option
	l      *sing_hysteria2.Listener
	ts     LC.Hysteria2Server
}

func NewHysteria2(options *Hysteria2Option) (*Hysteria2, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Hysteria2{
		Base:   base,
		config: options,
		ts: LC.Hysteria2Server{
			Enable:                true,
			Listen:                base.RawAddress(),
			Users:                 options.Users,
			Obfs:                  options.Obfs,
			ObfsPassword:          options.ObfsPassword,
			ObfsMinPacketSize:     options.ObfsMinPacketSize,
			ObfsMaxPacketSize:     options.ObfsMaxPacketSize,
			Certificate:           options.Certificate,
			PrivateKey:            options.PrivateKey,
			ClientAuthType:        options.ClientAuthType,
			ClientAuthCert:        options.ClientAuthCert,
			EchKey:                options.EchKey,
			MaxIdleTime:           options.MaxIdleTime,
			ALPN:                  options.ALPN,
			Up:                    options.Up,
			Down:                  options.Down,
			IgnoreClientBandwidth: options.IgnoreClientBandwidth,
			Masquerade:            options.Masquerade,
			CWND:                  options.CWND,
			BBRProfile:            options.BBRProfile,
			UdpMTU:                options.UdpMTU,
			MuxOption:             options.MuxOption.Build(),
			RealmOpts:             options.RealmOpts.Build(),
			// quic-go special config
			InitialStreamReceiveWindow:     options.InitialStreamReceiveWindow,
			MaxStreamReceiveWindow:         options.MaxStreamReceiveWindow,
			InitialConnectionReceiveWindow: options.InitialConnectionReceiveWindow,
			MaxConnectionReceiveWindow:     options.MaxConnectionReceiveWindow,
		},
	}, nil
}

// Config implements constant.InboundListener
func (t *Hysteria2) Config() C.InboundConfig {
	return t.config
}

// Address implements constant.InboundListener
func (t *Hysteria2) Address() string {
	var addrList []string
	if t.l != nil {
		for _, addr := range t.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (t *Hysteria2) Listen(tunnel C.Tunnel) error {
	var err error
	t.l, err = sing_hysteria2.New(t.ts, t.ListenConfig(), tunnel, t.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Hysteria2[%s] proxy listening at: %s", t.Name(), t.Address())
	return nil
}

// Close implements constant.InboundListener
func (t *Hysteria2) Close() error {
	return t.l.Close()
}

var _ C.InboundListener = (*Hysteria2)(nil)
