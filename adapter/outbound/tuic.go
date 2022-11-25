package outbound

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/quic-go"

	"github.com/Dreamacro/clash/component/dialer"
	tlsC "github.com/Dreamacro/clash/component/tls"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/tuic"
)

type Tuic struct {
	*Base
	getClient func(udp bool, opts ...dialer.Option) *tuic.Client
}

type TuicOption struct {
	BasicOption
	Name                  string   `proxy:"name"`
	Server                string   `proxy:"server"`
	Port                  int      `proxy:"port"`
	Token                 string   `proxy:"token"`
	Ip                    string   `proxy:"ip,omitempty"`
	HeartbeatInterval     int      `proxy:"heartbeat_interval,omitempty"`
	ALPN                  []string `proxy:"alpn,omitempty"`
	ReduceRtt             bool     `proxy:"reduce_rtt,omitempty"`
	RequestTimeout        int      `proxy:"request_timeout,omitempty"`
	UdpRelayMode          string   `proxy:"udp_relay_mode,omitempty"`
	CongestionController  string   `proxy:"congestion_controller,omitempty"`
	DisableSni            bool     `proxy:"disable_sni,omitempty"`
	MaxUdpRelayPacketSize int      `proxy:"max_udp_relay_packet_size,omitempty"`

	SkipCertVerify      bool   `proxy:"skip-cert-verify,omitempty"`
	Fingerprint         string `proxy:"fingerprint,omitempty"`
	CustomCA            string `proxy:"ca,omitempty"`
	CustomCAString      string `proxy:"ca_str,omitempty"`
	ReceiveWindowConn   int    `proxy:"recv_window_conn,omitempty"`
	ReceiveWindow       int    `proxy:"recv_window,omitempty"`
	DisableMTUDiscovery bool   `proxy:"disable_mtu_discovery,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (t *Tuic) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	opts = t.Base.DialOptions(opts...)
	conn, err := t.getClient(false, opts...).DialContext(ctx, metadata, func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, err := dialer.ListenPacket(ctx, "udp", "", opts...)
		if err != nil {
			return nil, nil, err
		}
		addr, err := resolveUDPAddrWithPrefer(ctx, "udp", t.addr, t.prefer)
		if err != nil {
			return nil, nil, err
		}
		return pc, addr, err
	})
	if err != nil {
		return nil, err
	}
	return NewConn(conn, t), err
}

// ListenPacketContext implements C.ProxyAdapter
func (t *Tuic) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	opts = t.Base.DialOptions(opts...)
	pc, err := t.getClient(true, opts...).ListenPacketContext(ctx, metadata, func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		pc, err := dialer.ListenPacket(ctx, "udp", "", opts...)
		if err != nil {
			return nil, nil, err
		}
		addr, err := resolveUDPAddrWithPrefer(ctx, "udp", t.addr, t.prefer)
		if err != nil {
			return nil, nil, err
		}
		return pc, addr, err
	})
	if err != nil {
		return nil, err
	}
	return newPacketConn(pc, t), nil
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
		tlsConfig = tlsC.GetGlobalFingerprintTLCConfig(tlsConfig)
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
		option.MaxUdpRelayPacketSize = 1500
	}

	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     uint64(option.ReceiveWindowConn),
		MaxStreamReceiveWindow:         uint64(option.ReceiveWindowConn),
		InitialConnectionReceiveWindow: uint64(option.ReceiveWindow),
		MaxConnectionReceiveWindow:     uint64(option.ReceiveWindow),
		KeepAlivePeriod:                time.Duration(option.HeartbeatInterval) * time.Millisecond,
		DisablePathMTUDiscovery:        option.DisableMTUDiscovery,
		EnableDatagrams:                true,
	}
	if option.ReceiveWindowConn == 0 {
		quicConfig.InitialStreamReceiveWindow = DefaultStreamReceiveWindow / 10
		quicConfig.MaxStreamReceiveWindow = DefaultStreamReceiveWindow
	}
	if option.ReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = DefaultConnectionReceiveWindow / 10
		quicConfig.MaxConnectionReceiveWindow = DefaultConnectionReceiveWindow
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
	tcpClientMap := make(map[any]*tuic.Client)
	tcpClientMapMutex := &sync.Mutex{}
	udpClientMap := make(map[any]*tuic.Client)
	udpClientMapMutex := &sync.Mutex{}
	getClient := func(udp bool, opts ...dialer.Option) *tuic.Client {
		clientMap := tcpClientMap
		clientMapMutex := tcpClientMapMutex
		if udp {
			clientMap = udpClientMap
			clientMapMutex = udpClientMapMutex
		}

		o := *dialer.ApplyOptions(opts...)

		clientMapMutex.Lock()
		defer clientMapMutex.Unlock()
		for key := range clientMap {
			client := clientMap[key]
			if client == nil {
				delete(clientMap, key) // It is safe in Golang
				continue
			}
			if key == o {
				client.LastVisited = time.Now()
				return client
			}
			if time.Now().Sub(client.LastVisited) > 30*time.Minute {
				delete(clientMap, key)
				continue
			}
		}
		client := &tuic.Client{
			TlsConfig:             tlsConfig,
			QuicConfig:            quicConfig,
			Host:                  host,
			Token:                 tkn,
			UdpRelayMode:          option.UdpRelayMode,
			CongestionController:  option.CongestionController,
			ReduceRtt:             option.ReduceRtt,
			RequestTimeout:        option.RequestTimeout,
			MaxUdpRelayPacketSize: option.MaxUdpRelayPacketSize,
			LastVisited:           time.Now(),
			UDP:                   udp,
		}
		clientMap[o] = client
		runtime.SetFinalizer(client, closeTuicClient)
		return client
	}

	return &Tuic{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Tuic,
			udp:    true,
			iface:  option.Interface,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		getClient: getClient,
	}, nil
}

func closeTuicClient(client *tuic.Client) {
	client.Close(nil)
}
