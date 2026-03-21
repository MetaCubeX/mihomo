package outbound

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/masque"
	"github.com/metacubex/mihomo/transport/tuic/common"

	connectip "github.com/metacubex/connect-ip-go"
	"github.com/metacubex/quic-go"
	wireguard "github.com/metacubex/sing-wireguard"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

type Masque struct {
	*Base
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	tunDevice  wireguard.Device
	resolver   resolver.Resolver
	uri        string

	runCtx    context.Context
	runCancel context.CancelFunc
	runMutex  sync.Mutex
	running   atomic.Bool
	runDevice atomic.Bool

	option MasqueOption
}

type MasqueOption struct {
	BasicOption
	Name       string `proxy:"name"`
	Server     string `proxy:"server"`
	Port       int    `proxy:"port"`
	PrivateKey string `proxy:"private-key"`
	PublicKey  string `proxy:"public-key"`
	Ip         string `proxy:"ip,omitempty"`
	Ipv6       string `proxy:"ipv6,omitempty"`
	URI        string `proxy:"uri,omitempty"`
	SNI        string `proxy:"sni,omitempty"`
	MTU        int    `proxy:"mtu,omitempty"`
	UDP        bool   `proxy:"udp,omitempty"`

	CongestionController string `proxy:"congestion-controller,omitempty"`
	CWND                 int    `proxy:"cwnd,omitempty"`

	RemoteDnsResolve bool     `proxy:"remote-dns-resolve,omitempty"`
	Dns              []string `proxy:"dns,omitempty"`
}

func (option MasqueOption) Prefixes() ([]netip.Prefix, error) {
	localPrefixes := make([]netip.Prefix, 0, 2)
	if len(option.Ip) > 0 {
		if !strings.Contains(option.Ip, "/") {
			option.Ip = option.Ip + "/32"
		}
		if prefix, err := netip.ParsePrefix(option.Ip); err == nil {
			localPrefixes = append(localPrefixes, prefix)
		} else {
			return nil, fmt.Errorf("ip address parse error: %w", err)
		}
	}
	if len(option.Ipv6) > 0 {
		if !strings.Contains(option.Ipv6, "/") {
			option.Ipv6 = option.Ipv6 + "/128"
		}
		if prefix, err := netip.ParsePrefix(option.Ipv6); err == nil {
			localPrefixes = append(localPrefixes, prefix)
		} else {
			return nil, fmt.Errorf("ipv6 address parse error: %w", err)
		}
	}
	if len(localPrefixes) == 0 {
		return nil, errors.New("missing local address")
	}
	return localPrefixes, nil
}

func NewMasque(option MasqueOption) (*Masque, error) {
	outbound := &Masque{
		Base: &Base{
			name:   option.Name,
			addr:   net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:     C.Masque,
			pdName: option.ProviderName,
			udp:    option.UDP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: option.IPVersion,
		},
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())

	ctx, cancel := context.WithCancel(context.Background())
	outbound.runCtx = ctx
	outbound.runCancel = cancel

	privKeyB64, err := base64.StdEncoding.DecodeString(option.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}
	privKey, err := x509.ParseECPrivateKey(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	endpointPubKeyB64, err := base64.StdEncoding.DecodeString(option.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %v", err)
	}
	pubKey, err := x509.ParsePKIXPublicKey(endpointPubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to assert public key as ECDSA")
	}

	uri := option.URI
	if uri == "" {
		uri = masque.ConnectURI
	}
	outbound.uri = uri

	sni := option.SNI
	if sni == "" {
		sni = masque.ConnectSNI
	}

	tlsConfig, err := masque.PrepareTlsConfig(privKey, ecPubKey, sni)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare TLS config: %v\n", err)
	}
	outbound.tlsConfig = tlsConfig

	outbound.quicConfig = &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: 1242,
		KeepAlivePeriod:   30 * time.Second,
	}

	prefixes, err := option.Prefixes()
	if err != nil {
		return nil, err
	}

	outbound.option = option

	mtu := option.MTU
	if mtu == 0 {
		mtu = 1280
	}
	if len(prefixes) == 0 {
		return nil, errors.New("missing local address")
	}
	outbound.tunDevice, err = wireguard.NewStackDevice(prefixes, uint32(mtu))
	if err != nil {
		return nil, fmt.Errorf("create device: %w", err)
	}

	var has6 bool
	for _, address := range prefixes {
		if !address.Addr().Unmap().Is4() {
			has6 = true
			break
		}
	}

	if option.RemoteDnsResolve && len(option.Dns) > 0 {
		nss, err := dns.ParseNameServer(option.Dns)
		if err != nil {
			return nil, err
		}
		for i := range nss {
			nss[i].ProxyAdapter = outbound
		}
		outbound.resolver = dns.NewResolver(dns.Config{
			Main: nss,
			IPv6: has6,
		})
	}

	return outbound, nil
}

func (w *Masque) run(ctx context.Context) error {
	if w.running.Load() {
		return nil
	}
	w.runMutex.Lock()
	defer w.runMutex.Unlock()
	// double-check like sync.Once
	if w.running.Load() {
		return nil
	}

	if w.runCtx.Err() != nil {
		return w.runCtx.Err()
	}

	if !w.runDevice.Load() {
		err := w.tunDevice.Start()
		if err != nil {
			return err
		}
		w.runDevice.Store(true)
	}

	udpAddr, err := resolveUDPAddr(ctx, "udp", w.addr, w.prefer)
	if err != nil {
		return err
	}

	pc, err := w.dialer.ListenPacket(ctx, "udp", "", udpAddr.AddrPort())
	if err != nil {
		return err
	}

	quicConn, err := quic.Dial(ctx, pc, udpAddr, w.tlsConfig, w.quicConfig)
	if err != nil {
		return err
	}

	common.SetCongestionController(quicConn, w.option.CongestionController, w.option.CWND)

	tr, ipConn, err := masque.ConnectTunnel(ctx, quicConn, w.uri)
	if err != nil {
		_ = pc.Close()
		return err
	}

	w.running.Store(true)

	runCtx, runCancel := context.WithCancel(w.runCtx)
	contextutils.AfterFunc(runCtx, func() {
		w.running.Store(false)
		_ = ipConn.Close()
		_ = tr.Close()
		_ = pc.Close()
	})

	go func() {
		defer runCancel()
		buf := pool.Get(pool.UDPBufferSize)
		defer pool.Put(buf)
		bufs := [][]byte{buf}
		sizes := []int{0}
		for runCtx.Err() == nil {
			_, err := w.tunDevice.Read(bufs, sizes, 0)
			if err != nil {
				log.Errorln("[Masque](%s) error reading from TUN device: %v", w.name, err)
				return
			}
			icmp, err := ipConn.WritePacket(buf[:sizes[0]])
			if err != nil {
				if errors.As(err, new(*connectip.CloseError)) {
					log.Errorln("[Masque](%s) connection closed while writing to IP connection: %v", w.name, err)
					return
				}
				log.Warnln("[Masque](%s) error writing to IP connection: %v, continuing...", w.name, err)
				continue
			}

			if len(icmp) > 0 {
				if _, err := w.tunDevice.Write([][]byte{icmp}, 0); err != nil {
					log.Warnln("[Masque](%s) error writing ICMP to TUN device: %v, continuing...", w.name, err)
				}
			}
		}
	}()

	go func() {
		defer runCancel()
		buf := pool.Get(pool.UDPBufferSize)
		defer pool.Put(buf)
		for runCtx.Err() == nil {
			n, err := ipConn.ReadPacket(buf)
			if err != nil {
				if errors.As(err, new(*connectip.CloseError)) {
					log.Errorln("[Masque](%s) connection closed while writing to IP connection: %v", w.name, err)
					return
				}
				log.Warnln("[Masque](%s) error reading from IP connection: %v, continuing...", w.name, err)
				continue
			}
			if _, err := w.tunDevice.Write([][]byte{buf[:n]}, 0); err != nil {
				log.Errorln("[Masque](%s) error writing to TUN device: %v", w.name, err)
				return
			}
		}
	}()

	return nil
}

// Close implements C.ProxyAdapter
func (w *Masque) Close() error {
	w.runCancel()
	if w.tunDevice != nil {
		w.tunDevice.Close()
	}
	return nil
}

func (w *Masque) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	var conn net.Conn
	if err = w.run(ctx); err != nil {
		return nil, err
	}
	if !metadata.Resolved() || w.resolver != nil {
		r := resolver.DefaultResolver
		if w.resolver != nil {
			r = w.resolver
		}
		options := w.DialOptions()
		options = append(options, dialer.WithResolver(r))
		options = append(options, dialer.WithNetDialer(wgNetDialer{tunDevice: w.tunDevice}))
		conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	} else {
		conn, err = w.tunDevice.DialContext(ctx, "tcp", M.SocksaddrFrom(metadata.DstIP, metadata.DstPort).Unwrap())
	}
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("conn is nil")
	}
	return NewConn(conn, w), nil
}

func (w *Masque) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	var pc net.PacketConn
	if err = w.run(ctx); err != nil {
		return nil, err
	}
	if err = w.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc, err = w.tunDevice.ListenPacket(ctx, M.SocksaddrFrom(metadata.DstIP, metadata.DstPort).Unwrap())
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, errors.New("packetConn is nil")
	}
	return newPacketConn(pc, w), nil
}

func (w *Masque) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if (!metadata.Resolved() || w.resolver != nil) && metadata.Host != "" {
		r := resolver.DefaultResolver
		if w.resolver != nil {
			r = w.resolver
		}
		ip, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, r)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

// ProxyInfo implements C.ProxyAdapter
func (w *Masque) ProxyInfo() C.ProxyInfo {
	info := w.Base.ProxyInfo()
	info.DialerProxy = w.option.DialerProxy
	return info
}

// IsL3Protocol implements C.ProxyAdapter
func (w *Masque) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}
