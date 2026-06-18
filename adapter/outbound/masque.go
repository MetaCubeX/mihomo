package outbound

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	wireguard "github.com/metacubex/sing-wireguard"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

type Masque struct {
	*Base
	tlsConfig   *tls.Config
	quicConfig  *quic.Config
	tunDevice   wireguard.Device
	resolver    resolver.Resolver
	uri         string
	h2Transport *http.Transport
	l4Client    *masque.L4Client

	runCtx    context.Context
	runCancel context.CancelFunc
	runMutex  sync.Mutex
	running   atomic.Bool
	runDevice atomic.Bool

	option MasqueOption
}

type MasqueOption struct {
	BasicOption
	Name           string `proxy:"name"`
	Server         string `proxy:"server"`
	Port           int    `proxy:"port"`
	PrivateKey     string `proxy:"private-key"`
	PublicKey      string `proxy:"public-key"`
	Ip             string `proxy:"ip,omitempty"`
	Ipv6           string `proxy:"ipv6,omitempty"`
	URI            string `proxy:"uri,omitempty"`
	SNI            string `proxy:"sni,omitempty"`
	MTU            int    `proxy:"mtu,omitempty"`
	UDP            bool   `proxy:"udp,omitempty"`
	SkipCertVerify bool   `proxy:"skip-cert-verify,omitempty"`
	Network        string `proxy:"network,omitempty"`

	CongestionController string `proxy:"congestion-controller,omitempty"`
	CWND                 int    `proxy:"cwnd,omitempty"`
	BBRProfile           string `proxy:"bbr-profile,omitempty"`

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
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.Masque,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
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

	l4proxy := option.Network == "h3-l4proxy"

	uri := option.URI
	if uri == "" {
		uri = masque.ConnectURI
	}
	outbound.uri = uri

	sni := option.SNI
	if sni == "" {
		sni = masque.ConnectSNI
		if l4proxy {
			sni = masque.L4ConnectSNI
		}
	}

	tlsConfig, err := masque.PrepareTlsConfig(privKey, ecPubKey, sni, option.SkipCertVerify)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare TLS config: %v\n", err)
	}
	outbound.tlsConfig = tlsConfig

	if option.Network == "h2" {
		tlsConfig.NextProtos = []string{"h2"}
		// use h2c mode to disallow the net/http fallback to http1.1 when the server returns a not h2 ALPN
		//
		// Note that this usage is only applicable to our own net/http fork.
		// The standard library also needs to mask the tls.Conn type for the conn returned by DialTLSContext
		// see: https://github.com/golang/go/issues/79293#issuecomment-4426393534
		protocols := new(http.Protocols)
		protocols.SetUnencryptedHTTP2(true)
		outbound.h2Transport = &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := outbound.dialer.DialContext(ctx, "tcp", outbound.addr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(c, tlsConfig)
				err = tlsConn.HandshakeContext(ctx)
				if err != nil {
					_ = c.Close()
					return nil, err
				}
				return tlsConn, nil
			},
			Protocols: protocols,
			HTTP2: &http.HTTP2Config{
				SendPingTimeout: 30 * time.Second,
			},
		}
	}

	outbound.quicConfig = &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: 1242,
		KeepAlivePeriod:   30 * time.Second,
	}

	outbound.option = option

	mtu := option.MTU
	if mtu == 0 {
		mtu = 1280
	}

	var has6 bool
	if l4proxy {
		outbound.l4Client = masque.NewL4Client(outbound.runCtx, outbound.dialQuic)
		if outbound.udp {
			log.Warnln("[Masque](%s) L4 proxy mode is not supported for UDP", outbound.name)
			outbound.udp = false
		}
		has6 = true // l4 proxy mode always has ipv6
	} else {
		prefixes, err := option.Prefixes()
		if err != nil {
			return nil, err
		}
		if len(prefixes) == 0 {
			return nil, errors.New("missing local address")
		}
		outbound.tunDevice, err = wireguard.NewStackDevice(prefixes, uint32(mtu))
		if err != nil {
			return nil, fmt.Errorf("create device: %w", err)
		}

		for _, address := range prefixes {
			if !address.Addr().Unmap().Is4() {
				has6 = true
				break
			}
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

func (w *Masque) dialQuic(ctx context.Context) (net.PacketConn, *quic.Conn, error) {
	pc, quicConn, err := common.DialQuic(ctx, w.addr, w.DialOptions(), w.dialer, w.tlsConfig, w.quicConfig, false)
	if err != nil {
		return nil, nil, err
	}
	common.SetCongestionController(quicConn, w.option.CongestionController, w.option.CWND, w.option.BBRProfile)
	return pc, quicConn, nil
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

	var pc net.PacketConn
	var closer io.Closer
	var ipConn masque.IpConn
	var err error
	if w.h2Transport != nil {
		closer, ipConn, err = masque.ConnectTunnelH2(ctx, w.h2Transport, w.uri)
		if err != nil {
			return err
		}
	} else {
		var quicConn *quic.Conn
		pc, quicConn, err = w.dialQuic(ctx)

		closer, ipConn, err = masque.ConnectTunnel(ctx, quicConn, w.uri)
		if err != nil {
			_ = pc.Close()
			return err
		}
	}

	w.running.Store(true)

	runCtx, runCancel := context.WithCancel(w.runCtx)
	contextutils.AfterFunc(runCtx, func() {
		w.running.Store(false)
		_ = ipConn.Close()
		_ = closer.Close()
		if pc != nil {
			_ = pc.Close()
		}
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
				if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
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
		for runCtx.Err() == nil {
			buf, err := ipConn.ReadPacket()
			if err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
					log.Errorln("[Masque](%s) connection closed while writing to IP connection: %v", w.name, err)
					return
				}
				log.Warnln("[Masque](%s) error reading from IP connection: %v, continuing...", w.name, err)
				continue
			}
			if _, err := w.tunDevice.Write([][]byte{buf}, 0); err != nil {
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
	if w.l4Client != nil {
		w.l4Client.Close()
	}
	return nil
}

func (w *Masque) dialContextL4(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	var conn net.Conn
	if !metadata.Resolved() || w.resolver != nil {
		r := resolver.DefaultResolver
		if w.resolver != nil {
			r = w.resolver
		}
		options := w.DialOptions()
		options = append(options, dialer.WithResolver(r))
		options = append(options, dialer.WithNetDialer(w.l4Client))
		conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	} else {
		conn, err = w.l4Client.DialContext(ctx, "tcp", metadata.AddrPort().String())
	}
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("conn is nil")
	}
	return NewConn(conn, w), nil
}

func (w *Masque) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if w.l4Client != nil {
		return w.dialContextL4(ctx, metadata)
	}
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
	if w.l4Client != nil {
		return nil, errors.New("masque L4 proxy mode is not supported for UDP")
	}
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
	return NewPacketConn(pc, w), nil
}

func (w *Masque) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if (!metadata.Resolved() || w.resolver != nil) && metadata.Host != "" {
		r := resolver.DefaultResolver
		if w.resolver != nil {
			r = w.resolver
		}
		ip, err := resolveIPWithResolver(ctx, metadata.Host, w.prefer, r)
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
