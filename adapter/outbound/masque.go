package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/masque"
	"github.com/metacubex/mihomo/transport/tuic/common"

	connectip "github.com/metacubex/connect-ip-go"
	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	"golang.org/x/sync/semaphore"
)

type Masque struct {
	*Base
	tlsConfig   *tls.Config
	quicConfig  *quic.Config
	resolver    resolver.Resolver
	uri         string
	h2Transport *http.Transport
	connectH3   masqueH3Connector
	connectH2   masqueH2Connector
	owner       ProxyAdapter
	routes      []connectip.IPRoute
	quicDialOpt common.DialQuicOption

	runCtx    context.Context
	runCancel context.CancelFunc
	runLock   *semaphore.Weighted
	session   *masqueSession
	prefixes  []netip.Prefix
	mtu       uint32

	option MasqueOption
}

type masqueH3Connector func(context.Context, *quic.Conn, string) (io.Closer, masque.IpConn, error)
type masqueH2Connector func(context.Context, *http.Transport, string) (io.Closer, masque.IpConn, error)

type masqueRuntime struct {
	tlsConfig              *tls.Config
	connectH3              masqueH3Connector
	connectH2              masqueH2Connector
	quicDialOption         common.DialQuicOption
	skipRouteAdvertisement bool
}

type masqueSession struct {
	tunDevice  ipStack
	ipConn     masque.IpConn
	closer     io.Closer
	packetConn net.PacketConn
	runCtx     context.Context
	runCancel  context.CancelFunc

	closing   atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

type MasqueOption struct {
	BasicOption
	Name             string            `proxy:"name"`
	Server           string            `proxy:"server"`
	Port             int               `proxy:"port"`
	Certificate      string            `proxy:"certificate,omitempty"`
	PrivateKey       string            `proxy:"private-key,omitempty"`
	PublicKey        string            `proxy:"public-key,omitempty"` // legacy Cloudflare-only option; rejected
	Ip               string            `proxy:"ip,omitempty"`
	Ipv6             string            `proxy:"ipv6,omitempty"`
	URI              string            `proxy:"uri,omitempty"`
	SNI              string            `proxy:"sni,omitempty"`
	Headers          map[string]string `proxy:"headers,omitempty"`
	Routes           []string          `proxy:"routes,omitempty"`
	MTU              int               `proxy:"mtu,omitempty"`
	UDP              bool              `proxy:"udp,omitempty"`
	HandshakeTimeout int               `proxy:"handshake-timeout,omitempty"`
	SkipCertVerify   bool              `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify   string            `proxy:"name-cert-verify,omitempty"`
	Fingerprint      string            `proxy:"fingerprint,omitempty"`
	Network          string            `proxy:"network,omitempty"`

	CongestionController string `proxy:"congestion-controller,omitempty"`
	CWND                 int    `proxy:"cwnd,omitempty"`
	BBRProfile           string `proxy:"bbr-profile,omitempty"`

	IPStack IPStackOption `proxy:"ip-stack,omitempty"`

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
	return newMasque(option, masqueRuntime{})
}

func newMasque(option MasqueOption, runtimeConfig masqueRuntime) (*Masque, error) {
	if option.Server == "" {
		return nil, errors.New("masque server is required")
	}
	if option.Port < 1 || option.Port > 65535 {
		return nil, errors.New("masque port must be between 1 and 65535")
	}
	if option.HandshakeTimeout < 0 {
		return nil, errors.New("masque handshake timeout must be non-negative")
	}
	if option.MTU < 0 {
		return nil, errors.New("masque MTU must be non-negative")
	}
	if runtimeConfig.tlsConfig == nil && option.PublicKey != "" {
		return nil, errors.New("masque public-key is a legacy WARP option; use type: warp for Cloudflare WARP")
	}
	option.Network = strings.ToLower(strings.TrimSpace(option.Network))
	if option.Network == "" {
		option.Network = "h3"
	}
	if option.Network != "h3" && option.Network != "h2" {
		return nil, fmt.Errorf("masque network must be h3 or h2, got %q", option.Network)
	}
	option.IPStack.normalize()
	if err := option.IPStack.validate(); err != nil {
		return nil, err
	}

	uri := option.URI
	if uri == "" {
		uri = "https://" + net.JoinHostPort(option.Server, strconv.Itoa(option.Port)) + masque.DefaultPath
	}
	tunnelURL, err := masque.ParseTunnelURL(uri)
	if err != nil {
		return nil, err
	}

	headers := make(http.Header, len(option.Headers))
	for name, value := range option.Headers {
		if strings.HasPrefix(name, ":") {
			return nil, fmt.Errorf("masque pseudo-header %q cannot be configured", name)
		}
		headers.Set(name, value)
	}
	if runtimeConfig.connectH3 == nil {
		runtimeConfig.connectH3 = func(ctx context.Context, conn *quic.Conn, uri string) (io.Closer, masque.IpConn, error) {
			return masque.ConnectTunnel(ctx, conn, uri, headers)
		}
	}
	if runtimeConfig.connectH2 == nil {
		runtimeConfig.connectH2 = func(ctx context.Context, transport *http.Transport, uri string) (io.Closer, masque.IpConn, error) {
			return masque.ConnectTunnelH2(ctx, transport, uri, headers)
		}
	}

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
		uri:         uri,
		connectH3:   runtimeConfig.connectH3,
		connectH2:   runtimeConfig.connectH2,
		quicDialOpt: runtimeConfig.quicDialOption,
		runLock:     semaphore.NewWeighted(1),
		option:      option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	outbound.runCtx, outbound.runCancel = context.WithCancel(context.Background())

	tlsConfig := runtimeConfig.tlsConfig
	if tlsConfig == nil {
		serverName := option.SNI
		if serverName == "" {
			serverName = tunnelURL.Hostname()
		}
		tlsConfig, err = ca.GetTLSConfig(ca.Option{
			TLSConfig: &tls.Config{
				ServerName:         serverName,
				InsecureSkipVerify: option.SkipCertVerify,
			},
			Fingerprint:    option.Fingerprint,
			NameCertVerify: option.NameCertVerify,
			Certificate:    option.Certificate,
			PrivateKey:     option.PrivateKey,
		})
		if err != nil {
			return nil, fmt.Errorf("masque TLS configuration: %w", err)
		}
	}
	tlsConfig = tlsConfig.Clone()
	if option.Network == "h2" {
		tlsConfig.NextProtos = []string{"h2"}
	} else {
		tlsConfig.NextProtos = []string{http3.NextProtoH3}
	}
	outbound.tlsConfig = tlsConfig

	if option.Network == "h2" {
		protocols := new(http.Protocols)
		// The connection returned below has already completed TLS. This mode
		// selects HTTP/2 without allowing an HTTP/1.1 fallback.
		protocols.SetUnencryptedHTTP2(true)
		outbound.h2Transport = &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := outbound.dialer.DialContext(ctx, "tcp", outbound.addr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(conn, tlsConfig)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					_ = conn.Close()
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
		EnableDatagrams: true,
		KeepAlivePeriod: 30 * time.Second,
	}

	prefixes, err := option.Prefixes()
	if err != nil {
		return nil, err
	}
	mtu := option.MTU
	if mtu == 0 {
		mtu = 1280
	}
	outbound.prefixes = prefixes
	outbound.mtu = uint32(mtu)
	if !runtimeConfig.skipRouteAdvertisement {
		outbound.routes, err = masqueClientRoutes(prefixes, option.Routes)
		if err != nil {
			return nil, err
		}
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
		outbound.resolver = dns.NewResolver(dns.Config{Main: nss, IPv6: has6})
	}
	return outbound, nil
}

func masqueClientRoutes(prefixes []netip.Prefix, configured []string) ([]connectip.IPRoute, error) {
	if len(configured) == 0 {
		routes := make([]connectip.IPRoute, 0, len(prefixes))
		for _, prefix := range prefixes {
			address := prefix.Addr()
			routes = append(routes, connectip.IPRoute{StartIP: address, EndIP: address})
		}
		return normalizeMasqueRoutes(routes)
	}
	routes := make([]connectip.IPRoute, 0, len(configured))
	for _, value := range configured {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("masque route %q: %w", value, err)
		}
		start := prefix.Masked().Addr()
		bytes := start.AsSlice()
		for bit := prefix.Bits(); bit < start.BitLen(); bit++ {
			bytes[bit/8] |= 1 << (7 - bit%8)
		}
		end, ok := netip.AddrFromSlice(bytes)
		if !ok {
			return nil, fmt.Errorf("masque route %q has an invalid address", value)
		}
		routes = append(routes, connectip.IPRoute{StartIP: start, EndIP: end})
	}
	return normalizeMasqueRoutes(routes)
}

func normalizeMasqueRoutes(routes []connectip.IPRoute) ([]connectip.IPRoute, error) {
	sort.Slice(routes, func(i, j int) bool {
		left, right := routes[i], routes[j]
		if left.StartIP.Is4() != right.StartIP.Is4() {
			return left.StartIP.Is4()
		}
		if left.IPProtocol != right.IPProtocol {
			return left.IPProtocol < right.IPProtocol
		}
		return left.StartIP.Compare(right.StartIP) < 0
	})
	for index := 1; index < len(routes); index++ {
		previous, current := routes[index-1], routes[index]
		if previous.StartIP.Is4() == current.StartIP.Is4() &&
			previous.IPProtocol == current.IPProtocol &&
			current.StartIP.Compare(previous.EndIP) <= 0 {
			return nil, fmt.Errorf(
				"masque routes %s-%s and %s-%s overlap",
				previous.StartIP, previous.EndIP, current.StartIP, current.EndIP,
			)
		}
	}
	return routes, nil
}

func (w *Masque) dialQuic(ctx context.Context) (net.PacketConn, *quic.Conn, error) {
	pc, quicConn, err := common.DialQuic(ctx, w.addr, w.DialOptions(), w.dialer, w.tlsConfig, w.quicConfig, w.quicDialOpt)
	if err != nil {
		return nil, nil, err
	}
	common.SetCongestionController(quicConn, w.option.CongestionController, w.option.CWND, w.option.BBRProfile)
	return pc, quicConn, nil
}

func (w *Masque) run(ctx context.Context) (ipStack, error) {
	runCtx, cancel := context.WithCancel(ctx)
	stop := contextutils.AfterFunc(w.runCtx, cancel)
	defer func() {
		stop()
		cancel()
	}()

	if err := w.runLock.Acquire(runCtx, 1); err != nil {
		return nil, err
	}
	releaseRunLock := true
	defer func() {
		if releaseRunLock {
			w.runLock.Release(1)
		}
	}()

	if w.session != nil && !w.session.closing.Load() {
		return w.session.tunDevice, nil
	}

	if w.runCtx.Err() != nil {
		return nil, w.runCtx.Err()
	}

	if w.option.HandshakeTimeout > 0 {
		type runResult struct {
			tunDevice ipStack
			err       error
		}
		resultCh := make(chan runResult, 1)
		releaseRunLock = false
		go func() {
			defer w.runLock.Release(1)

			handshakeTimeout := time.Duration(w.option.HandshakeTimeout) * time.Second
			handshakeCtx, handshakeCancel := context.WithTimeout(w.runCtx, handshakeTimeout)
			defer handshakeCancel()

			tunDevice, err := w.startLocked(handshakeCtx)
			resultCh <- runResult{tunDevice: tunDevice, err: err}
		}()

		select {
		case result := <-resultCh:
			return result.tunDevice, result.err
		case <-runCtx.Done():
			return nil, runCtx.Err()
		}
	}

	return w.startLocked(runCtx)
}

func (w *Masque) startLocked(ctx context.Context) (ipStack, error) {
	var pc net.PacketConn
	var closer io.Closer
	var ipConn masque.IpConn
	var err error
	if w.h2Transport != nil {
		closer, ipConn, err = w.connectH2(ctx, w.h2Transport, w.uri)
		if err != nil {
			return nil, err
		}
	} else {
		var quicConn *quic.Conn
		pc, quicConn, err = w.dialQuic(ctx)
		if err != nil {
			return nil, err
		}

		closer, ipConn, err = w.connectH3(ctx, quicConn, w.uri)
		if err != nil {
			_ = pc.Close()
			return nil, err
		}
	}
	closeTunnel := func() {
		_ = ipConn.Close()
		_ = closer.Close()
		if pc != nil {
			_ = pc.Close()
		}
	}
	if len(w.routes) > 0 {
		standardConn, ok := ipConn.(interface {
			AdvertiseRoute(context.Context, []connectip.IPRoute) error
		})
		if !ok {
			closeTunnel()
			return nil, errors.New("masque: CONNECT-IP implementation cannot advertise RFC 9484 routes")
		}
		if err := standardConn.AdvertiseRoute(ctx, w.routes); err != nil {
			closeTunnel()
			return nil, fmt.Errorf("masque: advertise client routes: %w", err)
		}
	}

	tunDevice, err := newIPStack(w.option.IPStack, w.prefixes, w.mtu)
	if err != nil {
		closeTunnel()
		return nil, fmt.Errorf("create MASQUE IP stack: %w", err)
	}
	if err := tunDevice.Start(); err != nil {
		_ = tunDevice.Close()
		closeTunnel()
		return nil, err
	}
	runCtx, runCancel := context.WithCancel(w.runCtx)
	session := &masqueSession{
		tunDevice:  tunDevice,
		ipConn:     ipConn,
		closer:     closer,
		packetConn: pc,
		runCtx:     runCtx,
		runCancel:  runCancel,
	}
	w.session = session
	w.startPacketLoops(session)
	return tunDevice, nil
}

func (w *Masque) startPacketLoops(session *masqueSession) {
	stop := func() { _ = w.stopSession(session) }
	contextutils.AfterFunc(session.runCtx, stop)

	go func() {
		defer stop()
		buf := pool.Get(pool.UDPBufferSize)
		defer pool.Put(buf)
		bufs := [][]byte{buf}
		sizes := []int{0}
		for session.runCtx.Err() == nil {
			_, err := session.tunDevice.Read(bufs, sizes, 0)
			if err != nil {
				if session.runCtx.Err() == nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
					log.Errorln("[Masque](%s) error reading from stack device: %v", w.name, err)
				}
				return
			}
			icmp, err := session.ipConn.WritePacket(buf[:sizes[0]])
			if err != nil {
				if session.runCtx.Err() == nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
					log.Warnln("[Masque](%s) error writing packet to CONNECT-IP link: %v", w.name, err)
				}
				return
			}

			if len(icmp) > 0 {
				if _, err := session.tunDevice.Write([][]byte{icmp}, 0); err != nil {
					if session.runCtx.Err() == nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
						log.Warnln("[Masque](%s) error writing ICMP to stack device: %v", w.name, err)
					}
					return
				}
			}
		}
	}()

	go func() {
		defer stop()
		for session.runCtx.Err() == nil {
			buf, err := session.ipConn.ReadPacket()
			if err != nil {
				if session.runCtx.Err() == nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
					log.Warnln("[Masque](%s) error reading packet from CONNECT-IP link: %v", w.name, err)
				}
				return
			}
			if _, err := session.tunDevice.Write([][]byte{buf}, 0); err != nil {
				if session.runCtx.Err() == nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
					log.Errorln("[Masque](%s) error writing to stack device: %v", w.name, err)
				}
				return
			}
		}
	}()
}

func (w *Masque) stopSession(session *masqueSession) error {
	session.closing.Store(true)
	session.closeOnce.Do(func() {
		session.runCancel()
		_ = w.runLock.Acquire(context.Background(), 1)
		defer w.runLock.Release(1)
		if w.session == session {
			w.session = nil
		}

		recordError := func(err error) {
			if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
				return
			}
			if session.closeErr == nil {
				session.closeErr = err
			}
		}
		recordError(session.ipConn.Close())
		recordError(session.closer.Close())
		if session.packetConn != nil {
			recordError(session.packetConn.Close())
		}
		recordError(session.tunDevice.Close())
	})
	return session.closeErr
}

// Close implements C.ProxyAdapter
func (w *Masque) Close() error {
	w.runCancel()
	_ = w.runLock.Acquire(context.Background(), 1)
	session := w.session
	w.session = nil
	w.runLock.Release(1)
	if w.h2Transport != nil {
		w.h2Transport.CloseIdleConnections()
	}
	if session != nil {
		return w.stopSession(session)
	}
	return nil
}

func (w *Masque) connectionOwner() ProxyAdapter {
	if w.owner != nil {
		return w.owner
	}
	return w
}

func (w *Masque) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	var conn net.Conn
	tunDevice, err := w.run(ctx)
	if err != nil {
		return nil, err
	}
	if !metadata.Resolved() || w.resolver != nil {
		r := resolver.DefaultResolver
		if w.resolver != nil {
			r = w.resolver
		}
		options := w.DialOptions()
		options = append(options, dialer.WithResolver(r))
		options = append(options, dialer.WithNetDialer(ipStackNetDialer{stack: tunDevice}))
		conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	} else {
		conn, err = tunDevice.DialTCP(ctx, "tcp", netip.AddrPort{}, metadata.AddrPort())
	}
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("conn is nil")
	}
	return NewConn(conn, w.connectionOwner()), nil
}

func (w *Masque) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	var pc net.PacketConn
	tunDevice, err := w.run(ctx)
	if err != nil {
		return nil, err
	}
	if err = w.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	// The ipStack contract guarantees that a generic UDP wildcard supports both address families.
	pc, err = tunDevice.ListenUDP(ctx, "udp", netip.AddrPort{})
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, errors.New("packetConn is nil")
	}
	return NewPacketConn(pc, w.connectionOwner()), nil
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
