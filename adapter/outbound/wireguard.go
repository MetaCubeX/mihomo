package outbound

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/common/atomic"
	CN "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/slowdown"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"

	wireguard "github.com/metacubex/sing-wireguard"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/wireguard-go/device"
)

type WireGuard struct {
	*Base
	bind      *wireguard.ClientBind
	device    *device.Device
	tunDevice wireguard.Device
	dialer    proxydialer.SingDialer
	resolver  *dns.Resolver
	refP      *refProxyAdapter

	initOk        atomic.Bool
	initMutex     sync.Mutex
	initErr       error
	option        WireGuardOption
	connectAddr   M.Socksaddr
	localPrefixes []netip.Prefix

	closeCh chan struct{} // for test
}

type WireGuardOption struct {
	BasicOption
	WireGuardPeerOption
	Name                string `proxy:"name"`
	Ip                  string `proxy:"ip,omitempty"`
	Ipv6                string `proxy:"ipv6,omitempty"`
	PrivateKey          string `proxy:"private-key"`
	Workers             int    `proxy:"workers,omitempty"`
	MTU                 int    `proxy:"mtu,omitempty"`
	UDP                 bool   `proxy:"udp,omitempty"`
	PersistentKeepalive int    `proxy:"persistent-keepalive,omitempty"`

	Peers []WireGuardPeerOption `proxy:"peers,omitempty"`

	RemoteDnsResolve bool     `proxy:"remote-dns-resolve,omitempty"`
	Dns              []string `proxy:"dns,omitempty"`
}

type WireGuardPeerOption struct {
	Server       string   `proxy:"server"`
	Port         int      `proxy:"port"`
	PublicKey    string   `proxy:"public-key,omitempty"`
	PreSharedKey string   `proxy:"pre-shared-key,omitempty"`
	Reserved     []uint8  `proxy:"reserved,omitempty"`
	AllowedIPs   []string `proxy:"allowed-ips,omitempty"`
}

type wgSingErrorHandler struct {
	name string
}

var _ E.Handler = (*wgSingErrorHandler)(nil)

func (w wgSingErrorHandler) NewError(ctx context.Context, err error) {
	if E.IsClosedOrCanceled(err) {
		log.SingLogger.Debug(fmt.Sprintf("[WG](%s) connection closed: %s", w.name, err))
		return
	}
	log.SingLogger.Error(fmt.Sprintf("[WG](%s) %s", w.name, err))
}

type wgNetDialer struct {
	tunDevice wireguard.Device
}

var _ dialer.NetDialer = (*wgNetDialer)(nil)

func (d wgNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.tunDevice.DialContext(ctx, network, M.ParseSocksaddr(address).Unwrap())
}

func (option WireGuardPeerOption) Addr() M.Socksaddr {
	return M.ParseSocksaddrHostPort(option.Server, uint16(option.Port))
}

func (option WireGuardOption) Prefixes() ([]netip.Prefix, error) {
	localPrefixes := make([]netip.Prefix, 0, 2)
	if len(option.Ip) > 0 {
		if !strings.Contains(option.Ip, "/") {
			option.Ip = option.Ip + "/32"
		}
		if prefix, err := netip.ParsePrefix(option.Ip); err == nil {
			localPrefixes = append(localPrefixes, prefix)
		} else {
			return nil, E.Cause(err, "ip address parse error")
		}
	}
	if len(option.Ipv6) > 0 {
		if !strings.Contains(option.Ipv6, "/") {
			option.Ipv6 = option.Ipv6 + "/128"
		}
		if prefix, err := netip.ParsePrefix(option.Ipv6); err == nil {
			localPrefixes = append(localPrefixes, prefix)
		} else {
			return nil, E.Cause(err, "ipv6 address parse error")
		}
	}
	if len(localPrefixes) == 0 {
		return nil, E.New("missing local address")
	}
	return localPrefixes, nil
}

func NewWireGuard(option WireGuardOption) (*WireGuard, error) {
	outbound := &WireGuard{
		Base: &Base{
			name:   option.Name,
			addr:   net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:     C.WireGuard,
			udp:    option.UDP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		dialer: proxydialer.NewSlowDownSingDialer(proxydialer.NewByNameSingDialer(option.DialerProxy, dialer.NewDialer()), slowdown.New()),
	}
	runtime.SetFinalizer(outbound, closeWireGuard)

	var reserved [3]uint8
	if len(option.Reserved) > 0 {
		if len(option.Reserved) != 3 {
			return nil, E.New("invalid reserved value, required 3 bytes, got ", len(option.Reserved))
		}
		copy(reserved[:], option.Reserved)
	}
	var isConnect bool
	if len(option.Peers) < 2 {
		isConnect = true
		if len(option.Peers) == 1 {
			outbound.connectAddr = option.Peers[0].Addr()
		} else {
			outbound.connectAddr = option.Addr()
		}
	}
	outbound.bind = wireguard.NewClientBind(context.Background(), wgSingErrorHandler{outbound.Name()}, outbound.dialer, isConnect, outbound.connectAddr.AddrPort(), reserved)

	var err error
	outbound.localPrefixes, err = option.Prefixes()
	if err != nil {
		return nil, err
	}

	{
		bytes, err := base64.StdEncoding.DecodeString(option.PrivateKey)
		if err != nil {
			return nil, E.Cause(err, "decode private key")
		}
		option.PrivateKey = hex.EncodeToString(bytes)
	}

	if len(option.Peers) > 0 {
		for i := range option.Peers {
			peer := &option.Peers[i] // we need modify option here
			bytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
			if err != nil {
				return nil, E.Cause(err, "decode public key for peer ", i)
			}
			peer.PublicKey = hex.EncodeToString(bytes)

			if peer.PreSharedKey != "" {
				bytes, err := base64.StdEncoding.DecodeString(peer.PreSharedKey)
				if err != nil {
					return nil, E.Cause(err, "decode pre shared key for peer ", i)
				}
				peer.PreSharedKey = hex.EncodeToString(bytes)
			}

			if len(peer.AllowedIPs) == 0 {
				return nil, E.New("missing allowed_ips for peer ", i)
			}

			if len(peer.Reserved) > 0 {
				if len(peer.Reserved) != 3 {
					return nil, E.New("invalid reserved value for peer ", i, ", required 3 bytes, got ", len(peer.Reserved))
				}
			}
		}
	} else {
		{
			bytes, err := base64.StdEncoding.DecodeString(option.PublicKey)
			if err != nil {
				return nil, E.Cause(err, "decode peer public key")
			}
			option.PublicKey = hex.EncodeToString(bytes)
		}
		if option.PreSharedKey != "" {
			bytes, err := base64.StdEncoding.DecodeString(option.PreSharedKey)
			if err != nil {
				return nil, E.Cause(err, "decode pre shared key")
			}
			option.PreSharedKey = hex.EncodeToString(bytes)
		}
	}
	outbound.option = option

	mtu := option.MTU
	if mtu == 0 {
		mtu = 1408
	}
	if len(outbound.localPrefixes) == 0 {
		return nil, E.New("missing local address")
	}
	outbound.tunDevice, err = wireguard.NewStackDevice(outbound.localPrefixes, uint32(mtu))
	if err != nil {
		return nil, E.Cause(err, "create WireGuard device")
	}
	outbound.device = device.NewDevice(context.Background(), outbound.tunDevice, outbound.bind, &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			log.SingLogger.Debug(fmt.Sprintf("[WG](%s) %s", option.Name, fmt.Sprintf(format, args...)))
		},
		Errorf: func(format string, args ...interface{}) {
			log.SingLogger.Error(fmt.Sprintf("[WG](%s) %s", option.Name, fmt.Sprintf(format, args...)))
		},
	}, option.Workers)

	var has6 bool
	for _, address := range outbound.localPrefixes {
		if !address.Addr().Unmap().Is4() {
			has6 = true
			break
		}
	}

	refP := &refProxyAdapter{}
	outbound.refP = refP
	if option.RemoteDnsResolve && len(option.Dns) > 0 {
		nss, err := dns.ParseNameServer(option.Dns)
		if err != nil {
			return nil, err
		}
		for i := range nss {
			nss[i].ProxyAdapter = refP
		}
		outbound.resolver = dns.NewResolver(dns.Config{
			Main: nss,
			IPv6: has6,
		})
	}

	return outbound, nil
}

func (w *WireGuard) resolve(ctx context.Context, address M.Socksaddr) (netip.AddrPort, error) {
	if address.Addr.IsValid() {
		return address.AddrPort(), nil
	}
	udpAddr, err := resolveUDPAddrWithPrefer(ctx, "udp", address.String(), w.prefer)
	if err != nil {
		return netip.AddrPort{}, err
	}
	// net.ResolveUDPAddr maybe return 4in6 address, so unmap at here
	addrPort := udpAddr.AddrPort()
	return netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()), nil
}

func (w *WireGuard) init(ctx context.Context) error {
	if w.initOk.Load() {
		return nil
	}
	w.initMutex.Lock()
	defer w.initMutex.Unlock()
	// double check like sync.Once
	if w.initOk.Load() {
		return nil
	}
	if w.initErr != nil {
		return w.initErr
	}

	w.bind.ResetReservedForEndpoint()
	ipcConf := "private_key=" + w.option.PrivateKey
	if len(w.option.Peers) > 0 {
		for i, peer := range w.option.Peers {
			destination, err := w.resolve(ctx, peer.Addr())
			if err != nil {
				// !!! do not set initErr here !!!
				// let us can retry domain resolve in next time
				return E.Cause(err, "resolve endpoint domain for peer ", i)
			}
			ipcConf += "\npublic_key=" + peer.PublicKey
			ipcConf += "\nendpoint=" + destination.String()
			if peer.PreSharedKey != "" {
				ipcConf += "\npreshared_key=" + peer.PreSharedKey
			}
			for _, allowedIP := range peer.AllowedIPs {
				ipcConf += "\nallowed_ip=" + allowedIP
			}
			if len(peer.Reserved) > 0 {
				var reserved [3]uint8
				copy(reserved[:], w.option.Reserved)
				w.bind.SetReservedForEndpoint(destination, reserved)
			}
		}
	} else {
		ipcConf += "\npublic_key=" + w.option.PublicKey
		destination, err := w.resolve(ctx, w.connectAddr)
		if err != nil {
			// !!! do not set initErr here !!!
			// let us can retry domain resolve in next time
			return E.Cause(err, "resolve endpoint domain")
		}
		w.bind.SetConnectAddr(destination)
		ipcConf += "\nendpoint=" + destination.String()
		if w.option.PreSharedKey != "" {
			ipcConf += "\npreshared_key=" + w.option.PreSharedKey
		}
		var has4, has6 bool
		for _, address := range w.localPrefixes {
			if address.Addr().Is4() {
				has4 = true
			} else {
				has6 = true
			}
		}
		if has4 {
			ipcConf += "\nallowed_ip=0.0.0.0/0"
		}
		if has6 {
			ipcConf += "\nallowed_ip=::/0"
		}
	}

	if w.option.PersistentKeepalive != 0 {
		ipcConf += fmt.Sprintf("\npersistent_keepalive_interval=%d", w.option.PersistentKeepalive)
	}

	if debug.Enabled {
		log.SingLogger.Trace(fmt.Sprintf("[WG](%s) created wireguard ipc conf: \n %s", w.option.Name, ipcConf))
	}
	err := w.device.IpcSet(ipcConf)
	if err != nil {
		w.initErr = E.Cause(err, "setup wireguard")
		return w.initErr
	}

	err = w.tunDevice.Start()
	if err != nil {
		w.initErr = err
		return w.initErr
	}

	w.initOk.Store(true)
	return nil
}

func closeWireGuard(w *WireGuard) {
	if w.device != nil {
		w.device.Close()
	}
	_ = common.Close(w.tunDevice)
	if w.closeCh != nil {
		close(w.closeCh)
	}
}

func (w *WireGuard) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	options := w.Base.DialOptions(opts...)
	w.dialer.SetDialer(dialer.NewDialer(options...))
	var conn net.Conn
	if err = w.init(ctx); err != nil {
		return nil, err
	}
	if !metadata.Resolved() || w.resolver != nil {
		r := resolver.DefaultResolver
		if w.resolver != nil {
			w.refP.SetProxyAdapter(w)
			defer w.refP.ClearProxyAdapter()
			r = w.resolver
		}
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
		return nil, E.New("conn is nil")
	}
	return NewConn(CN.NewRefConn(conn, w), w), nil
}

func (w *WireGuard) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	options := w.Base.DialOptions(opts...)
	w.dialer.SetDialer(dialer.NewDialer(options...))
	var pc net.PacketConn
	if err = w.init(ctx); err != nil {
		return nil, err
	}
	if (!metadata.Resolved() || w.resolver != nil) && metadata.Host != "" {
		r := resolver.DefaultResolver
		if w.resolver != nil {
			w.refP.SetProxyAdapter(w)
			defer w.refP.ClearProxyAdapter()
			r = w.resolver
		}
		ip, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, r)
		if err != nil {
			return nil, errors.New("can't resolve ip")
		}
		metadata.DstIP = ip
	}
	pc, err = w.tunDevice.ListenPacket(ctx, M.SocksaddrFrom(metadata.DstIP, metadata.DstPort).Unwrap())
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, E.New("packetConn is nil")
	}
	return newPacketConn(CN.NewRefPacketConn(pc, w), w), nil
}

// IsL3Protocol implements C.ProxyAdapter
func (w *WireGuard) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

type refProxyAdapter struct {
	proxyAdapter C.ProxyAdapter
	count        int
	mutex        sync.Mutex
}

func (r *refProxyAdapter) SetProxyAdapter(proxyAdapter C.ProxyAdapter) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.proxyAdapter = proxyAdapter
	r.count++
}

func (r *refProxyAdapter) ClearProxyAdapter() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.count--
	if r.count == 0 {
		r.proxyAdapter = nil
	}
}

func (r *refProxyAdapter) Name() string {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.Name()
	}
	return ""
}

func (r *refProxyAdapter) Type() C.AdapterType {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.Type()
	}
	return C.AdapterType(0)
}

func (r *refProxyAdapter) Addr() string {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.Addr()
	}
	return ""
}

func (r *refProxyAdapter) SupportUDP() bool {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.SupportUDP()
	}
	return false
}

func (r *refProxyAdapter) SupportXUDP() bool {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.SupportXUDP()
	}
	return false
}

func (r *refProxyAdapter) SupportTFO() bool {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.SupportTFO()
	}
	return false
}

func (r *refProxyAdapter) MarshalJSON() ([]byte, error) {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.MarshalJSON()
	}
	return nil, C.ErrNotSupport
}

func (r *refProxyAdapter) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.StreamConnContext(ctx, c, metadata)
	}
	return nil, C.ErrNotSupport
}

func (r *refProxyAdapter) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.DialContext(ctx, metadata, opts...)
	}
	return nil, C.ErrNotSupport
}

func (r *refProxyAdapter) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.ListenPacketContext(ctx, metadata, opts...)
	}
	return nil, C.ErrNotSupport
}

func (r *refProxyAdapter) SupportUOT() bool {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.SupportUOT()
	}
	return false
}

func (r *refProxyAdapter) SupportWithDialer() C.NetWork {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.SupportWithDialer()
	}
	return C.InvalidNet
}

func (r *refProxyAdapter) DialContextWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (C.Conn, error) {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.DialContextWithDialer(ctx, dialer, metadata)
	}
	return nil, C.ErrNotSupport
}

func (r *refProxyAdapter) ListenPacketWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (C.PacketConn, error) {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.ListenPacketWithDialer(ctx, dialer, metadata)
	}
	return nil, C.ErrNotSupport
}

func (r *refProxyAdapter) IsL3Protocol(metadata *C.Metadata) bool {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.IsL3Protocol(metadata)
	}
	return false
}

func (r *refProxyAdapter) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	if r.proxyAdapter != nil {
		return r.proxyAdapter.Unwrap(metadata, touch)
	}
	return nil
}

var _ C.ProxyAdapter = (*refProxyAdapter)(nil)
