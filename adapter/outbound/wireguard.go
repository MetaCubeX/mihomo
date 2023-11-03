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

	CN "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
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
	startOnce sync.Once
	startErr  error
	resolver  *dns.Resolver
	refP      *refProxyAdapter
}

type WireGuardOption struct {
	BasicOption
	WireGuardPeerOption
	Name                string `proxy:"name"`
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
	Ip           string   `proxy:"ip,omitempty"`
	Ipv6         string   `proxy:"ipv6,omitempty"`
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

func (option WireGuardPeerOption) Prefixes() ([]netip.Prefix, error) {
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
		dialer: proxydialer.NewByNameSingDialer(option.DialerProxy, dialer.NewDialer()),
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
	var connectAddr M.Socksaddr
	if len(option.Peers) < 2 {
		isConnect = true
		if len(option.Peers) == 1 {
			connectAddr = option.Peers[0].Addr()
		} else {
			connectAddr = option.Addr()
		}
	}
	outbound.bind = wireguard.NewClientBind(context.Background(), wgSingErrorHandler{outbound.Name()}, outbound.dialer, isConnect, connectAddr, reserved)

	var localPrefixes []netip.Prefix

	var privateKey string
	{
		bytes, err := base64.StdEncoding.DecodeString(option.PrivateKey)
		if err != nil {
			return nil, E.Cause(err, "decode private key")
		}
		privateKey = hex.EncodeToString(bytes)
	}
	ipcConf := "private_key=" + privateKey
	if peersLen := len(option.Peers); peersLen > 0 {
		localPrefixes = make([]netip.Prefix, 0, peersLen*2)
		for i, peer := range option.Peers {
			var peerPublicKey, preSharedKey string
			{
				bytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
				if err != nil {
					return nil, E.Cause(err, "decode public key for peer ", i)
				}
				peerPublicKey = hex.EncodeToString(bytes)
			}
			if peer.PreSharedKey != "" {
				bytes, err := base64.StdEncoding.DecodeString(peer.PreSharedKey)
				if err != nil {
					return nil, E.Cause(err, "decode pre shared key for peer ", i)
				}
				preSharedKey = hex.EncodeToString(bytes)
			}
			destination := peer.Addr()
			ipcConf += "\npublic_key=" + peerPublicKey
			ipcConf += "\nendpoint=" + destination.String()
			if preSharedKey != "" {
				ipcConf += "\npreshared_key=" + preSharedKey
			}
			if len(peer.AllowedIPs) == 0 {
				return nil, E.New("missing allowed_ips for peer ", i)
			}
			for _, allowedIP := range peer.AllowedIPs {
				ipcConf += "\nallowed_ip=" + allowedIP
			}
			if len(peer.Reserved) > 0 {
				if len(peer.Reserved) != 3 {
					return nil, E.New("invalid reserved value for peer ", i, ", required 3 bytes, got ", len(peer.Reserved))
				}
				copy(reserved[:], option.Reserved)
				outbound.bind.SetReservedForEndpoint(destination, reserved)
			}
			prefixes, err := peer.Prefixes()
			if err != nil {
				return nil, err
			}
			localPrefixes = append(localPrefixes, prefixes...)
		}
	} else {
		var peerPublicKey, preSharedKey string
		{
			bytes, err := base64.StdEncoding.DecodeString(option.PublicKey)
			if err != nil {
				return nil, E.Cause(err, "decode peer public key")
			}
			peerPublicKey = hex.EncodeToString(bytes)
		}
		if option.PreSharedKey != "" {
			bytes, err := base64.StdEncoding.DecodeString(option.PreSharedKey)
			if err != nil {
				return nil, E.Cause(err, "decode pre shared key")
			}
			preSharedKey = hex.EncodeToString(bytes)
		}
		ipcConf += "\npublic_key=" + peerPublicKey
		ipcConf += "\nendpoint=" + connectAddr.String()
		if preSharedKey != "" {
			ipcConf += "\npreshared_key=" + preSharedKey
		}
		var err error
		localPrefixes, err = option.Prefixes()
		if err != nil {
			return nil, err
		}
		var has4, has6 bool
		for _, address := range localPrefixes {
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

	if option.PersistentKeepalive != 0 {
		ipcConf += fmt.Sprintf("\npersistent_keepalive_interval=%d", option.PersistentKeepalive)
	}
	mtu := option.MTU
	if mtu == 0 {
		mtu = 1408
	}
	if len(localPrefixes) == 0 {
		return nil, E.New("missing local address")
	}
	var err error
	outbound.tunDevice, err = wireguard.NewStackDevice(localPrefixes, uint32(mtu))
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
	if debug.Enabled {
		log.SingLogger.Trace(fmt.Sprintf("[WG](%s) created wireguard ipc conf: \n %s", option.Name, ipcConf))
	}
	err = outbound.device.IpcSet(ipcConf)
	if err != nil {
		return nil, E.Cause(err, "setup wireguard")
	}
	//err = outbound.tunDevice.Start()

	var has6 bool
	for _, address := range localPrefixes {
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

func closeWireGuard(w *WireGuard) {
	if w.device != nil {
		w.device.Close()
	}
	_ = common.Close(w.tunDevice)
}

func (w *WireGuard) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	options := w.Base.DialOptions(opts...)
	w.dialer.SetDialer(dialer.NewDialer(options...))
	var conn net.Conn
	w.startOnce.Do(func() {
		w.startErr = w.tunDevice.Start()
	})
	if w.startErr != nil {
		return nil, w.startErr
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
	w.startOnce.Do(func() {
		w.startErr = w.tunDevice.Start()
	})
	if w.startErr != nil {
		return nil, w.startErr
	}
	if err != nil {
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
