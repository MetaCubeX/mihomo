package outbound

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/resolver/defaultguard"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	ipnstore "tailscale.com/ipn/store"
	"tailscale.com/logtail"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

type Tailscale struct {
	*Base
	option TailscaleOption
	server *tsnet.Server

	startMu       sync.Mutex
	startErr      error
	serverStarted bool
	started       bool

	exitNodeMu  sync.Mutex
	exitNodeSet bool
}

const tailscaleStartTimeout = 45 * time.Second

var (
	tailscaleAndroidInterfaceGetterOnce sync.Once
	tailscaleAndroidNetworkMu           sync.RWMutex
	tailscaleAndroidNetwork             androidTailscaleNetworkInfo
	tailscaleAndroidNetmonMu            sync.Mutex
	tailscaleAndroidNetmonNodes         = map[*Tailscale]struct{}{}
	tailscaleLogtailDisableOnce         sync.Once
)

var errTailscaleLegacyAndroidProfileDisabled = fmt.Errorf("legacy Android profile migration disabled")

type androidTailscaleNetworkInfo struct {
	DefaultInterface string                          `json:"defaultInterface"`
	Interfaces       []androidTailscaleInterfaceInfo `json:"interfaces"`
}

type androidTailscaleInterfaceInfo struct {
	Name      string   `json:"name"`
	Index     int      `json:"index"`
	MTU       int      `json:"mtu"`
	Addresses []string `json:"addresses"`
}

type TailscaleOption struct {
	BasicOption
	Name       string `proxy:"name"`
	AuthKey    string `proxy:"auth-key,omitempty"`
	Hostname   string `proxy:"hostname,omitempty"`
	ControlURL string `proxy:"control-url,omitempty"`
	Ephemeral  bool   `proxy:"ephemeral,omitempty"`
	// AcceptRoutes controls whether subnet routes advertised by other Tailscale
	// nodes are usable by this tsnet node. It defaults to true.
	AcceptRoutes *bool  `proxy:"accept-routes,omitempty"`
	ExitNode     string `proxy:"exit-node,omitempty"`
}

func NewTailscale(option TailscaleOption) (*Tailscale, error) {
	installTailscaleAndroidInterfaceGetter()
	disableTailscaleLogtailUploads(option.Name)

	hostname := normalizeTailscaleHostname(option.Hostname)
	if hostname == "" {
		hostname = normalizeTailscaleHostname(option.Name)
	}
	if hostname == "" {
		hostname = "mihomo-tailscale"
	}
	stateDir := C.Path.GetPathByHash("tailscale", option.Name)
	stateStore, err := newTailscaleStateStore(stateDir, option.Name)
	if err != nil {
		return nil, err
	}
	log.Infoln("[Tailscale](%s) creating node hostname=%s auth-key-present=%t control-url=%s", option.Name, hostname, option.AuthKey != "", option.ControlURL)

	outbound := &Tailscale{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         "tailscale",
			Type:         C.Tailscale,
			ProviderName: option.ProviderName,
			UDP:          true,
		}),
		option: option,
	}
	outbound.server = &tsnet.Server{
		Dir:        stateDir,
		Store:      stateStore,
		Hostname:   hostname,
		AuthKey:    option.AuthKey,
		ControlURL: option.ControlURL,
		Ephemeral:  option.Ephemeral,
		UserLogf:   tailscaleUserLogf(option.Name),
		Logf: func(format string, args ...any) {
			log.Debugln("[Tailscale](%s) %s", option.Name, fmt.Sprintf(format, args...))
		},
	}
	return outbound, nil
}

type tailscaleAndroidStateStore struct {
	ipn.StateStore
	name string
}

func newTailscaleStateStore(stateDir string, name string) (ipn.StateStore, error) {
	if runtime.GOOS == "android" {
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			return nil, fmt.Errorf("create tailscale state dir: %w", err)
		}
		if err := os.Setenv("TS_LOGS_DIR", stateDir); err != nil {
			return nil, fmt.Errorf("set tailscale logs dir: %w", err)
		}
	}
	stateFile := filepath.Join(stateDir, "tailscaled.state")
	store, err := ipnstore.New(tailscaleStoreLogf(name), stateFile)
	if err != nil {
		return nil, fmt.Errorf("create tailscale state store: %w", err)
	}
	if runtime.GOOS == "android" {
		log.Infoln("[Tailscale](%s) using Android isolated state store %s", name, stateFile)
		return &tailscaleAndroidStateStore{StateStore: store, name: name}, nil
	}
	return store, nil
}

func disableTailscaleLogtailUploads(name string) {
	tailscaleLogtailDisableOnce.Do(func() {
		logtail.Disable()
		log.Infoln("[Tailscale](%s) disabled Tailscale logtail uploads to avoid background OS DNS lookups", name)
	})
}

func tailscaleStoreLogf(name string) func(string, ...any) {
	return func(format string, args ...any) {
		log.Debugln("[Tailscale](%s) store: %s", name, fmt.Sprintf(format, args...))
	}
}

func (s *tailscaleAndroidStateStore) ReadState(id ipn.StateKey) ([]byte, error) {
	if id == "ipn-android" {
		log.Infoln("[Tailscale](%s) skipping legacy Android profile migration", s.name)
		return nil, errTailscaleLegacyAndroidProfileDisabled
	}
	return s.StateStore.ReadState(id)
}

func installTailscaleAndroidInterfaceGetter() {
	if runtime.GOOS != "android" {
		return
	}
	tailscaleAndroidInterfaceGetterOnce.Do(func() {
		netmon.RegisterInterfaceGetter(tailscaleAndroidInterfaces)
		log.Infoln("[Tailscale] registered Android-safe interface getter")
	})
}

func SetAndroidTailscaleNetworkInfo(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("empty Android Tailscale network info")
	}
	var info androidTailscaleNetworkInfo
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		return fmt.Errorf("parse Android Tailscale network info: %w", err)
	}
	info = normalizeAndroidTailscaleNetworkInfo(info)

	tailscaleAndroidNetworkMu.Lock()
	tailscaleAndroidNetwork = info
	tailscaleAndroidNetworkMu.Unlock()

	updateTailscaleAndroidDefaultRoute(info.DefaultInterface)
	injectTailscaleAndroidNetmonEvents()
	log.Infoln("[Tailscale] Android network info updated default=%s interfaces=%d", info.DefaultInterface, len(info.Interfaces))
	return nil
}

func registerTailscaleAndroidNetmon(t *Tailscale) {
	tailscaleAndroidNetmonMu.Lock()
	tailscaleAndroidNetmonNodes[t] = struct{}{}
	count := len(tailscaleAndroidNetmonNodes)
	tailscaleAndroidNetmonMu.Unlock()
	log.Debugln("[Tailscale](%s) registered Android netmon wake target count=%d", t.Name(), count)
}

func unregisterTailscaleAndroidNetmon(t *Tailscale) {
	tailscaleAndroidNetmonMu.Lock()
	delete(tailscaleAndroidNetmonNodes, t)
	count := len(tailscaleAndroidNetmonNodes)
	tailscaleAndroidNetmonMu.Unlock()
	log.Debugln("[Tailscale](%s) unregistered Android netmon wake target count=%d", t.Name(), count)
}

func injectTailscaleAndroidNetmonEvents() {
	tailscaleAndroidNetmonMu.Lock()
	nodes := make([]*Tailscale, 0, len(tailscaleAndroidNetmonNodes))
	for node := range tailscaleAndroidNetmonNodes {
		nodes = append(nodes, node)
	}
	tailscaleAndroidNetmonMu.Unlock()

	injected := 0
	for _, node := range nodes {
		if node == nil || node.server == nil || node.server.Sys() == nil {
			continue
		}
		netMon, ok := node.server.Sys().NetMon.GetOK()
		if !ok || netMon == nil {
			continue
		}
		netMon.InjectEvent()
		injected++
	}
	log.Infoln("[Tailscale] Android network change injected netmon events count=%d targets=%d", injected, len(nodes))
}

func tailscaleAndroidInterfaces() ([]netmon.Interface, error) {
	if ifaces := currentAndroidTailscaleInterfaces(); len(ifaces) > 0 {
		log.Debugln("[Tailscale] providing Android platform network interfaces count=%d", len(ifaces))
		return ifaces, nil
	}
	log.Debugln("[Tailscale] providing Android-safe synthetic network interfaces")
	return syntheticTailscaleAndroidInterfaces(), nil
}

func currentAndroidTailscaleInterfaces() []netmon.Interface {
	tailscaleAndroidNetworkMu.RLock()
	info := tailscaleAndroidNetwork
	tailscaleAndroidNetworkMu.RUnlock()

	if len(info.Interfaces) == 0 {
		return nil
	}
	ifaces := make([]netmon.Interface, 0, len(info.Interfaces)+1)
	for i, iface := range info.Interfaces {
		addrs := androidTailscaleNetAddrs(iface.Addresses)
		if len(addrs) == 0 {
			continue
		}
		index := iface.Index
		if index <= 0 {
			index = 2 + i
		}
		mtu := iface.MTU
		if mtu <= 0 {
			mtu = 1500
		}
		ifaces = append(ifaces, netmon.Interface{
			Interface: &net.Interface{
				Index: index,
				MTU:   mtu,
				Name:  iface.Name,
				Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
			},
			AltAddrs: addrs,
		})
	}
	if len(ifaces) == 0 {
		return nil
	}
	ifaces = append(ifaces, syntheticTailscaleAndroidLoopbackInterface())
	return ifaces
}

func syntheticTailscaleAndroidInterfaces() []netmon.Interface {
	return []netmon.Interface{
		{
			Interface: &net.Interface{
				Index: 2,
				MTU:   1500,
				Name:  "android0",
				Flags: net.FlagUp | net.FlagBroadcast | net.FlagMulticast,
			},
			AltAddrs: []net.Addr{
				&net.IPNet{IP: net.IPv4(10, 0, 0, 2), Mask: net.CIDRMask(24, 32)},
			},
		},
		syntheticTailscaleAndroidLoopbackInterface(),
	}
}

func syntheticTailscaleAndroidLoopbackInterface() netmon.Interface {
	return netmon.Interface{
		Interface: &net.Interface{
			Index: 1,
			MTU:   65536,
			Name:  "lo",
			Flags: net.FlagUp | net.FlagLoopback,
		},
		AltAddrs: []net.Addr{
			&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		},
	}
}

func normalizeAndroidTailscaleNetworkInfo(info androidTailscaleNetworkInfo) androidTailscaleNetworkInfo {
	info.DefaultInterface = strings.TrimSpace(info.DefaultInterface)
	out := androidTailscaleNetworkInfo{DefaultInterface: info.DefaultInterface}
	for _, iface := range info.Interfaces {
		iface.Name = strings.TrimSpace(iface.Name)
		if iface.Name == "" {
			continue
		}
		addrs := make([]string, 0, len(iface.Addresses))
		for _, addr := range iface.Addresses {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				continue
			}
			if _, err := netip.ParsePrefix(addr); err != nil {
				log.Warnln("[Tailscale] skipping invalid Android interface address iface=%s address=%s error=%v", iface.Name, addr, err)
				continue
			}
			addrs = append(addrs, addr)
		}
		if len(addrs) == 0 {
			continue
		}
		iface.Addresses = addrs
		out.Interfaces = append(out.Interfaces, iface)
	}
	return out
}

func androidTailscaleNetAddrs(addresses []string) []net.Addr {
	addrs := make([]net.Addr, 0, len(addresses))
	for _, addr := range addresses {
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			log.Warnln("[Tailscale] skipping invalid Android interface address address=%s error=%v", addr, err)
			continue
		}
		ipNet := androidTailscaleIPNet(prefix)
		if ipNet != nil {
			addrs = append(addrs, ipNet)
		}
	}
	return addrs
}

func androidTailscaleIPNet(prefix netip.Prefix) *net.IPNet {
	addr := prefix.Addr().Unmap()
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	if addr.Is4() {
		bytes := addr.As4()
		return &net.IPNet{
			IP:   net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3]),
			Mask: net.CIDRMask(prefix.Bits(), 32),
		}
	}
	if addr.Is6() {
		bytes := addr.As16()
		return &net.IPNet{
			IP:   net.IP(append([]byte(nil), bytes[:]...)),
			Mask: net.CIDRMask(prefix.Bits(), 128),
		}
	}
	return nil
}

func (t *Tailscale) start() error {
	t.startMu.Lock()
	defer t.startMu.Unlock()
	if t.started {
		return nil
	}

	t.startErr = nil
	if err := os.MkdirAll(t.server.Dir, 0o700); err != nil {
		t.startErr = fmt.Errorf("create tailscale state dir: %w", err)
		return t.startErr
	}
	log.Infoln("[Tailscale](%s) starting node hostname=%s state=%s ephemeral=%t", t.Name(), t.server.Hostname, t.server.Dir, t.option.Ephemeral)
	if !t.serverStarted {
		if err := withDefaultResolverAllowed(t.server.Start); err != nil {
			t.startErr = fmt.Errorf("start tailscale node: %w", err)
			log.Warnln("[Tailscale](%s) start failed: %s", t.Name(), err)
			return t.startErr
		}
		t.serverStarted = true
		registerTailscaleAndroidNetmon(t)
		log.Infoln("[Tailscale](%s) tsnet start returned", t.Name())
	}

	startCtx, cancel := context.WithTimeout(context.Background(), tailscaleStartTimeout)
	defer cancel()
	log.Infoln("[Tailscale](%s) configuring route prefs", t.Name())
	if err := withDefaultResolverAllowed(func() error { return t.ensureRoutePrefs(startCtx) }); err != nil {
		t.startErr = fmt.Errorf("configure tailscale route prefs: %w", err)
		log.Warnln("[Tailscale](%s) configure route prefs failed: %s", t.Name(), err)
		return t.startErr
	}
	log.Infoln("[Tailscale](%s) waiting for node readiness", t.Name())
	status, err := t.up(startCtx)
	if err != nil {
		t.startErr = fmt.Errorf("wait tailscale node ready: %w", err)
		log.Warnln("[Tailscale](%s) wait ready failed: %s", t.Name(), err)
		return t.startErr
	}
	t.started = true
	log.Infoln("[Tailscale](%s) node ready state=%s ips=%s subnet-routes=%s", t.Name(), status.BackendState, tailscaleIPsString(status.TailscaleIPs), tailscalePrimaryRoutesString(status))
	return t.startErr
}

func (t *Tailscale) acceptRoutes() bool {
	return t.option.AcceptRoutes == nil || *t.option.AcceptRoutes
}

func (t *Tailscale) ensureRoutePrefs(ctx context.Context) error {
	acceptRoutes := t.acceptRoutes()
	lc, err := t.server.LocalClient()
	if err != nil {
		return fmt.Errorf("create tailscale local client: %w", err)
	}
	if _, err = lc.EditPrefs(ctx, tailscaleRoutePrefs(acceptRoutes, t.option.ExitNode)); err != nil {
		return fmt.Errorf("set accept-routes=%t: %w", acceptRoutes, err)
	}
	log.Infoln("[Tailscale](%s) accept-routes=%t", t.Name(), acceptRoutes)
	if t.option.ExitNode == "" {
		log.Debugln("[Tailscale](%s) exit-node disabled", t.Name())
	}
	return nil
}

func tailscaleRoutePrefs(acceptRoutes bool, exitNode string) *ipn.MaskedPrefs {
	prefs := &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			RouteAll: acceptRoutes,
		},
		RouteAllSet: true,
	}
	if exitNode == "" {
		prefs.ExitNodeIDSet = true
		prefs.ExitNodeIPSet = true
		prefs.AutoExitNodeSet = true
	}
	return prefs
}

func (t *Tailscale) ensureExitNode(ctx context.Context) error {
	if t.option.ExitNode == "" {
		return nil
	}
	t.exitNodeMu.Lock()
	defer t.exitNodeMu.Unlock()
	if t.exitNodeSet {
		return nil
	}

	lc, err := t.server.LocalClient()
	if err != nil {
		return fmt.Errorf("create tailscale local client: %w", err)
	}
	status, err := lc.Status(ctx)
	if err != nil {
		return fmt.Errorf("get tailscale status: %w", err)
	}
	id, ip, description, err := resolveTailscaleExitNode(t.option.ExitNode, status)
	if err != nil {
		return err
	}

	maskedPrefs := tailscaleSetExitNodePrefs(id, ip)
	if _, err = lc.EditPrefs(ctx, maskedPrefs); err != nil {
		return fmt.Errorf("set tailscale exit node %s: %w", description, err)
	}
	t.exitNodeSet = true
	log.Infoln("[Tailscale](%s) using exit node %s", t.Name(), description)
	return nil
}

func tailscaleSetExitNodePrefs(id tailcfg.StableNodeID, ip netip.Addr) *ipn.MaskedPrefs {
	prefs := &ipn.MaskedPrefs{
		ExitNodeIDSet:   true,
		ExitNodeIPSet:   true,
		AutoExitNodeSet: true,
		Prefs: ipn.Prefs{
			ExitNodeID: id,
			ExitNodeIP: ip,
		},
	}
	return prefs
}

func (t *Tailscale) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if err = t.start(); err != nil {
		return nil, err
	}
	if err = withDefaultResolverAllowed(func() error { return t.ensureExitNode(ctx) }); err != nil {
		return nil, err
	}
	conn, err := t.dial(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		log.Warnln("[Tailscale](%s) dial tcp %s failed: %s", t.Name(), metadata.RemoteAddress(), err)
		return nil, err
	}
	return NewConn(conn, t), nil
}

func (t *Tailscale) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.start(); err != nil {
		return nil, err
	}
	if err = withDefaultResolverAllowed(func() error { return t.ensureExitNode(ctx) }); err != nil {
		return nil, err
	}
	rawPC := newTailscalePacketConn(t.Name(), t.dial)
	if err = rawPC.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc := newPacketConn(rawPC, t)
	pc.(*packetConn).resolveUDP = rawPC.ResolveUDP
	return pc, nil
}

func (t *Tailscale) Close() error {
	if !t.serverStarted {
		return nil
	}
	unregisterTailscaleAndroidNetmon(t)
	if err := t.server.Close(); err != nil {
		return fmt.Errorf("close tailscale node: %w", err)
	}
	t.started = false
	t.serverStarted = false
	log.Infoln("[Tailscale](%s) node closed", t.Name())
	return nil
}

func (t *Tailscale) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

func (t *Tailscale) IsL3Protocol(metadata *C.Metadata) bool {
	return metadata.Host == "" || metadata.Resolved()
}

func (t *Tailscale) up(ctx context.Context) (*ipnstate.Status, error) {
	release := defaultguard.Allow()
	defer release()
	return t.server.Up(ctx)
}

func (t *Tailscale) dial(ctx context.Context, network, address string) (net.Conn, error) {
	release := defaultguard.Allow()
	defer release()
	return t.server.Dial(ctx, network, address)
}

func withDefaultResolverAllowed(fn func() error) error {
	release := defaultguard.Allow()
	defer release()
	return fn()
}

func normalizeTailscaleHostname(hostname string) string {
	hostname = strings.Trim(strings.ToLower(hostname), "-")
	if hostname == "" {
		return ""
	}
	var builder strings.Builder
	lastHyphen := false
	for _, r := range hostname {
		valid := r == '-' || ('0' <= r && r <= '9') || ('a' <= r && r <= 'z')
		if !valid {
			r = '-'
		}
		if r == '-' {
			if lastHyphen {
				continue
			}
			lastHyphen = true
		} else {
			lastHyphen = false
		}
		builder.WriteRune(r)
	}
	return strings.Trim(builder.String(), "-")
}

type tailscalePacketConn struct {
	name      string
	dial      tailscaleDialFunc
	mu        sync.Mutex
	conns     map[string]*tailscaleUDPConn
	remotes   map[string]tailscaleUDPRemote
	domains   map[string]tailscaleUDPDomainMapping
	readCh    chan tailscaleUDPPacket
	closed    chan struct{}
	closeOnce sync.Once
}

type tailscaleDialFunc func(ctx context.Context, network, address string) (net.Conn, error)

type tailscaleUDPRemote struct {
	dialAddress string
	writeAddr   net.Addr
	readAddr    net.Addr
	preserveDNS bool
}

type tailscaleUDPDomainMapping struct {
	host       string
	readDomain bool
}

type tailscaleUDPConn struct {
	net.Conn
	remote  tailscaleUDPRemote
	writeMu sync.Mutex
}

type tailscaleUDPPacket struct {
	data []byte
	addr net.Addr
}

func newTailscalePacketConn(name string, dial tailscaleDialFunc) *tailscalePacketConn {
	return &tailscalePacketConn{
		name:    name,
		dial:    dial,
		conns:   make(map[string]*tailscaleUDPConn),
		remotes: make(map[string]tailscaleUDPRemote),
		domains: make(map[string]tailscaleUDPDomainMapping),
		readCh:  make(chan tailscaleUDPPacket, 64),
		closed:  make(chan struct{}),
	}
}

func (c *tailscalePacketConn) ResolveUDP(_ context.Context, metadata *C.Metadata) error {
	remote, err := tailscaleUDPRemoteForMetadata(metadata)
	if err != nil {
		return err
	}
	if udpAddr, ok := remote.writeAddr.(*net.UDPAddr); ok {
		metadata.DstIP = udpAddr.AddrPort().Addr().Unmap()
	}
	c.registerRemote(remote)
	if remote.preserveDNS {
		log.Debugln("[Tailscale](%s) dial udp %s using Tailscale DNS", c.name, remote.dialAddress)
	}
	return nil
}

func (c *tailscalePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, ErrUDPRemoteAddrMismatch
	}
	uc, err := c.connForAddr(addr)
	if err != nil {
		return 0, err
	}
	uc.writeMu.Lock()
	defer uc.writeMu.Unlock()
	return uc.Write(b)
}

func (c *tailscalePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.readCh:
		return copy(b, packet.data), packet.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *tailscalePacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.mu.Lock()
		defer c.mu.Unlock()
		for key, conn := range c.conns {
			_ = conn.Close()
			delete(c.conns, key)
		}
	})
	return nil
}

func (c *tailscalePacketConn) LocalAddr() net.Addr {
	return tailscalePacketAddr("tailscale-udp")
}

func (c *tailscalePacketConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *tailscalePacketConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *tailscalePacketConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func (c *tailscalePacketConn) registerRemote(remote tailscaleUDPRemote) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remotes[remote.writeAddr.String()] = remote
	if !remote.preserveDNS {
		return
	}
	udpAddr, ok := remote.writeAddr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return
	}
	host, _, err := net.SplitHostPort(remote.dialAddress)
	if err != nil || host == "" {
		return
	}
	_, readDomain := remote.readAddr.(tailscaleDomainAddr)
	c.domains[udpAddr.AddrPort().Addr().Unmap().String()] = tailscaleUDPDomainMapping{
		host:       host,
		readDomain: readDomain,
	}
}

func (c *tailscalePacketConn) connForAddr(addr net.Addr) (*tailscaleUDPConn, error) {
	key := addr.String()
	c.mu.Lock()
	if uc := c.conns[key]; uc != nil {
		c.mu.Unlock()
		return uc, nil
	}
	remote, ok := c.remotes[key]
	if !ok {
		remote = c.remoteForWriteAddr(addr)
		c.remotes[key] = remote
	}
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
	conn, err := c.dial(ctx, "udp", remote.dialAddress)
	cancel()
	if err != nil {
		log.Warnln("[Tailscale](%s) dial udp %s failed: %s", c.name, remote.dialAddress, err)
		return nil, err
	}
	uc := &tailscaleUDPConn{Conn: conn, remote: remote}

	c.mu.Lock()
	if existing := c.conns[key]; existing != nil {
		c.mu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	select {
	case <-c.closed:
		c.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	default:
	}
	c.conns[key] = uc
	c.mu.Unlock()

	log.Debugln("[Tailscale](%s) udp flow opened remote=%s addr=%s", c.name, remote.dialAddress, key)
	go c.readLoop(key, uc)
	return uc, nil
}

func (c *tailscalePacketConn) remoteForWriteAddr(addr net.Addr) tailscaleUDPRemote {
	if udpAddr, ok := addr.(*net.UDPAddr); ok && udpAddr != nil {
		if mapping, ok := c.domains[udpAddr.AddrPort().Addr().Unmap().String()]; ok {
			dialAddress := net.JoinHostPort(mapping.host, strconv.Itoa(udpAddr.Port))
			readAddr := net.Addr(udpAddr)
			if mapping.readDomain {
				readAddr = tailscaleDomainAddr(dialAddress)
			}
			return tailscaleUDPRemote{
				dialAddress: dialAddress,
				writeAddr:   addr,
				readAddr:    readAddr,
				preserveDNS: true,
			}
		}
	}
	return tailscaleUDPRemote{
		dialAddress: addr.String(),
		writeAddr:   addr,
		readAddr:    addr,
	}
}

func (c *tailscalePacketConn) readLoop(key string, uc *tailscaleUDPConn) {
	buf := make([]byte, 64*1024)
	for {
		n, err := uc.Read(buf)
		if err != nil {
			c.removeConn(key, uc)
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		select {
		case c.readCh <- tailscaleUDPPacket{data: data, addr: uc.remote.readAddr}:
		case <-c.closed:
			return
		}
	}
}

func (c *tailscalePacketConn) removeConn(key string, uc *tailscaleUDPConn) {
	c.mu.Lock()
	if c.conns[key] == uc {
		delete(c.conns, key)
	}
	c.mu.Unlock()
	_ = uc.Close()
	log.Debugln("[Tailscale](%s) udp flow closed remote=%s addr=%s", c.name, uc.remote.dialAddress, key)
}

type tailscalePacketAddr string

func (a tailscalePacketAddr) Network() string {
	return "udp"
}

func (a tailscalePacketAddr) String() string {
	return string(a)
}

type tailscaleDomainAddr string

func (a tailscaleDomainAddr) Network() string {
	return "udp"
}

func (a tailscaleDomainAddr) String() string {
	return string(a)
}

func tailscaleUDPRemoteForMetadata(metadata *C.Metadata) (tailscaleUDPRemote, error) {
	if metadata.Host != "" {
		remoteAddress := metadata.RemoteAddress()
		writeAddr := tailscaleUDPWriteAddr(metadata)
		return tailscaleUDPRemote{
			dialAddress: remoteAddress,
			writeAddr:   writeAddr,
			readAddr:    tailscaleUDPReadAddr(metadata, remoteAddress),
			preserveDNS: true,
		}, nil
	}

	remoteAddr := metadata.UDPAddr()
	if remoteAddr == nil {
		return tailscaleUDPRemote{}, fmt.Errorf("resolve tailscale udp remote %s: destination ip not valid", metadata.RemoteAddress())
	}
	return tailscaleUDPRemote{
		dialAddress: remoteAddr.String(),
		writeAddr:   remoteAddr,
		readAddr:    remoteAddr,
	}, nil
}

func tailscaleUDPWriteAddr(metadata *C.Metadata) net.Addr {
	if addr := metadataRawUDPAddr(metadata); addr != nil {
		return addr
	}
	addr := tailscaleUDPDomainSyntheticAddr(metadata.Host)
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, metadata.DstPort))
}

func tailscaleUDPReadAddr(metadata *C.Metadata, remoteAddress string) net.Addr {
	if addr := metadataRawUDPAddr(metadata); addr != nil {
		return addr
	}
	return tailscaleDomainAddr(remoteAddress)
}

func metadataRawUDPAddr(metadata *C.Metadata) *net.UDPAddr {
	if addr, ok := metadata.RawDstAddr.(*net.UDPAddr); ok && addr != nil {
		if addrPort := addr.AddrPort(); addrPort.IsValid() {
			return addr
		}
	}
	return nil
}

func tailscaleUDPDomainSyntheticAddr(host string) netip.Addr {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(strings.ToLower(host)))
	sum := hash.Sum32()
	return netip.AddrFrom4([4]byte{240, byte(sum >> 16), byte(sum >> 8), byte(sum)})
}

func tailscaleIPsString(ips []netip.Addr) string {
	if len(ips) == 0 {
		return "[]"
	}
	values := make([]string, 0, len(ips))
	for _, ip := range ips {
		values = append(values, ip.String())
	}
	return "[" + strings.Join(values, ",") + "]"
}

func tailscalePrimaryRoutesString(status *ipnstate.Status) string {
	if status == nil || len(status.Peer) == 0 {
		return "[]"
	}
	routeSet := map[string]struct{}{}
	for _, peer := range status.Peer {
		if peer == nil || peer.PrimaryRoutes == nil || peer.PrimaryRoutes.IsNil() {
			continue
		}
		for _, route := range peer.PrimaryRoutes.AsSlice() {
			routeSet[route.String()] = struct{}{}
		}
	}
	if len(routeSet) == 0 {
		return "[]"
	}
	routes := make([]string, 0, len(routeSet))
	for route := range routeSet {
		routes = append(routes, route)
	}
	slices.Sort(routes)
	return "[" + strings.Join(routes, ",") + "]"
}

func tailscaleUserLogf(name string) func(string, ...any) {
	return func(format string, args ...any) {
		message := fmt.Sprintf(format, args...)
		if strings.Contains(message, "To start this tsnet server") {
			log.Infoln("[Tailscale](%s) %s", name, message)
			return
		}
		log.Debugln("[Tailscale](%s) %s", name, message)
	}
}

func resolveTailscaleExitNode(target string, status *ipnstate.Status) (tailcfg.StableNodeID, netip.Addr, string, error) {
	target = strings.TrimSpace(target)
	if ip, err := netip.ParseAddr(target); err == nil {
		return "", ip, ip.String(), nil
	}

	matches := make([]*ipnstate.PeerStatus, 0, 1)
	for _, peer := range status.Peer {
		if tailscalePeerMatches(peer, target) {
			matches = append(matches, peer)
		}
	}
	if len(matches) == 1 && matches[0].ExitNodeOption && matches[0].Online {
		return matches[0].ID, netip.Addr{}, peerDescription(matches[0]), nil
	}

	if len(matches) != 1 {
		log.Warnln("[Tailscale] exit-node %q matched %d nodes, falling back to automatic selection", target, len(matches))
	} else if !matches[0].ExitNodeOption {
		log.Warnln("[Tailscale] exit-node %q is not an available exit node, falling back to automatic selection", target)
	} else {
		log.Warnln("[Tailscale] exit-node %q is offline, falling back to automatic selection", target)
	}

	peer := selectAutomaticExitNode(status)
	if peer == nil {
		return "", netip.Addr{}, "", fmt.Errorf("no available tailscale exit node for %q", target)
	}
	return peer.ID, netip.Addr{}, peerDescription(peer), nil
}

func tailscalePeerMatches(peer *ipnstate.PeerStatus, target string) bool {
	normalizedTarget := strings.TrimSuffix(strings.ToLower(target), ".")
	if string(peer.ID) == target {
		return true
	}
	if strings.EqualFold(peer.HostName, target) {
		return true
	}
	dnsName := strings.TrimSuffix(strings.ToLower(peer.DNSName), ".")
	if dnsName == normalizedTarget {
		return true
	}
	if firstLabel, _, ok := strings.Cut(dnsName, "."); ok && firstLabel == normalizedTarget {
		return true
	}
	if ip, err := netip.ParseAddr(target); err == nil {
		for _, peerIP := range peer.TailscaleIPs {
			if peerIP == ip {
				return true
			}
		}
	}
	return false
}

func selectAutomaticExitNode(status *ipnstate.Status) *ipnstate.PeerStatus {
	for _, peer := range status.Peer {
		if !peer.ExitNodeOption {
			continue
		}
		if peer.Online {
			return peer
		}
	}
	return nil
}

func peerDescription(peer *ipnstate.PeerStatus) string {
	if peer.DNSName != "" {
		return strings.TrimSuffix(peer.DNSName, ".")
	}
	if peer.HostName != "" {
		return peer.HostName
	}
	return string(peer.ID)
}

var _ ProxyAdapter = (*Tailscale)(nil)
