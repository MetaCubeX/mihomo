package outbound

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

func resetAndroidTailscaleNetworkInfoForTest(t *testing.T) {
	t.Helper()
	tailscaleAndroidNetworkMu.Lock()
	tailscaleAndroidNetwork = androidTailscaleNetworkInfo{}
	tailscaleAndroidNetworkMu.Unlock()
	t.Cleanup(func() {
		tailscaleAndroidNetworkMu.Lock()
		tailscaleAndroidNetwork = androidTailscaleNetworkInfo{}
		tailscaleAndroidNetworkMu.Unlock()
	})
}

func TestNormalizeTailscaleHostname(t *testing.T) {
	got := normalizeTailscaleHostname("TS_Main.Example")
	if got != "ts-main-example" {
		t.Fatalf("unexpected hostname: %s", got)
	}
}

func TestTailscaleAcceptRoutesDefault(t *testing.T) {
	proxy := &Tailscale{option: TailscaleOption{}}
	if !proxy.acceptRoutes() {
		t.Fatal("tailscale proxy should accept subnet routes by default")
	}

	disabled := false
	proxy.option.AcceptRoutes = &disabled
	if proxy.acceptRoutes() {
		t.Fatal("tailscale proxy should honor accept-routes=false")
	}
}

func TestTailscaleAndroidInterfacesAvoidsSystemNetlink(t *testing.T) {
	resetAndroidTailscaleNetworkInfoForTest(t)

	ifaces, err := tailscaleAndroidInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(ifaces) != 2 {
		t.Fatalf("interfaces length = %d, want 2", len(ifaces))
	}

	var haveUsableV4 bool
	var haveLoopback bool
	for _, iface := range ifaces {
		if iface.Interface == nil {
			t.Fatalf("nil interface in %#v", ifaces)
		}
		if !iface.IsUp() {
			t.Fatalf("interface %s should be up", iface.Name)
		}
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if iface.IsLoopback() && ipNet.IP.IsLoopback() {
				haveLoopback = true
			}
			if !iface.IsLoopback() && ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
				haveUsableV4 = true
			}
		}
	}
	if !haveLoopback {
		t.Fatal("expected loopback address")
	}
	if !haveUsableV4 {
		t.Fatal("expected a non-loopback IPv4 address so Tailscale treats Android network as up")
	}
}

func TestTailscaleAndroidInterfacesUsePlatformNetworkInfo(t *testing.T) {
	resetAndroidTailscaleNetworkInfoForTest(t)

	err := SetAndroidTailscaleNetworkInfo(`{
		"defaultInterface": "rmnet_data4",
		"interfaces": [
			{
				"name": "rmnet_data4",
				"index": 31,
				"mtu": 1410,
				"addresses": [
					"10.153.83.183/28",
					"2409:8924:2000:28cc:7c06:30ff:fe59:4839/64"
				]
			}
		]
	}`)
	if err != nil {
		t.Fatal(err)
	}

	ifaces, err := tailscaleAndroidInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(ifaces) != 2 {
		t.Fatalf("interfaces length = %d, want platform interface plus loopback", len(ifaces))
	}
	if ifaces[0].Name != "rmnet_data4" || ifaces[0].Index != 31 || ifaces[0].MTU != 1410 {
		t.Fatalf("unexpected platform interface: %#v", ifaces[0].Interface)
	}
	addrs, err := ifaces[0].Addrs()
	if err != nil {
		t.Fatal(err)
	}
	var haveV4 bool
	var haveV6 bool
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			t.Fatalf("unexpected addr type %T", addr)
		}
		if ipNet.IP.Equal(net.ParseIP("10.153.83.183")) && len(ipNet.Mask) == net.IPv4len {
			haveV4 = true
		}
		if ipNet.IP.Equal(net.ParseIP("2409:8924:2000:28cc:7c06:30ff:fe59:4839")) && len(ipNet.Mask) == net.IPv6len {
			haveV6 = true
		}
	}
	if !haveV4 || !haveV6 {
		t.Fatalf("expected IPv4 and IPv6 platform addrs, addrs=%v", addrs)
	}
}

func TestTailscaleAndroidStateStoreSkipsLegacyAndroidProfile(t *testing.T) {
	inner := fakeStateStore{values: map[ipn.StateKey][]byte{
		"ipn-android": []byte(`{"WantRunning":true}`),
		"other":       []byte("ok"),
	}}
	store := &tailscaleAndroidStateStore{StateStore: inner, name: "ts-main"}

	if _, err := store.ReadState("ipn-android"); err != errTailscaleLegacyAndroidProfileDisabled {
		t.Fatalf("legacy Android profile err = %v, want disabled migration error", err)
	}
	got, err := store.ReadState("other")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ok" {
		t.Fatalf("unexpected delegated state: %q", got)
	}
}

func TestTailscaleRoutePrefsClearsExitNodeWhenUnset(t *testing.T) {
	prefs := tailscaleRoutePrefs(true, "")
	if !prefs.RouteAll || !prefs.RouteAllSet {
		t.Fatalf("expected accept-routes to be set, prefs=%#v", prefs)
	}
	if !prefs.ExitNodeIDSet || !prefs.ExitNodeIPSet || !prefs.AutoExitNodeSet {
		t.Fatalf("expected exit-node fields to be explicitly cleared, prefs=%#v", prefs)
	}
	if prefs.ExitNodeID != "" || prefs.ExitNodeIP.IsValid() || prefs.AutoExitNode != "" {
		t.Fatalf("unexpected exit-node clear values, prefs=%#v", prefs)
	}
}

func TestTailscaleRoutePrefsKeepsExitNodeUntouchedWhenConfigured(t *testing.T) {
	prefs := tailscaleRoutePrefs(false, "exit-gateway")
	if prefs.RouteAll || !prefs.RouteAllSet {
		t.Fatalf("expected accept-routes=false to be set, prefs=%#v", prefs)
	}
	if prefs.ExitNodeIDSet || prefs.ExitNodeIPSet || prefs.AutoExitNodeSet {
		t.Fatalf("exit-node fields should be left for ensureExitNode, prefs=%#v", prefs)
	}
}

func TestTailscaleSetExitNodePrefsClearStaleAlternatives(t *testing.T) {
	prefs := tailscaleSetExitNodePrefs(tailcfg.StableNodeID("node-1"), netip.Addr{})
	if prefs.ExitNodeID != "node-1" || !prefs.ExitNodeIDSet {
		t.Fatalf("expected exit-node id to be set, prefs=%#v", prefs)
	}
	if !prefs.ExitNodeIPSet || prefs.ExitNodeIP.IsValid() || !prefs.AutoExitNodeSet || prefs.AutoExitNode != "" {
		t.Fatalf("expected stale exit-node alternatives to be cleared, prefs=%#v", prefs)
	}

	ip := netip.MustParseAddr("100.64.0.10")
	prefs = tailscaleSetExitNodePrefs("", ip)
	if prefs.ExitNodeIP != ip || !prefs.ExitNodeIPSet {
		t.Fatalf("expected exit-node ip to be set, prefs=%#v", prefs)
	}
	if !prefs.ExitNodeIDSet || prefs.ExitNodeID != "" || !prefs.AutoExitNodeSet || prefs.AutoExitNode != "" {
		t.Fatalf("expected stale exit-node alternatives to be cleared, prefs=%#v", prefs)
	}
}

func TestTailscaleIsL3ProtocolPreservesUnresolvedHost(t *testing.T) {
	proxy := &Tailscale{}
	if proxy.IsL3Protocol(&C.Metadata{Host: "resolver.example.ts.net"}) {
		t.Fatal("unresolved domain should be preserved for Tailscale DNS")
	}
	if !proxy.IsL3Protocol(&C.Metadata{DstIP: netip.MustParseAddr("100.64.0.10")}) {
		t.Fatal("ip-only metadata should remain L3")
	}
	if !proxy.IsL3Protocol(&C.Metadata{Host: "example.com", DstIP: netip.MustParseAddr("100.64.0.10")}) {
		t.Fatal("already-resolved metadata should remain L3")
	}
}

func TestTailscalePrimaryRoutesString(t *testing.T) {
	status := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		key.NewNode().Public(): {
			PrimaryRoutes: viewsOfPrefixes(
				netip.MustParsePrefix("192.168.6.0/24"),
				netip.MustParsePrefix("10.0.0.0/24"),
			),
		},
		key.NewNode().Public(): {
			PrimaryRoutes: viewsOfPrefixes(netip.MustParsePrefix("192.168.6.0/24")),
		},
	}}

	got := tailscalePrimaryRoutesString(status)
	if got != "[10.0.0.0/24,192.168.6.0/24]" {
		t.Fatalf("unexpected routes: %s", got)
	}
}

func TestTailscaleResolveUDPRemotePreservesDomain(t *testing.T) {
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Host:    "example.com",
		DstIP:   netip.MustParseAddr("100.64.0.10"),
		DstPort: 53,
	}

	remote, err := tailscaleUDPRemoteForMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if remote.dialAddress != "example.com:53" {
		t.Fatalf("unexpected UDP remote: %s", remote.dialAddress)
	}
	if !remote.preserveDNS {
		t.Fatal("expected UDP domain to preserve Tailscale DNS")
	}
	if _, ok := remote.readAddr.(tailscaleDomainAddr); !ok {
		t.Fatalf("expected domain read addr, got %T(%s)", remote.readAddr, remote.readAddr)
	}
	if got := remote.writeAddr.String(); got == "100.64.0.10:53" || got == "example.com:53" {
		t.Fatalf("expected internal write addr placeholder, got %s", got)
	}
}

func TestTailscaleResolveUDPRemoteUsesRawDestinationForFakeIP(t *testing.T) {
	rawDst := &net.UDPAddr{IP: net.ParseIP("198.18.0.1"), Port: 5353}
	metadata := &C.Metadata{
		NetWork:    C.UDP,
		Host:       "printer.example.ts.net",
		DNSMode:    C.DNSFakeIP,
		DstPort:    5353,
		RawDstAddr: rawDst,
	}

	remote, err := tailscaleUDPRemoteForMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if remote.dialAddress != "printer.example.ts.net:5353" {
		t.Fatalf("unexpected UDP remote: %s", remote.dialAddress)
	}
	if !remote.preserveDNS {
		t.Fatal("expected fake-ip domain to preserve Tailscale DNS")
	}
	if remote.writeAddr.String() != rawDst.String() || remote.readAddr.String() != rawDst.String() {
		t.Fatalf("expected raw destination for packet addr, write=%s read=%s", remote.writeAddr, remote.readAddr)
	}
}

func TestTailscaleResolveUDPRemoteUsesIPWithoutHost(t *testing.T) {
	metadata := &C.Metadata{
		NetWork: C.UDP,
		DstIP:   netip.MustParseAddr("100.64.0.10"),
		DstPort: 53,
	}

	remote, err := tailscaleUDPRemoteForMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if remote.dialAddress != "100.64.0.10:53" {
		t.Fatalf("unexpected UDP remote: %s", remote.dialAddress)
	}
	if remote.preserveDNS {
		t.Fatal("ip-only UDP destination should not preserve Tailscale DNS")
	}
	if remote.writeAddr.String() != remote.dialAddress || remote.readAddr.String() != remote.dialAddress {
		t.Fatalf("unexpected packet addr, write=%s read=%s", remote.writeAddr, remote.readAddr)
	}
}

func TestTailscalePacketConnDialsPerUDPRemote(t *testing.T) {
	dialer := &fakeTailscaleDialer{}
	pc := newTailscalePacketConn("ts-main", dialer.Dial)

	first := &C.Metadata{NetWork: C.UDP, Host: "alpha.example.ts.net", DstPort: 53}
	if err := pc.ResolveUDP(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	firstAddr := first.UDPAddr()
	if firstAddr == nil {
		t.Fatal("first metadata was not assigned a UDP write address")
	}

	second := &C.Metadata{NetWork: C.UDP, Host: "beta.example.ts.net", DstPort: 5353}
	if err := pc.ResolveUDP(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	secondAddr := second.UDPAddr()
	if secondAddr == nil {
		t.Fatal("second metadata was not assigned a UDP write address")
	}

	if _, err := pc.WriteTo([]byte("a"), firstAddr); err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo([]byte("b"), secondAddr); err != nil {
		t.Fatal(err)
	}

	got := dialer.Addresses()
	want := []string{"alpha.example.ts.net:53", "beta.example.ts.net:5353"}
	if len(got) != len(want) {
		t.Fatalf("unexpected dial count: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected dial addresses: got %v want %v", got, want)
		}
	}
}

func TestTailscalePacketConnInfersDomainForSameHostDifferentPort(t *testing.T) {
	dialer := &fakeTailscaleDialer{}
	pc := newTailscalePacketConn("ts-main", dialer.Dial)

	first := &C.Metadata{NetWork: C.UDP, Host: "alpha.example.ts.net", DstPort: 53}
	if err := pc.ResolveUDP(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	firstAddr := first.UDPAddr()
	if firstAddr == nil {
		t.Fatal("first metadata was not assigned a UDP write address")
	}
	secondAddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(firstAddr.AddrPort().Addr(), 5353))

	if _, err := pc.WriteTo([]byte("a"), firstAddr); err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo([]byte("b"), secondAddr); err != nil {
		t.Fatal(err)
	}

	got := dialer.Addresses()
	want := []string{"alpha.example.ts.net:53", "alpha.example.ts.net:5353"}
	if len(got) != len(want) {
		t.Fatalf("unexpected dial count: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected dial addresses: got %v want %v", got, want)
		}
	}
}

func TestTailscalePacketConnReturnsDomainReadAddr(t *testing.T) {
	dialer := &fakeTailscaleDialer{}
	pc := newTailscalePacketConn("ts-main", dialer.Dial)

	metadata := &C.Metadata{NetWork: C.UDP, Host: "alpha.example.ts.net", DstPort: 53}
	if err := pc.ResolveUDP(context.Background(), metadata); err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo([]byte("query"), metadata.UDPAddr()); err != nil {
		t.Fatal(err)
	}
	conn := dialer.Conn("alpha.example.ts.net:53")
	if conn == nil {
		t.Fatal("missing fake connection")
	}
	conn.PushRead([]byte("response"))

	buf := make([]byte, 64)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "response" {
		t.Fatalf("unexpected payload: %q", buf[:n])
	}
	if addr.String() != "alpha.example.ts.net:53" {
		t.Fatalf("unexpected read addr: %s", addr)
	}
}

func TestResolveTailscaleExitNode(t *testing.T) {
	status := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		key.NewNode().Public(): {
			ID:             tailcfg.StableNodeID("node-offline"),
			HostName:       "offline-gateway",
			DNSName:        "offline-gateway.example.ts.net.",
			ExitNodeOption: true,
			Online:         false,
		},
		key.NewNode().Public(): {
			ID:             tailcfg.StableNodeID("node-online"),
			HostName:       "exit-gateway",
			DNSName:        "exit-gateway.example.ts.net.",
			TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.10")},
			ExitNodeOption: true,
			Online:         true,
		},
	}}

	id, _, description, err := resolveTailscaleExitNode("exit-gateway.example.ts.net", status)
	if err != nil {
		t.Fatal(err)
	}
	if id != "node-online" || description != "exit-gateway.example.ts.net" {
		t.Fatalf("unexpected exit node: id=%s description=%s", id, description)
	}

	id, _, _, err = resolveTailscaleExitNode("offline-gateway", status)
	if err != nil {
		t.Fatal(err)
	}
	if id != "node-online" {
		t.Fatalf("expected fallback to online exit node, got %s", id)
	}

	_, ip, description, err := resolveTailscaleExitNode("100.64.0.10", status)
	if err != nil {
		t.Fatal(err)
	}
	if ip != netip.MustParseAddr("100.64.0.10") || description != "100.64.0.10" {
		t.Fatalf("unexpected exit node ip: ip=%s description=%s", ip, description)
	}
}

func TestResolveTailscaleExitNodeRejectsOfflineFallback(t *testing.T) {
	status := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		key.NewNode().Public(): {
			ID:             tailcfg.StableNodeID("node-offline"),
			HostName:       "offline-gateway",
			DNSName:        "offline-gateway.example.ts.net.",
			TailscaleIPs:   []netip.Addr{netip.MustParseAddr("100.64.0.10")},
			ExitNodeOption: true,
			Online:         false,
		},
	}}

	_, _, _, err := resolveTailscaleExitNode("offline-gateway", status)
	if err == nil {
		t.Fatal("expected no available exit node error")
	}
}

func viewsOfPrefixes(routes ...netip.Prefix) *views.Slice[netip.Prefix] {
	view := views.SliceOf(routes)
	return &view
}

type fakeStateStore struct {
	values map[ipn.StateKey][]byte
}

func (s fakeStateStore) ReadState(id ipn.StateKey) ([]byte, error) {
	value, ok := s.values[id]
	if !ok {
		return nil, ipn.ErrStateNotExist
	}
	return value, nil
}

func (s fakeStateStore) WriteState(id ipn.StateKey, value []byte) error {
	s.values[id] = value
	return nil
}

type fakeTailscaleDialer struct {
	mu    sync.Mutex
	addrs []string
	conns map[string]*fakeTailscaleConn
}

func (d *fakeTailscaleDialer) Dial(_ context.Context, _ string, address string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conns == nil {
		d.conns = make(map[string]*fakeTailscaleConn)
	}
	conn := newFakeTailscaleConn(address)
	d.addrs = append(d.addrs, address)
	d.conns[address] = conn
	return conn, nil
}

func (d *fakeTailscaleDialer) Addresses() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

func (d *fakeTailscaleDialer) Conn(address string) *fakeTailscaleConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conns[address]
}

type fakeTailscaleConn struct {
	address string
	reads   chan []byte
	writes  bytes.Buffer
	closed  chan struct{}
}

func newFakeTailscaleConn(address string) *fakeTailscaleConn {
	return &fakeTailscaleConn{
		address: address,
		reads:   make(chan []byte, 1),
		closed:  make(chan struct{}),
	}
}

func (c *fakeTailscaleConn) Read(b []byte) (int, error) {
	select {
	case data := <-c.reads:
		return copy(b, data), nil
	case <-c.closed:
		return 0, io.ErrClosedPipe
	}
}

func (c *fakeTailscaleConn) Write(b []byte) (int, error) {
	return c.writes.Write(b)
}

func (c *fakeTailscaleConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *fakeTailscaleConn) LocalAddr() net.Addr {
	return tailscalePacketAddr("local")
}

func (c *fakeTailscaleConn) RemoteAddr() net.Addr {
	return tailscalePacketAddr(c.address)
}

func (c *fakeTailscaleConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *fakeTailscaleConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *fakeTailscaleConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func (c *fakeTailscaleConn) PushRead(data []byte) {
	c.reads <- data
}
