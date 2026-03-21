package outbound

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"sync"
	"syscall"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type ProxyAdapter interface {
	C.ProxyAdapter
	DialOptions() []dialer.Option
	ResolveUDP(ctx context.Context, metadata *C.Metadata) error
}

type Base struct {
	name   string
	addr   string
	tp     C.AdapterType
	pdName string
	udp    bool
	xudp   bool
	tfo    bool
	mpTcp  bool
	iface  string
	rmark  int
	prefer C.DNSPrefer
	dialer C.Dialer
	id     string
}

// Name implements C.ProxyAdapter
func (b *Base) Name() string {
	return b.name
}

// Id implements C.ProxyAdapter
func (b *Base) Id() string {
	if b.id == "" {
		b.id = utils.NewUUIDV6().String()
	}

	return b.id
}

// Type implements C.ProxyAdapter
func (b *Base) Type() C.AdapterType {
	return b.tp
}

func (b *Base) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	return nil, C.ErrNotSupport
}

// ListenPacketContext implements C.ProxyAdapter
func (b *Base) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	return nil, C.ErrNotSupport
}

// SupportUOT implements C.ProxyAdapter
func (b *Base) SupportUOT() bool {
	return false
}

// SupportUDP implements C.ProxyAdapter
func (b *Base) SupportUDP() bool {
	return b.udp
}

// ProxyInfo implements C.ProxyAdapter
func (b *Base) ProxyInfo() (info C.ProxyInfo) {
	info.XUDP = b.xudp
	info.TFO = b.tfo
	info.MPTCP = b.mpTcp
	info.SMUX = false
	info.Interface = b.iface
	info.RoutingMark = b.rmark
	info.ProviderName = b.pdName
	return
}

// IsL3Protocol implements C.ProxyAdapter
func (b *Base) IsL3Protocol(metadata *C.Metadata) bool {
	return false
}

// MarshalJSON implements C.ProxyAdapter
func (b *Base) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type": b.Type().String(),
		"id":   b.Id(),
	})
}

// Addr implements C.ProxyAdapter
func (b *Base) Addr() string {
	return b.addr
}

// Unwrap implements C.ProxyAdapter
func (b *Base) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return nil
}

// DialOptions return []dialer.Option from struct
func (b *Base) DialOptions() (opts []dialer.Option) {
	if b.iface != "" {
		opts = append(opts, dialer.WithInterface(b.iface))
	}

	if b.rmark != 0 {
		opts = append(opts, dialer.WithRoutingMark(b.rmark))
	}

	switch b.prefer {
	case C.IPv4Only:
		opts = append(opts, dialer.WithOnlySingleStack(true))
	case C.IPv6Only:
		opts = append(opts, dialer.WithOnlySingleStack(false))
	case C.IPv4Prefer:
		opts = append(opts, dialer.WithPreferIPv4())
	case C.IPv6Prefer:
		opts = append(opts, dialer.WithPreferIPv6())
	default:
	}

	if b.tfo {
		opts = append(opts, dialer.WithTFO(true))
	}

	if b.mpTcp {
		opts = append(opts, dialer.WithMPTCP(true))
	}

	return opts
}

func (b *Base) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if !metadata.Resolved() {
		ip, err := resolver.ResolveIP(ctx, metadata.Host)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

func (b *Base) Close() error {
	return nil
}

type BasicOption struct {
	TFO         bool        `proxy:"tfo,omitempty"`
	MPTCP       bool        `proxy:"mptcp,omitempty"`
	Interface   string      `proxy:"interface-name,omitempty"`
	RoutingMark int         `proxy:"routing-mark,omitempty"`
	IPVersion   C.DNSPrefer `proxy:"ip-version,omitempty"`
	DialerProxy string      `proxy:"dialer-proxy,omitempty"` // don't apply this option into groups, but can set a group name in a proxy

	//
	// The following parameters are used internally, assign value by the structure decoder are disallowed
	//
	DialerForAPI C.Dialer `proxy:"-"` // the dialer used for API usage has higher priority than all the above configurations.
	ProviderName string   `proxy:"-"`
}

func (b *BasicOption) NewDialer(opts []dialer.Option) C.Dialer {
	cDialer := b.DialerForAPI
	if cDialer == nil {
		if b.DialerProxy != "" {
			cDialer = proxydialer.NewByName(b.DialerProxy)
		} else {
			cDialer = dialer.NewDialer(opts...)
		}
	}
	return cDialer
}

type BaseOption struct {
	Name        string
	Addr        string
	Type        C.AdapterType
	UDP         bool
	XUDP        bool
	TFO         bool
	MPTCP       bool
	Interface   string
	RoutingMark int
	Prefer      C.DNSPrefer
}

func NewBase(opt BaseOption) *Base {
	return &Base{
		name:   opt.Name,
		addr:   opt.Addr,
		tp:     opt.Type,
		udp:    opt.UDP,
		xudp:   opt.XUDP,
		tfo:    opt.TFO,
		mpTcp:  opt.MPTCP,
		iface:  opt.Interface,
		rmark:  opt.RoutingMark,
		prefer: opt.Prefer,
	}
}

type conn struct {
	N.ExtendedConn
	chain       C.Chain
	pdChain     C.Chain
	adapterAddr string
}

func (c *conn) RemoteDestination() string {
	if remoteAddr := c.RemoteAddr(); remoteAddr != nil {
		m := C.Metadata{}
		if err := m.SetRemoteAddr(remoteAddr); err == nil {
			if m.Valid() {
				return m.String()
			}
		}
	}
	host, _, _ := net.SplitHostPort(c.adapterAddr)
	return host
}

// Chains implements C.Connection
func (c *conn) Chains() C.Chain {
	return c.chain
}

// ProviderChains implements C.Connection
func (c *conn) ProviderChains() C.Chain {
	return c.pdChain
}

// AppendToChains implements C.Connection
func (c *conn) AppendToChains(a C.ProxyAdapter) {
	c.chain = append(c.chain, a.Name())
	c.pdChain = append(c.pdChain, a.ProxyInfo().ProviderName)
}

func (c *conn) Upstream() any {
	return c.ExtendedConn
}

func (c *conn) WriterReplaceable() bool {
	return true
}

func (c *conn) ReaderReplaceable() bool {
	return true
}

func (c *conn) AddRef(ref any) {
	c.ExtendedConn = N.NewRefConn(c.ExtendedConn, ref) // add ref for autoCloseProxyAdapter
}

func NewConn(c net.Conn, a C.ProxyAdapter) C.Conn {
	if _, ok := c.(syscall.Conn); !ok { // exclusion system conn like *net.TCPConn
		c = N.NewDeadlineConn(c) // most conn from outbound can't handle readDeadline correctly
	}
	cc := &conn{N.NewExtendedConn(c), nil, nil, a.Addr()}
	cc.AppendToChains(a)
	return cc
}

type packetConn struct {
	N.EnhancePacketConn
	chain       C.Chain
	pdChain     C.Chain
	adapterName string
	connID      string
	adapterAddr string
	resolveUDP  func(ctx context.Context, metadata *C.Metadata) error
}

func (c *packetConn) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	return c.resolveUDP(ctx, metadata)
}

func (c *packetConn) RemoteDestination() string {
	host, _, _ := net.SplitHostPort(c.adapterAddr)
	return host
}

// Chains implements C.Connection
func (c *packetConn) Chains() C.Chain {
	return c.chain
}

// ProviderChains implements C.Connection
func (c *packetConn) ProviderChains() C.Chain {
	return c.pdChain
}

// AppendToChains implements C.Connection
func (c *packetConn) AppendToChains(a C.ProxyAdapter) {
	c.chain = append(c.chain, a.Name())
	c.pdChain = append(c.pdChain, a.ProxyInfo().ProviderName)
}

func (c *packetConn) LocalAddr() net.Addr {
	lAddr := c.EnhancePacketConn.LocalAddr()
	return N.NewCustomAddr(c.adapterName, c.connID, lAddr) // make quic-go's connMultiplexer happy
}

func (c *packetConn) Upstream() any {
	return c.EnhancePacketConn
}

func (c *packetConn) WriterReplaceable() bool {
	return true
}

func (c *packetConn) ReaderReplaceable() bool {
	return true
}

func (c *packetConn) AddRef(ref any) {
	c.EnhancePacketConn = N.NewRefPacketConn(c.EnhancePacketConn, ref) // add ref for autoCloseProxyAdapter
}

func newPacketConn(pc net.PacketConn, a ProxyAdapter) C.PacketConn {
	epc := N.NewEnhancePacketConn(pc)
	if _, ok := pc.(syscall.Conn); !ok { // exclusion system conn like *net.UDPConn
		epc = N.NewDeadlineEnhancePacketConn(epc) // most conn from outbound can't handle readDeadline correctly
	}
	cpc := &packetConn{epc, nil, nil, a.Name(), utils.NewUUIDV4().String(), a.Addr(), a.ResolveUDP}
	cpc.AppendToChains(a)
	return cpc
}

type AddRef interface {
	AddRef(ref any)
}

type autoCloseProxyAdapter struct {
	ProxyAdapter
	closeOnce sync.Once
	closeErr  error
}

func (p *autoCloseProxyAdapter) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := p.ProxyAdapter.DialContext(ctx, metadata)
	if err != nil {
		return nil, err
	}
	if c, ok := c.(AddRef); ok {
		c.AddRef(p)
	}
	return c, nil
}

func (p *autoCloseProxyAdapter) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	pc, err := p.ProxyAdapter.ListenPacketContext(ctx, metadata)
	if err != nil {
		return nil, err
	}
	if pc, ok := pc.(AddRef); ok {
		pc.AddRef(p)
	}
	return pc, nil
}

func (p *autoCloseProxyAdapter) Close() error {
	p.closeOnce.Do(func() {
		log.Debugln("Closing outdated proxy [%s]", p.Name())
		runtime.SetFinalizer(p, nil)
		p.closeErr = p.ProxyAdapter.Close()
	})
	return p.closeErr
}

func NewAutoCloseProxyAdapter(adapter ProxyAdapter) ProxyAdapter {
	proxy := &autoCloseProxyAdapter{
		ProxyAdapter: adapter,
	}
	// auto close ProxyAdapter
	runtime.SetFinalizer(proxy, (*autoCloseProxyAdapter).Close)
	return proxy
}
