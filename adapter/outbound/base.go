package outbound

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"syscall"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
)

type Base struct {
	name   string
	addr   string
	iface  string
	tp     C.AdapterType
	udp    bool
	xudp   bool
	tfo    bool
	mpTcp  bool
	rmark  int
	id     string
	prefer C.DNSPrefer
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

// StreamConnContext implements C.ProxyAdapter
func (b *Base) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	return c, C.ErrNotSupport
}

func (b *Base) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	return nil, C.ErrNotSupport
}

// DialContextWithDialer implements C.ProxyAdapter
func (b *Base) DialContextWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.Conn, err error) {
	return nil, C.ErrNotSupport
}

// ListenPacketContext implements C.ProxyAdapter
func (b *Base) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	return nil, C.ErrNotSupport
}

// ListenPacketWithDialer implements C.ProxyAdapter
func (b *Base) ListenPacketWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.PacketConn, err error) {
	return nil, C.ErrNotSupport
}

// SupportWithDialer implements C.ProxyAdapter
func (b *Base) SupportWithDialer() C.NetWork {
	return C.InvalidNet
}

// SupportUOT implements C.ProxyAdapter
func (b *Base) SupportUOT() bool {
	return false
}

// SupportUDP implements C.ProxyAdapter
func (b *Base) SupportUDP() bool {
	return b.udp
}

// SupportXUDP implements C.ProxyAdapter
func (b *Base) SupportXUDP() bool {
	return b.xudp
}

// SupportTFO implements C.ProxyAdapter
func (b *Base) SupportTFO() bool {
	return b.tfo
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
func (b *Base) DialOptions(opts ...dialer.Option) []dialer.Option {
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

type BasicOption struct {
	TFO         bool   `proxy:"tfo,omitempty" group:"tfo,omitempty"`
	MPTCP       bool   `proxy:"mptcp,omitempty" group:"mptcp,omitempty"`
	Interface   string `proxy:"interface-name,omitempty" group:"interface-name,omitempty"`
	RoutingMark int    `proxy:"routing-mark,omitempty" group:"routing-mark,omitempty"`
	IPVersion   string `proxy:"ip-version,omitempty" group:"ip-version,omitempty"`
	DialerProxy string `proxy:"dialer-proxy,omitempty"` // don't apply this option into groups, but can set a group name in a proxy
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
	chain                   C.Chain
	actualRemoteDestination string
}

func (c *conn) RemoteDestination() string {
	return c.actualRemoteDestination
}

// Chains implements C.Connection
func (c *conn) Chains() C.Chain {
	return c.chain
}

// AppendToChains implements C.Connection
func (c *conn) AppendToChains(a C.ProxyAdapter) {
	c.chain = append(c.chain, a.Name())
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

func NewConn(c net.Conn, a C.ProxyAdapter) C.Conn {
	if _, ok := c.(syscall.Conn); !ok { // exclusion system conn like *net.TCPConn
		c = N.NewDeadlineConn(c) // most conn from outbound can't handle readDeadline correctly
	}
	return &conn{N.NewExtendedConn(c), []string{a.Name()}, parseRemoteDestination(a.Addr())}
}

type packetConn struct {
	N.EnhancePacketConn
	chain                   C.Chain
	adapterName             string
	connID                  string
	actualRemoteDestination string
}

func (c *packetConn) RemoteDestination() string {
	return c.actualRemoteDestination
}

// Chains implements C.Connection
func (c *packetConn) Chains() C.Chain {
	return c.chain
}

// AppendToChains implements C.Connection
func (c *packetConn) AppendToChains(a C.ProxyAdapter) {
	c.chain = append(c.chain, a.Name())
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

func newPacketConn(pc net.PacketConn, a C.ProxyAdapter) C.PacketConn {
	epc := N.NewEnhancePacketConn(pc)
	if _, ok := pc.(syscall.Conn); !ok { // exclusion system conn like *net.UDPConn
		epc = N.NewDeadlineEnhancePacketConn(epc) // most conn from outbound can't handle readDeadline correctly
	}
	return &packetConn{epc, []string{a.Name()}, a.Name(), utils.NewUUIDV4().String(), parseRemoteDestination(a.Addr())}
}

func parseRemoteDestination(addr string) string {
	if dst, _, err := net.SplitHostPort(addr); err == nil {
		return dst
	} else {
		if addrError, ok := err.(*net.AddrError); ok && strings.Contains(addrError.Err, "missing port") {
			return dst
		} else {
			return ""
		}
	}
}
