package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"

	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"

	"github.com/gofrs/uuid"
)

type Base struct {
	name   string
	addr   string
	iface  string
	tp     C.AdapterType
	udp    bool
	xudp   bool
	tfo    bool
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
		id, err := uuid.NewV6()
		if err != nil {
			b.id = b.name
		} else {
			b.id = id.String()
		}
	}

	return b.id
}

// Type implements C.ProxyAdapter
func (b *Base) Type() C.AdapterType {
	return b.tp
}

// StreamConn implements C.ProxyAdapter
func (b *Base) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	return c, errors.New("no support")
}

func (b *Base) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	return nil, errors.New("no support")
}

// DialContextWithDialer implements C.ProxyAdapter
func (b *Base) DialContextWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.Conn, err error) {
	return nil, errors.New("no support")
}

// ListenPacketContext implements C.ProxyAdapter
func (b *Base) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	return nil, errors.New("no support")
}

// ListenPacketWithDialer implements C.ProxyAdapter
func (b *Base) ListenPacketWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.PacketConn, err error) {
	return nil, errors.New("no support")
}

// SupportWithDialer implements C.ProxyAdapter
func (b *Base) SupportWithDialer() bool {
	return false
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

	return opts
}

type BasicOption struct {
	Interface   string `proxy:"interface-name,omitempty" group:"interface-name,omitempty"`
	RoutingMark int    `proxy:"routing-mark,omitempty" group:"routing-mark,omitempty"`
	IPVersion   string `proxy:"ip-version,omitempty" group:"ip-version,omitempty"`
}

type BaseOption struct {
	Name        string
	Addr        string
	Type        C.AdapterType
	UDP         bool
	XUDP        bool
	TFO         bool
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

func NewConn(c net.Conn, a C.ProxyAdapter) C.Conn {
	return &conn{N.NewExtendedConn(c), []string{a.Name()}, parseRemoteDestination(a.Addr())}
}

type packetConn struct {
	net.PacketConn
	chain                   C.Chain
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

func newPacketConn(pc net.PacketConn, a C.ProxyAdapter) C.PacketConn {
	return &packetConn{pc, []string{a.Name()}, parseRemoteDestination(a.Addr())}
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
