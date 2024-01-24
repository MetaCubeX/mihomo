package constant

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/dialer"
)

// Adapter Type
const (
	Direct AdapterType = iota
	Reject
	RejectDrop
	Compatible
	Pass

	Relay
	Selector
	Fallback
	URLTest
	LoadBalance

	Shadowsocks
	ShadowsocksR
	Snell
	Socks5
	Http
	Vmess
	Vless
	Trojan
	Hysteria
	Hysteria2
	WireGuard
	Tuic
)

const (
	DefaultTCPTimeout = dialer.DefaultTCPTimeout
	DefaultUDPTimeout = dialer.DefaultUDPTimeout
	DefaultDropTime   = 12 * DefaultTCPTimeout
	DefaultTLSTimeout = DefaultTCPTimeout
	DefaultTestURL    = "https://www.gstatic.com/generate_204"
)

var ErrNotSupport = errors.New("no support")

type Connection interface {
	Chains() Chain
	AppendToChains(adapter ProxyAdapter)
	RemoteDestination() string
}

type Chain []string

func (c Chain) String() string {
	switch len(c) {
	case 0:
		return ""
	case 1:
		return c[0]
	default:
		return fmt.Sprintf("%s[%s]", c[len(c)-1], c[0])
	}
}

func (c Chain) Last() string {
	switch len(c) {
	case 0:
		return ""
	default:
		return c[0]
	}
}

type Conn interface {
	N.ExtendedConn
	Connection
}

type PacketConn interface {
	N.EnhancePacketConn
	Connection
	// Deprecate WriteWithMetadata because of remote resolve DNS cause TURN failed
	// WriteWithMetadata(p []byte, metadata *Metadata) (n int, err error)
}

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error)
}

type ProxyAdapter interface {
	Name() string
	Type() AdapterType
	Addr() string
	SupportUDP() bool
	SupportXUDP() bool
	SupportTFO() bool
	MarshalJSON() ([]byte, error)

	// Deprecated: use DialContextWithDialer and ListenPacketWithDialer instead.
	// StreamConn wraps a protocol around net.Conn with Metadata.
	//
	// Examples:
	//	conn, _ := net.DialContext(context.Background(), "tcp", "host:port")
	//	conn, _ = adapter.StreamConnContext(context.Background(), conn, metadata)
	//
	// It returns a C.Conn with protocol which start with
	// a new session (if any)
	StreamConnContext(ctx context.Context, c net.Conn, metadata *Metadata) (net.Conn, error)

	// DialContext return a C.Conn with protocol which
	// contains multiplexing-related reuse logic (if any)
	DialContext(ctx context.Context, metadata *Metadata, opts ...dialer.Option) (Conn, error)
	ListenPacketContext(ctx context.Context, metadata *Metadata, opts ...dialer.Option) (PacketConn, error)

	// SupportUOT return UDP over TCP support
	SupportUOT() bool

	SupportWithDialer() NetWork
	DialContextWithDialer(ctx context.Context, dialer Dialer, metadata *Metadata) (Conn, error)
	ListenPacketWithDialer(ctx context.Context, dialer Dialer, metadata *Metadata) (PacketConn, error)

	// IsL3Protocol return ProxyAdapter working in L3 (tell dns module not pass the domain to avoid loopback)
	IsL3Protocol(metadata *Metadata) bool

	// Unwrap extracts the proxy from a proxy-group. It returns nil when nothing to extract.
	Unwrap(metadata *Metadata, touch bool) Proxy
}

type Group interface {
	URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (mp map[string]uint16, err error)
	GetProxies(touch bool) []Proxy
	Touch()
}

type DelayHistory struct {
	Time  time.Time `json:"time"`
	Delay uint16    `json:"delay"`
}

type ProxyState struct {
	Alive   bool           `json:"alive"`
	History []DelayHistory `json:"history"`
}

type DelayHistoryStoreType int

type Proxy interface {
	ProxyAdapter
	AliveForTestUrl(url string) bool
	DelayHistory() []DelayHistory
	ExtraDelayHistories() map[string]ProxyState
	LastDelayForTestUrl(url string) uint16
	URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error)

	// Deprecated: use DialContext instead.
	Dial(metadata *Metadata) (Conn, error)

	// Deprecated: use DialPacketConn instead.
	DialUDP(metadata *Metadata) (PacketConn, error)
}

// AdapterType is enum of adapter type
type AdapterType int

func (at AdapterType) String() string {
	switch at {
	case Direct:
		return "Direct"
	case Reject:
		return "Reject"
	case RejectDrop:
		return "RejectDrop"
	case Compatible:
		return "Compatible"
	case Pass:
		return "Pass"
	case Shadowsocks:
		return "Shadowsocks"
	case ShadowsocksR:
		return "ShadowsocksR"
	case Snell:
		return "Snell"
	case Socks5:
		return "Socks5"
	case Http:
		return "Http"
	case Vmess:
		return "Vmess"
	case Vless:
		return "Vless"
	case Trojan:
		return "Trojan"
	case Hysteria:
		return "Hysteria"
	case Hysteria2:
		return "Hysteria2"
	case WireGuard:
		return "WireGuard"
	case Tuic:
		return "Tuic"

	case Relay:
		return "Relay"
	case Selector:
		return "Selector"
	case Fallback:
		return "Fallback"
	case URLTest:
		return "URLTest"
	case LoadBalance:
		return "LoadBalance"

	default:
		return "Unknown"
	}
}

// UDPPacket contains the data of UDP packet, and offers control/info of UDP packet's source
type UDPPacket interface {
	// Data get the payload of UDP Packet
	Data() []byte

	// WriteBack writes the payload with source IP/Port equals addr
	// - variable source IP/Port is important to STUN
	// - if addr is not provided, WriteBack will write out UDP packet with SourceIP/Port equals to original Target,
	//   this is important when using Fake-IP.
	WriteBack

	// Drop call after packet is used, could recycle buffer in this function.
	Drop()

	// LocalAddr returns the source IP/Port of packet
	LocalAddr() net.Addr
}

type UDPPacketInAddr interface {
	InAddr() net.Addr
}

// PacketAdapter is a UDP Packet adapter for socks/redir/tun
type PacketAdapter interface {
	UDPPacket
	Metadata() *Metadata
}

type packetAdapter struct {
	UDPPacket
	metadata *Metadata
}

// Metadata returns destination metadata
func (s *packetAdapter) Metadata() *Metadata {
	return s.metadata
}

func NewPacketAdapter(packet UDPPacket, metadata *Metadata) PacketAdapter {
	return &packetAdapter{
		packet,
		metadata,
	}
}

type WriteBack interface {
	WriteBack(b []byte, addr net.Addr) (n int, err error)
}

type WriteBackProxy interface {
	WriteBack
	UpdateWriteBack(wb WriteBack)
}

type NatTable interface {
	Set(key string, e PacketConn, w WriteBackProxy)

	Get(key string) (PacketConn, WriteBackProxy)

	GetOrCreateLock(key string) (*sync.Cond, bool)

	Delete(key string)

	DeleteLock(key string)

	GetForLocalConn(lAddr, rAddr string) *net.UDPConn

	AddForLocalConn(lAddr, rAddr string, conn *net.UDPConn) bool

	RangeForLocalConn(lAddr string, f func(key string, value *net.UDPConn) bool)

	GetOrCreateLockForLocalConn(lAddr string, key string) (*sync.Cond, bool)

	DeleteForLocalConn(lAddr, key string)

	DeleteLockForLocalConn(lAddr, key string)
}
