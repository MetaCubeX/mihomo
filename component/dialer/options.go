package dialer

import (
	"context"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/resolver"
	"go4.org/netipx"
)

var (
	// DefaultInterface is the explicitly configured global interface. It takes
	// precedence over the proxy-endpoint route-exclusion and auto-detection
	// fallbacks.
	DefaultInterface   = atomic.NewTypedValue[string]("")
	DefaultRoutingMark = atomic.NewInt32(0)

	// DefaultInterfaceFinder is the final interface-selection fallback when no
	// explicit interface is configured and the proxy endpoint is not excluded
	// from TUN routes.
	DefaultInterfaceFinder = atomic.NewTypedValue[InterfaceFinder](nil)

	// ProxyEndpointRouteExcludeSet contains TUN route exclusions. It is only
	// consulted by dialers explicitly marked with WithProxyEndpointRouteExclude.
	// A matching endpoint falls back to the system route instead of automatic
	// interface detection, but does not override an explicitly configured
	// interface.
	ProxyEndpointRouteExcludeSet = atomic.NewTypedValue[*netipx.IPSet](nil)
)

type InterfaceFinder interface {
	FindInterfaceName(destination netip.Addr) string
}

type NetDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type NetDialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f NetDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

type option struct {
	interfaceName             string
	fallbackBind              bool
	addrReuse                 bool
	routingMark               int
	network                   int
	prefer                    int
	tfo                       bool
	mpTcp                     bool
	resolver                  resolver.Resolver
	netDialer                 NetDialer
	proxyEndpointRouteExclude bool
}

type Option func(opt *option)

func WithInterface(name string) Option {
	return func(opt *option) {
		opt.interfaceName = name
	}
}

func WithFallbackBind(fallback bool) Option {
	return func(opt *option) {
		opt.fallbackBind = fallback
	}
}

func WithAddrReuse(reuse bool) Option {
	return func(opt *option) {
		opt.addrReuse = reuse
	}
}

func WithRoutingMark(mark int) Option {
	return func(opt *option) {
		opt.routingMark = mark
	}
}

func WithResolver(r resolver.Resolver) Option {
	return func(opt *option) {
		opt.resolver = r
	}
}

func WithPreferIPv4() Option {
	return func(opt *option) {
		opt.prefer = 4
	}
}

func WithPreferIPv6() Option {
	return func(opt *option) {
		opt.prefer = 6
	}
}

func WithOnlySingleStack(isIPv4 bool) Option {
	return func(opt *option) {
		if isIPv4 {
			opt.network = 4
		} else {
			opt.network = 6
		}
	}
}

func WithTFO(tfo bool) Option {
	return func(opt *option) {
		opt.tfo = tfo
	}
}

func WithMPTCP(mpTcp bool) Option {
	return func(opt *option) {
		opt.mpTcp = mpTcp
	}
}

func WithNetDialer(netDialer NetDialer) Option {
	return func(opt *option) {
		opt.netDialer = netDialer
	}
}

// WithProxyEndpointRouteExclude makes this proxy-endpoint dialer fall back to
// the system route table when its destination is excluded from active TUN
// routes. It takes precedence over automatic interface detection, but not over
// an explicitly configured interface. Ordinary direct and DNS dialers must not
// use it.
func WithProxyEndpointRouteExclude() Option {
	return func(opt *option) {
		opt.proxyEndpointRouteExclude = true
	}
}

func WithOption(o option) Option {
	return func(opt *option) {
		*opt = o
	}
}

func WithOptions(options ...Option) Option {
	return func(opt *option) {
		for _, o := range options {
			o(opt)
		}
	}
}

func IsZeroOptions(opts []Option) bool {
	return applyOptions(opts...) == option{}
}

func applyOptions(options ...Option) option {
	opt := option{}
	for _, o := range options {
		o(&opt)
	}
	return opt
}
