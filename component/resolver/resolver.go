package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/trie"

	"github.com/miekg/dns"
	"github.com/zhangyunhao116/fastrand"
)

var (
	// DefaultResolver aim to resolve ip
	DefaultResolver Resolver

	// ProxyServerHostResolver resolve ip to proxies server host
	ProxyServerHostResolver Resolver

	// DisableIPv6 means don't resolve ipv6 host
	// default value is true
	DisableIPv6 = true

	// DefaultHosts aim to resolve hosts
	DefaultHosts = NewHosts(trie.New[HostValue]())

	// DefaultDNSTimeout defined the default dns request timeout
	DefaultDNSTimeout = time.Second * 5
)

var (
	ErrIPNotFound   = errors.New("couldn't find ip")
	ErrIPVersion    = errors.New("ip version error")
	ErrIPv6Disabled = errors.New("ipv6 disabled")
)

type Resolver interface {
	LookupIP(ctx context.Context, host string) (ips []netip.Addr, err error)
	LookupIPv4(ctx context.Context, host string) (ips []netip.Addr, err error)
	LookupIPv6(ctx context.Context, host string) (ips []netip.Addr, err error)
	ExchangeContext(ctx context.Context, m *dns.Msg) (msg *dns.Msg, err error)
	Invalid() bool
}

// LookupIPv4WithResolver same as LookupIPv4, but with a resolver
func LookupIPv4WithResolver(ctx context.Context, host string, r Resolver) ([]netip.Addr, error) {
	if node, ok := DefaultHosts.Search(host, false); ok {
		if addrs := utils.Filter(node.IPs, func(ip netip.Addr) bool {
			return ip.Is4()
		}); len(addrs) > 0 {
			return addrs, nil
		}
	}

	ip, err := netip.ParseAddr(host)
	if err == nil {
		if ip.Is4() || ip.Is4In6() {
			return []netip.Addr{ip}, nil
		}
		return []netip.Addr{}, ErrIPVersion
	}

	if r != nil && r.Invalid() {
		return r.LookupIPv4(ctx, host)
	}

	ipAddrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	} else if len(ipAddrs) == 0 {
		return nil, ErrIPNotFound
	}

	return ipAddrs, nil
}

// LookupIPv4 with a host, return ipv4 list
func LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return LookupIPv4WithResolver(ctx, host, DefaultResolver)
}

// ResolveIPv4WithResolver same as ResolveIPv4, but with a resolver
func ResolveIPv4WithResolver(ctx context.Context, host string, r Resolver) (netip.Addr, error) {
	ips, err := LookupIPv4WithResolver(ctx, host, r)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[fastrand.Intn(len(ips))], nil
}

// ResolveIPv4 with a host, return ipv4
func ResolveIPv4(ctx context.Context, host string) (netip.Addr, error) {
	return ResolveIPv4WithResolver(ctx, host, DefaultResolver)
}

// LookupIPv6WithResolver same as LookupIPv6, but with a resolver
func LookupIPv6WithResolver(ctx context.Context, host string, r Resolver) ([]netip.Addr, error) {
	if DisableIPv6 {
		return nil, ErrIPv6Disabled
	}

	if node, ok := DefaultHosts.Search(host, false); ok {
		if addrs := utils.Filter(node.IPs, func(ip netip.Addr) bool {
			return ip.Is6()
		}); len(addrs) > 0 {
			return addrs, nil
		}
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		if strings.Contains(host, ":") {
			return []netip.Addr{ip}, nil
		}
		return nil, ErrIPVersion
	}

	if r != nil && r.Invalid() {
		return r.LookupIPv6(ctx, host)
	}

	ipAddrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip6", host)
	if err != nil {
		return nil, err
	} else if len(ipAddrs) == 0 {
		return nil, ErrIPNotFound
	}

	return ipAddrs, nil
}

// LookupIPv6 with a host, return ipv6 list
func LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return LookupIPv6WithResolver(ctx, host, DefaultResolver)
}

// ResolveIPv6WithResolver same as ResolveIPv6, but with a resolver
func ResolveIPv6WithResolver(ctx context.Context, host string, r Resolver) (netip.Addr, error) {
	ips, err := LookupIPv6WithResolver(ctx, host, r)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[fastrand.Intn(len(ips))], nil
}

func ResolveIPv6(ctx context.Context, host string) (netip.Addr, error) {
	return ResolveIPv6WithResolver(ctx, host, DefaultResolver)
}

// LookupIPWithResolver same as LookupIP, but with a resolver
func LookupIPWithResolver(ctx context.Context, host string, r Resolver) ([]netip.Addr, error) {
	if node, ok := DefaultHosts.Search(host, false); ok {
		return node.IPs, nil
	}

	if r != nil && r.Invalid() {
		if DisableIPv6 {
			return r.LookupIPv4(ctx, host)
		}
		return r.LookupIP(ctx, host)
	} else if DisableIPv6 {
		return LookupIPv4WithResolver(ctx, host, r)
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	} else if len(ips) == 0 {
		return nil, ErrIPNotFound
	}

	return ips, nil
}

// LookupIP with a host, return ip
func LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return LookupIPWithResolver(ctx, host, DefaultResolver)
}

// ResolveIPWithResolver same as ResolveIP, but with a resolver
func ResolveIPWithResolver(ctx context.Context, host string, r Resolver) (netip.Addr, error) {
	ips, err := LookupIPWithResolver(ctx, host, r)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	ipv4s, ipv6s := SortationAddr(ips)
	if len(ipv4s) > 0 {
		return ipv4s[fastrand.Intn(len(ipv4s))], nil
	}
	return ipv6s[fastrand.Intn(len(ipv6s))], nil
}

// ResolveIP with a host, return ip and priority return TypeA
func ResolveIP(ctx context.Context, host string) (netip.Addr, error) {
	return ResolveIPWithResolver(ctx, host, DefaultResolver)
}

// ResolveIPv4ProxyServerHost proxies server host only
func ResolveIPv4ProxyServerHost(ctx context.Context, host string) (netip.Addr, error) {
	if ProxyServerHostResolver != nil {
		if ip, err := ResolveIPv4WithResolver(ctx, host, ProxyServerHostResolver); err != nil {
			return ResolveIPv4(ctx, host)
		} else {
			return ip, nil
		}
	}
	return ResolveIPv4(ctx, host)
}

// ResolveIPv6ProxyServerHost proxies server host only
func ResolveIPv6ProxyServerHost(ctx context.Context, host string) (netip.Addr, error) {
	if ProxyServerHostResolver != nil {
		if ip, err := ResolveIPv6WithResolver(ctx, host, ProxyServerHostResolver); err != nil {
			return ResolveIPv6(ctx, host)
		} else {
			return ip, nil
		}
	}
	return ResolveIPv6(ctx, host)
}

// ResolveProxyServerHost proxies server host only
func ResolveProxyServerHost(ctx context.Context, host string) (netip.Addr, error) {
	if ProxyServerHostResolver != nil {
		if ip, err := ResolveIPWithResolver(ctx, host, ProxyServerHostResolver); err != nil {
			return ResolveIP(ctx, host)
		} else {
			return ip, err
		}
	}
	return ResolveIP(ctx, host)
}

func LookupIPv6ProxyServerHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if ProxyServerHostResolver != nil {
		return LookupIPv6WithResolver(ctx, host, ProxyServerHostResolver)
	}
	return LookupIPv6(ctx, host)
}

func LookupIPv4ProxyServerHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if ProxyServerHostResolver != nil {
		return LookupIPv4WithResolver(ctx, host, ProxyServerHostResolver)
	}
	return LookupIPv4(ctx, host)
}

func LookupIPProxyServerHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if ProxyServerHostResolver != nil {
		return LookupIPWithResolver(ctx, host, ProxyServerHostResolver)
	}
	return LookupIP(ctx, host)
}

func SortationAddr(ips []netip.Addr) (ipv4s, ipv6s []netip.Addr) {
	for _, v := range ips {
		if v.Unmap().Is4() {
			ipv4s = append(ipv4s, v)
		} else {
			ipv6s = append(ipv6s, v)
		}
	}
	return
}
