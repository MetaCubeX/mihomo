package resolver

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/Dreamacro/clash/common/nnip"
	"github.com/Dreamacro/clash/component/trie"
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
	DefaultHosts = trie.New[netip.Addr]()

	// DefaultDNSTimeout defined the default dns request timeout
	DefaultDNSTimeout = time.Second * 5
)

var (
	ErrIPNotFound   = errors.New("couldn't find ip")
	ErrIPVersion    = errors.New("ip version error")
	ErrIPv6Disabled = errors.New("ipv6 disabled")
)

type Resolver interface {
	ResolveIP(host string, random bool) (ip netip.Addr, err error)
	ResolveIPv4(host string, random bool) (ip netip.Addr, err error)
	ResolveIPv6(host string, random bool) (ip netip.Addr, err error)
}

// ResolveIPv4 with a host, return ipv4
func ResolveIPv4(host string) (netip.Addr, error) {
	return resolveIPv4(host, true)
}

func ResolveIPv4WithResolver(host string, r Resolver, random bool) (netip.Addr, error) {
	if node := DefaultHosts.Search(host); node != nil {
		if ip := node.Data; ip.Is4() {
			return ip, nil
		}
	}

	ip, err := netip.ParseAddr(host)
	if err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			return ip, nil
		}
		return netip.Addr{}, ErrIPVersion
	}

	if r != nil {
		return r.ResolveIPv4(host, random)
	}

	if DefaultResolver == nil {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultDNSTimeout)
		defer cancel()
		ipAddrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if err != nil {
			return netip.Addr{}, err
		} else if len(ipAddrs) == 0 {
			return netip.Addr{}, ErrIPNotFound
		}

		index := 0
		if random {
			index = rand.Intn(len(ipAddrs))
		}
		ip := ipAddrs[index].To4()
		if ip == nil {
			return netip.Addr{}, ErrIPVersion
		}

		return netip.AddrFrom4(*(*[4]byte)(ip)), nil
	}

	return netip.Addr{}, ErrIPNotFound
}

// ResolveIPv6 with a host, return ipv6
func ResolveIPv6(host string) (netip.Addr, error) {
	return ResolveIPv6WithResolver(host, DefaultResolver, true)
}

func ResolveIPv6WithResolver(host string, r Resolver, random bool) (netip.Addr, error) {
	if DisableIPv6 {
		return netip.Addr{}, ErrIPv6Disabled
	}

	if node := DefaultHosts.Search(host); node != nil {
		if ip := node.Data; ip.Is6() {
			return ip, nil
		}
	}

	ip, err := netip.ParseAddr(host)
	if err == nil {
		if ip.Is6() {
			return ip, nil
		}
		return netip.Addr{}, ErrIPVersion
	}

	if r != nil {
		return r.ResolveIPv6(host, random)
	}

	if DefaultResolver == nil {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultDNSTimeout)
		defer cancel()
		ipAddrs, err := net.DefaultResolver.LookupIP(ctx, "ip6", host)
		if err != nil {
			return netip.Addr{}, err
		} else if len(ipAddrs) == 0 {
			return netip.Addr{}, ErrIPNotFound
		}

		index := 0
		if random {
			index = rand.Intn(len(ipAddrs))
		}
		return netip.AddrFrom16(*(*[16]byte)(ipAddrs[index])), nil
	}

	return netip.Addr{}, ErrIPNotFound
}

// ResolveIPWithResolver same as ResolveIP, but with a resolver
func ResolveIPWithResolver(host string, r Resolver, random bool) (netip.Addr, error) {
	if node := DefaultHosts.Search(host); node != nil {
		return node.Data, nil
	}

	if r != nil {
		if DisableIPv6 {
			return r.ResolveIPv4(host, random)
		}
		return r.ResolveIP(host, random)
	} else if DisableIPv6 {
		return resolveIPv4(host, random)
	}

	ip, err := netip.ParseAddr(host)
	if err == nil {
		return ip, nil
	}

	if DefaultResolver == nil {
		ipAddr, err := net.ResolveIPAddr("ip", host)
		if err != nil {
			return netip.Addr{}, err
		}

		return nnip.IpToAddr(ipAddr.IP), nil
	}

	return netip.Addr{}, ErrIPNotFound
}

// ResolveIP with a host, return ip
func ResolveIP(host string) (netip.Addr, error) {
	return resolveIP(host, true)
}

// ResolveFirstIP with a host, return ip
func ResolveFirstIP(host string) (netip.Addr, error) {
	return resolveIP(host, false)
}

// ResolveIPv4ProxyServerHost proxies server host only
func ResolveIPv4ProxyServerHost(host string) (netip.Addr, error) {
	if ProxyServerHostResolver != nil {
		return ResolveIPv4WithResolver(host, ProxyServerHostResolver, true)
	}
	return ResolveIPv4(host)
}

// ResolveIPv6ProxyServerHost proxies server host only
func ResolveIPv6ProxyServerHost(host string) (netip.Addr, error) {
	if ProxyServerHostResolver != nil {
		return ResolveIPv6WithResolver(host, ProxyServerHostResolver, true)
	}
	return ResolveIPv6(host)
}

// ResolveProxyServerHost proxies server host only
func ResolveProxyServerHost(host string) (netip.Addr, error) {
	if ProxyServerHostResolver != nil {
		return ResolveIPWithResolver(host, ProxyServerHostResolver, true)
	}
	return ResolveIP(host)
}

func resolveIP(host string, random bool) (netip.Addr, error) {
	return ResolveIPWithResolver(host, DefaultResolver, random)
}

func resolveIPv4(host string, random bool) (netip.Addr, error) {
	return ResolveIPv4WithResolver(host, DefaultResolver, random)
}
