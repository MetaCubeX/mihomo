package resolver

import (
	"errors"
	"net"
	"strings"

	"github.com/Dreamacro/clash/component/trie"
)

var (
	// DefaultResolver aim to resolve ip
	DefaultResolver Resolver

	// DisableIPv6 means don't resolve ipv6 host
	// default value is true
	DisableIPv6 = true

	// DefaultHosts aim to resolve hosts
	DefaultHosts = trie.New()
)

var (
	ErrIPNotFound   = errors.New("couldn't find ip")
	ErrIPVersion    = errors.New("ip version error")
	ErrIPv6Disabled = errors.New("ipv6 disabled")
)

type Resolver interface {
	ResolveIP(host string) (ip net.IP, err error)
	ResolveIPv4(host string) (ip net.IP, err error)
	ResolveIPv6(host string) (ip net.IP, err error)
}

// ResolveIPv4 with a host, return ipv4
func ResolveIPv4(host string) (net.IP, error) {
	if node := DefaultHosts.Search(host); node != nil {
		if ip := node.Data.(net.IP).To4(); ip != nil {
			return ip, nil
		}
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if !strings.Contains(host, ":") {
			return ip, nil
		}
		return nil, ErrIPVersion
	}

	if DefaultResolver != nil {
		return DefaultResolver.ResolveIPv4(host)
	}

	ipAddrs, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	for _, ip := range ipAddrs {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}

	return nil, ErrIPNotFound
}

// ResolveIPv6 with a host, return ipv6
func ResolveIPv6(host string) (net.IP, error) {
	if DisableIPv6 {
		return nil, ErrIPv6Disabled
	}

	if node := DefaultHosts.Search(host); node != nil {
		if ip := node.Data.(net.IP).To16(); ip != nil {
			return ip, nil
		}
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if strings.Contains(host, ":") {
			return ip, nil
		}
		return nil, ErrIPVersion
	}

	if DefaultResolver != nil {
		return DefaultResolver.ResolveIPv6(host)
	}

	ipAddrs, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	for _, ip := range ipAddrs {
		if ip.To4() == nil {
			return ip, nil
		}
	}

	return nil, ErrIPNotFound
}

// ResolveIP with a host, return ip
func ResolveIP(host string) (net.IP, error) {
	if node := DefaultHosts.Search(host); node != nil {
		return node.Data.(net.IP), nil
	}

	if DefaultResolver != nil {
		if DisableIPv6 {
			return DefaultResolver.ResolveIPv4(host)
		}
		return DefaultResolver.ResolveIP(host)
	} else if DisableIPv6 {
		return ResolveIPv4(host)
	}

	ip := net.ParseIP(host)
	if ip != nil {
		return ip, nil
	}

	ipAddr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, err
	}

	return ipAddr.IP, nil
}
