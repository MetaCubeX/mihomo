package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

type ResolvePreference int

const (
	ResolvePreferenceDefault = ResolvePreference(iota)
	ResolvePreferenceIPv4
	ResolvePreferenceIPv6
	ResolvePreferenceIPv4OrIPv6
	ResolvePreferenceIPv6OrIPv4

	ResolveTimeout = 8 * time.Second
)

var (
	errNoIPv4Addr = errors.New("no IPv4 address")
	errNoIPv6Addr = errors.New("no IPv6 address")
	errNoAddr     = errors.New("no address")
)

func resolveIPAddrWithPreference(host string, pref ResolvePreference) (*net.IPAddr, error) {
	if pref == ResolvePreferenceDefault {
		return net.ResolveIPAddr("ip", host)
	}
	ctx, cancel := context.WithTimeout(context.Background(), ResolveTimeout)
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	cancel()
	if err != nil {
		return nil, err
	}
	var ip4, ip6 *net.IPAddr
	for i := range ips {
		ip := &ips[i]
		is4 := ip.IP.To4() != nil
		if ip4 == nil && is4 {
			ip4 = ip
		} else if ip6 == nil && !is4 {
			ip6 = ip
		}
		if ip4 != nil && ip6 != nil {
			break
		}
	}
	switch pref {
	case ResolvePreferenceIPv4:
		if ip4 == nil {
			return nil, errNoIPv4Addr
		}
		return ip4, nil
	case ResolvePreferenceIPv6:
		if ip6 == nil {
			return nil, errNoIPv6Addr
		}
		return ip6, nil
	case ResolvePreferenceIPv4OrIPv6:
		if ip4 == nil {
			if ip6 == nil {
				return nil, errNoAddr
			} else {
				return ip6, nil
			}
		}
		return ip4, nil
	case ResolvePreferenceIPv6OrIPv4:
		if ip6 == nil {
			if ip4 == nil {
				return nil, errNoAddr
			} else {
				return ip4, nil
			}
		}
		return ip6, nil
	}
	return nil, errNoAddr
}

func ResolvePreferenceFromString(preference string) (ResolvePreference, error) {
	switch preference {
	case "4":
		return ResolvePreferenceIPv4, nil
	case "6":
		return ResolvePreferenceIPv6, nil
	case "46":
		return ResolvePreferenceIPv4OrIPv6, nil
	case "64":
		return ResolvePreferenceIPv6OrIPv4, nil
	default:
		return ResolvePreferenceDefault, fmt.Errorf("invalid preference: %s", preference)
	}
}
