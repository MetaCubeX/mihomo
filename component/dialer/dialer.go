package dialer

import (
	"context"
	"errors"
	"net"

	"github.com/Dreamacro/clash/component/resolver"
)

func Dialer() *net.Dialer {
	dialer := &net.Dialer{}
	if DialerHook != nil {
		DialerHook(dialer)
	}

	return dialer
}

func ListenConfig() *net.ListenConfig {
	cfg := &net.ListenConfig{}
	if ListenConfigHook != nil {
		ListenConfigHook(cfg)
	}

	return cfg
}

func Dial(network, address string) (net.Conn, error) {
	return DialContext(context.Background(), network, address)
}

func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp4", "tcp6", "udp4", "udp6":
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}

		dialer := Dialer()

		var ip net.IP
		switch network {
		case "tcp4", "udp4":
			ip, err = resolver.ResolveIPv4(host)
		default:
			ip, err = resolver.ResolveIPv6(host)
		}

		if err != nil {
			return nil, err
		}

		if DialHook != nil {
			DialHook(dialer, network, ip)
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	case "tcp", "udp":
		return dualStackDailContext(ctx, network, address)
	default:
		return nil, errors.New("network invalid")
	}
}

func ListenPacket(network, address string) (net.PacketConn, error) {
	lc := ListenConfig()

	if ListenPacketHook != nil && address == "" {
		ip := ListenPacketHook()
		if ip != nil {
			address = net.JoinHostPort(ip.String(), "0")
		}
	}
	return lc.ListenPacket(context.Background(), network, address)
}

func dualStackDailContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	returned := make(chan struct{})
	defer close(returned)

	type dialResult struct {
		net.Conn
		error
		resolved bool
		ipv6     bool
		done     bool
	}
	results := make(chan dialResult)
	var primary, fallback dialResult

	startRacer := func(ctx context.Context, network, host string, ipv6 bool) {
		dialer := Dialer()
		result := dialResult{ipv6: ipv6, done: true}
		defer func() {
			select {
			case results <- result:
			case <-returned:
				if result.Conn != nil {
					result.Conn.Close()
				}
			}
		}()

		var ip net.IP
		if ipv6 {
			ip, result.error = resolver.ResolveIPv6(host)
		} else {
			ip, result.error = resolver.ResolveIPv4(host)
		}
		if result.error != nil {
			return
		}
		result.resolved = true

		if DialHook != nil {
			DialHook(dialer, network, ip)
		}
		result.Conn, result.error = dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}

	go startRacer(ctx, network+"4", host, false)
	go startRacer(ctx, network+"6", host, true)

	for {
		select {
		case res := <-results:
			if res.error == nil {
				return res.Conn, nil
			}

			if !res.ipv6 {
				primary = res
			} else {
				fallback = res
			}

			if primary.done && fallback.done {
				if primary.resolved {
					return nil, primary.error
				} else if fallback.resolved {
					return nil, fallback.error
				} else {
					return nil, primary.error
				}
			}
		}
	}
}
