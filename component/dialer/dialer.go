package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/Dreamacro/clash/component/resolver"
)

var (
	dialMux                    sync.Mutex
	actualSingleDialContext    = singleDialContext
	actualDualStackDialContext = dualStackDialContext
	tcpConcurrent              = false
	DisableIPv6                = false
)

func DialContext(ctx context.Context, network, address string, options ...Option) (net.Conn, error) {
	opt := &option{
		interfaceName: DefaultInterface.Load(),
		routingMark:   int(DefaultRoutingMark.Load()),
	}

	for _, o := range DefaultOptions {
		o(opt)
	}

	for _, o := range options {
		o(opt)
	}

	switch network {
	case "tcp4", "tcp6", "udp4", "udp6":
		return actualSingleDialContext(ctx, network, address, opt)
	case "tcp", "udp":
		return actualDualStackDialContext(ctx, network, address, opt)
	default:
		return nil, errors.New("network invalid")
	}
}

func ListenPacket(ctx context.Context, network, address string, options ...Option) (net.PacketConn, error) {
	cfg := &option{
		interfaceName: DefaultInterface.Load(),
		routingMark:   int(DefaultRoutingMark.Load()),
	}

	for _, o := range DefaultOptions {
		o(cfg)
	}

	for _, o := range options {
		o(cfg)
	}

	if DisableIPv6 {
		network = "udp4"
	}

	lc := &net.ListenConfig{}
	if cfg.interfaceName != "" {
		addr, err := bindIfaceToListenConfig(cfg.interfaceName, lc, network, address)
		if err != nil {
			return nil, err
		}
		address = addr
	}
	if cfg.addrReuse {
		addrReuseToListenConfig(lc)
	}
	if cfg.routingMark != 0 {
		bindMarkToListenConfig(cfg.routingMark, lc, network, address)
	}

	return lc.ListenPacket(ctx, network, address)
}

func SetDial(concurrent bool) {
	dialMux.Lock()
	tcpConcurrent = concurrent
	if concurrent {
		actualSingleDialContext = concurrentSingleDialContext
		actualDualStackDialContext = concurrentDualStackDialContext
	} else {
		actualSingleDialContext = singleDialContext
		actualDualStackDialContext = dualStackDialContext
	}

	dialMux.Unlock()
}

func GetDial() bool {
	return tcpConcurrent
}

func dialContext(ctx context.Context, network string, destination netip.Addr, port string, opt *option) (net.Conn, error) {
	dialer := &net.Dialer{}
	if opt.interfaceName != "" {
		if err := bindIfaceToDialer(opt.interfaceName, dialer, network, destination); err != nil {
			return nil, err
		}
	}
	if opt.routingMark != 0 {
		bindMarkToDialer(opt.routingMark, dialer, network, destination)
	}

	if DisableIPv6 && destination.Is6() {
		return nil, fmt.Errorf("IPv6 is diabled, dialer cancel")
	}

	return dialer.DialContext(ctx, network, net.JoinHostPort(destination.String(), port))
}

func dualStackDialContext(ctx context.Context, network, address string, opt *option) (net.Conn, error) {
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

	startRacer := func(ctx context.Context, network, host string, direct bool, ipv6 bool) {
		result := dialResult{ipv6: ipv6, done: true}
		defer func() {
			select {
			case results <- result:
			case <-returned:
				if result.Conn != nil {
					_ = result.Conn.Close()
				}
			}
		}()

		var ip netip.Addr
		if ipv6 {
			if !direct {
				ip, result.error = resolver.ResolveIPv6ProxyServerHost(host)
			} else {
				ip, result.error = resolver.ResolveIPv6(host)
			}
		} else {
			if !direct {
				ip, result.error = resolver.ResolveIPv4ProxyServerHost(host)
			} else {
				ip, result.error = resolver.ResolveIPv4(host)
			}
		}
		if result.error != nil {
			return
		}
		result.resolved = true

		result.Conn, result.error = dialContext(ctx, network, ip, port, opt)
	}

	go startRacer(ctx, network+"4", host, opt.direct, false)
	go startRacer(ctx, network+"6", host, opt.direct, true)

	for res := range results {
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

	return nil, errors.New("never touched")
}

func concurrentDualStackDialContext(ctx context.Context, network, address string, opt *option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var ips []netip.Addr

	if opt.direct {
		ips, err = resolver.ResolveAllIP(host)
	} else {
		ips, err = resolver.ResolveAllIPProxyServerHost(host)
	}

	return concurrentDialContext(ctx, network, ips, port, opt)
}

func concurrentDialContext(ctx context.Context, network string, ips []netip.Addr, port string, opt *option) (net.Conn, error) {
	returned := make(chan struct{})
	defer close(returned)

	type dialResult struct {
		ip netip.Addr
		net.Conn
		error
		resolved bool
	}

	results := make(chan dialResult)

	tcpRacer := func(ctx context.Context, ip netip.Addr) {
		result := dialResult{ip: ip}

		defer func() {
			select {
			case results <- result:
			case <-returned:
				if result.Conn != nil {
					result.Conn.Close()
				}
			}
		}()

		v := "4"
		if ip.Is6() {
			v = "6"
		}

		result.Conn, result.error = dialContext(ctx, network+v, ip, port, opt)
	}

	for _, ip := range ips {
		go tcpRacer(ctx, ip)
	}

	connCount := len(ips)
	for res := range results {
		connCount--
		if res.error == nil {
			return res.Conn, nil
		}

		if connCount == 0 {
			break
		}
	}

	return nil, fmt.Errorf("all ips %v tcp shake hands failed", ips)
}

func singleDialContext(ctx context.Context, network string, address string, opt *option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var ip netip.Addr
	switch network {
	case "tcp4", "udp4":
		if !opt.direct {
			ip, err = resolver.ResolveIPv4ProxyServerHost(host)
		} else {
			ip, err = resolver.ResolveIPv4(host)
		}
	default:
		if !opt.direct {
			ip, err = resolver.ResolveIPv6ProxyServerHost(host)
		} else {
			ip, err = resolver.ResolveIPv6(host)
		}
	}
	if err != nil {
		return nil, err
	}

	return dialContext(ctx, network, ip, port, opt)
}

func concurrentSingleDialContext(ctx context.Context, network string, address string, opt *option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var ips []netip.Addr
	switch network {
	case "tcp4", "udp4":
		if !opt.direct {
			ips, err = resolver.ResolveAllIPv4ProxyServerHost(host)
		} else {
			ips, err = resolver.ResolveAllIPv4(host)
		}
	default:
		if !opt.direct {
			ips, err = resolver.ResolveAllIPv6ProxyServerHost(host)
		} else {
			ips, err = resolver.ResolveAllIPv6(host)
		}
	}

	if err != nil {
		return nil, err
	}

	return concurrentDialContext(ctx, network, ips, port, opt)
}
