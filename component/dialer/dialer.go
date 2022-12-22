package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"

	"github.com/Dreamacro/clash/component/resolver"

	"go.uber.org/atomic"
)

var (
	dialMux                    sync.Mutex
	actualSingleDialContext    = singleDialContext
	actualDualStackDialContext = dualStackDialContext
	tcpConcurrent              = false
	DisableIPv6                = false
	ErrorInvalidedNetworkStack = errors.New("invalided network stack")
	ErrorDisableIPv6           = errors.New("IPv6 is disabled, dialer cancel")
)

func ParseNetwork(network string, addr netip.Addr) string {
	if runtime.GOOS == "windows" { // fix bindIfaceToListenConfig() in windows force bind to an ipv4 address
		if !strings.HasSuffix(network, "4") &&
			!strings.HasSuffix(network, "6") &&
			addr.Unmap().Is6() {
			network += "6"
		}
	}
	return network
}

func applyOptions(options ...Option) *option {
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

	return opt
}

func DialContext(ctx context.Context, network, address string, options ...Option) (net.Conn, error) {
	opt := applyOptions(options...)

	if opt.network == 4 || opt.network == 6 {
		if strings.Contains(network, "tcp") {
			network = "tcp"
		} else {
			network = "udp"
		}

		network = fmt.Sprintf("%s%d", network, opt.network)
	}

	switch network {
	case "tcp4", "tcp6", "udp4", "udp6":
		return actualSingleDialContext(ctx, network, address, opt)
	case "tcp", "udp":
		return actualDualStackDialContext(ctx, network, address, opt)
	default:
		return nil, ErrorInvalidedNetworkStack
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
		return nil, ErrorDisableIPv6
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

	startRacer := func(ctx context.Context, network, host string, r resolver.Resolver, ipv6 bool) {
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
			if r == nil {
				ip, result.error = resolver.ResolveIPv6ProxyServerHost(ctx, host)
			} else {
				ip, result.error = resolver.ResolveIPv6WithResolver(ctx, host, r)
			}
		} else {
			if r == nil {
				ip, result.error = resolver.ResolveIPv4ProxyServerHost(ctx, host)
			} else {
				ip, result.error = resolver.ResolveIPv4WithResolver(ctx, host, r)
			}
		}
		if result.error != nil {
			return
		}
		result.resolved = true

		result.Conn, result.error = dialContext(ctx, network, ip, port, opt)
	}

	go startRacer(ctx, network+"4", host, opt.resolver, false)
	go startRacer(ctx, network+"6", host, opt.resolver, true)

	count := 2
	for i := 0; i < count; i++ {
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
		case <-ctx.Done():
			err = ctx.Err()
			break
		}
	}

	if err == nil {
		err = fmt.Errorf("dual stack dial failed")
	} else {
		err = fmt.Errorf("dual stack dial failed:%w", err)
	}
	return nil, err
}

func concurrentDualStackDialContext(ctx context.Context, network, address string, opt *option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var ips []netip.Addr
	if opt.resolver != nil {
		ips, err = resolver.LookupIPWithResolver(ctx, host, opt.resolver)
	} else {
		ips, err = resolver.LookupIPProxyServerHost(ctx, host)
	}

	if err != nil {
		return nil, err
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
		isPrimary bool
		done      bool
	}

	preferCount := atomic.NewInt32(0)
	results := make(chan dialResult)
	tcpRacer := func(ctx context.Context, ip netip.Addr) {
		result := dialResult{ip: ip, done: true}

		defer func() {
			select {
			case results <- result:
			case <-returned:
				if result.Conn != nil {
					_ = result.Conn.Close()
				}
			}
		}()
		if strings.Contains(network, "tcp") {
			network = "tcp"
		} else {
			network = "udp"
		}

		if ip.Is6() {
			network += "6"
			if opt.prefer != 4 {
				result.isPrimary = true
			}
		}

		if ip.Is4() {
			network += "4"
			if opt.prefer != 6 {
				result.isPrimary = true
			}
		}

		if result.isPrimary {
			preferCount.Add(1)
		}

		result.Conn, result.error = dialContext(ctx, network, ip, port, opt)
	}

	for _, ip := range ips {
		go tcpRacer(ctx, ip)
	}

	connCount := len(ips)
	var fallback dialResult
	var primaryError error
	var finalError error
	for i := 0; i < connCount; i++ {
		select {
		case res := <-results:
			if res.error == nil {
				if res.isPrimary {
					return res.Conn, nil
				} else {
					if !fallback.done || fallback.error != nil {
						fallback = res
					}
				}
			} else {
				if res.isPrimary {
					primaryError = res.error
					preferCount.Add(-1)
					if preferCount.Load() == 0 && fallback.done && fallback.error == nil {
						return fallback.Conn, nil
					}
				}
			}
		case <-ctx.Done():
			if fallback.done && fallback.error == nil {
				return fallback.Conn, nil
			}
			finalError = ctx.Err()
			break
		}
	}

	if fallback.done && fallback.error == nil {
		return fallback.Conn, nil
	}

	if primaryError != nil {
		return nil, primaryError
	}

	if fallback.error != nil {
		return nil, fallback.error
	}

	if finalError == nil {
		finalError = fmt.Errorf("all ips %v tcp shake hands failed", ips)
	} else {
		finalError = fmt.Errorf("concurrent dial failed:%w", finalError)
	}

	return nil, finalError
}

func singleDialContext(ctx context.Context, network string, address string, opt *option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var ip netip.Addr
	switch network {
	case "tcp4", "udp4":
		if opt.resolver == nil {
			ip, err = resolver.ResolveIPv4ProxyServerHost(ctx, host)
		} else {
			ip, err = resolver.ResolveIPv4WithResolver(ctx, host, opt.resolver)
		}
	default:
		if opt.resolver == nil {
			ip, err = resolver.ResolveIPv6ProxyServerHost(ctx, host)
		} else {
			ip, err = resolver.ResolveIPv6WithResolver(ctx, host, opt.resolver)
		}
	}
	if err != nil {
		return nil, err
	}

	return dialContext(ctx, network, ip, port, opt)
}

func concurrentSingleDialContext(ctx context.Context, network string, address string, opt *option) (net.Conn, error) {
	switch network {
	case "tcp4", "udp4":
		return concurrentIPv4DialContext(ctx, network, address, opt)
	default:
		return concurrentIPv6DialContext(ctx, network, address, opt)
	}
}

func concurrentIPv4DialContext(ctx context.Context, network, address string, opt *option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var ips []netip.Addr
	if opt.resolver == nil {
		ips, err = resolver.LookupIPv4ProxyServerHost(ctx, host)
	} else {
		ips, err = resolver.LookupIPv4WithResolver(ctx, host, opt.resolver)
	}

	if err != nil {
		return nil, err
	}

	return concurrentDialContext(ctx, network, ips, port, opt)
}

func concurrentIPv6DialContext(ctx context.Context, network, address string, opt *option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var ips []netip.Addr
	if opt.resolver == nil {
		ips, err = resolver.LookupIPv6ProxyServerHost(ctx, host)
	} else {
		ips, err = resolver.LookupIPv6WithResolver(ctx, host, opt.resolver)
	}

	if err != nil {
		return nil, err
	}

	return concurrentDialContext(ctx, network, ips, port, opt)
}

type Dialer struct {
	Opt option
}

func (d Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return DialContext(ctx, network, address, WithOption(d.Opt))
}

func (d Dialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	return ListenPacket(ctx, ParseNetwork(network, rAddrPort.Addr()), address, WithOption(d.Opt))
}

func NewDialer(options ...Option) Dialer {
	opt := applyOptions(options...)
	return Dialer{Opt: *opt}
}
