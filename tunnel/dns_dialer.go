package tunnel

// WARNING: all function in this file should only be using in dns module

import (
	"context"
	"fmt"
	"net"
	"strings"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

const DnsRespectRules = "RULES"

type DNSDialer struct {
	r            resolver.Resolver
	proxyAdapter C.ProxyAdapter
	proxyName    string
	opts         []dialer.Option
}

func NewDNSDialer(r resolver.Resolver, proxyAdapter C.ProxyAdapter, proxyName string, opts ...dialer.Option) *DNSDialer {
	return &DNSDialer{r: r, proxyAdapter: proxyAdapter, proxyName: proxyName, opts: opts}
}

func (d *DNSDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	r := d.r
	proxyName := d.proxyName
	proxyAdapter := d.proxyAdapter
	opts := d.opts
	var rule C.Rule
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.INNER,
	}
	err := metadata.SetRemoteAddress(addr) // tcp can resolve host by remote
	if err != nil {
		return nil, err
	}
	if !strings.Contains(network, "tcp") {
		metadata.NetWork = C.UDP
		if !metadata.Resolved() {
			// udp must resolve host first
			dstIP, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, r)
			if err != nil {
				return nil, err
			}
			metadata.DstIP = dstIP
		}
	}

	if proxyAdapter == nil && len(proxyName) != 0 {
		if proxyName == DnsRespectRules {
			if !metadata.Resolved() {
				// resolve here before resolveMetadata to avoid its inner resolver.ResolveIP
				dstIP, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, r)
				if err != nil {
					return nil, err
				}
				metadata.DstIP = dstIP
			}
			proxyAdapter, rule, err = resolveMetadata(metadata)
			if err != nil {
				return nil, err
			}
		} else {
			var ok bool
			proxyAdapter, ok = Proxies()[proxyName]
			if !ok {
				opts = append(opts, dialer.WithInterface(proxyName))
			}
		}
	}

	if metadata.NetWork == C.TCP {
		if proxyAdapter == nil {
			opts = append(opts, dialer.WithResolver(r))
			return dialer.DialContext(ctx, network, addr, opts...)
		}

		if proxyAdapter.IsL3Protocol(metadata) { // L3 proxy should resolve domain before to avoid loopback
			if !metadata.Resolved() {
				dstIP, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, r)
				if err != nil {
					return nil, err
				}
				metadata.DstIP = dstIP
			}
			metadata.Host = "" // clear host to avoid double resolve in proxy
		}

		conn, err := proxyAdapter.DialContext(ctx, metadata, opts...)
		if err != nil {
			logMetadataErr(metadata, rule, proxyAdapter, err)
			return nil, err
		}
		logMetadata(metadata, rule, conn)

		conn = statistic.NewTCPTracker(conn, statistic.DefaultManager, metadata, rule, 0, 0, false)

		return conn, nil
	} else {
		if proxyAdapter == nil {
			return dialer.DialContext(ctx, network, metadata.AddrPort().String(), opts...)
		}

		if !proxyAdapter.SupportUDP() {
			return nil, fmt.Errorf("proxy adapter [%s] UDP is not supported", proxyAdapter)
		}

		packetConn, err := proxyAdapter.ListenPacketContext(ctx, metadata, opts...)
		if err != nil {
			logMetadataErr(metadata, rule, proxyAdapter, err)
			return nil, err
		}
		logMetadata(metadata, rule, packetConn)

		packetConn = statistic.NewUDPTracker(packetConn, statistic.DefaultManager, metadata, rule, 0, 0, false)

		return N.NewBindPacketConn(packetConn, metadata.UDPAddr()), nil
	}

}

func (d *DNSDialer) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	r := d.r
	proxyAdapter := d.proxyAdapter
	proxyName := d.proxyName
	opts := d.opts
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.INNER,
	}
	err := metadata.SetRemoteAddress(addr)
	if err != nil {
		return nil, err
	}
	if !metadata.Resolved() {
		// udp must resolve host first
		dstIP, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, r)
		if err != nil {
			return nil, err
		}
		metadata.DstIP = dstIP
	}

	var rule C.Rule
	if proxyAdapter == nil {
		if proxyName == DnsRespectRules {
			proxyAdapter, rule, err = resolveMetadata(metadata)
			if err != nil {
				return nil, err
			}
		} else {
			var ok bool
			proxyAdapter, ok = Proxies()[proxyName]
			if !ok {
				opts = append(opts, dialer.WithInterface(proxyName))
			}
		}
	}

	if proxyAdapter == nil {
		return dialer.NewDialer(opts...).ListenPacket(ctx, network, "", metadata.AddrPort())
	}

	if !proxyAdapter.SupportUDP() {
		return nil, fmt.Errorf("proxy adapter [%s] UDP is not supported", proxyAdapter)
	}

	packetConn, err := proxyAdapter.ListenPacketContext(ctx, metadata, opts...)
	if err != nil {
		logMetadataErr(metadata, rule, proxyAdapter, err)
		return nil, err
	}
	logMetadata(metadata, rule, packetConn)

	packetConn = statistic.NewUDPTracker(packetConn, statistic.DefaultManager, metadata, rule, 0, 0, false)

	return packetConn, nil
}
