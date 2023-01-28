package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/Dreamacro/clash/common/cache"
	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/nnip"
	"github.com/Dreamacro/clash/common/picker"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel"

	D "github.com/miekg/dns"
)

const (
	MaxMsgSize = 65535
)

func putMsgToCache(c *cache.LruCache[string, *D.Msg], key string, msg *D.Msg) {
	// skip dns cache for acme challenge
	if len(msg.Question) != 0 {
		if q := msg.Question[0]; q.Qtype == D.TypeTXT && strings.HasPrefix(q.Name, "_acme-challenge") {
			log.Debugln("[DNS] dns cache ignored because of acme challenge for: %s", q.Name)
			return
		}
	}
	var ttl uint32
	switch {
	case len(msg.Answer) != 0:
		ttl = msg.Answer[0].Header().Ttl
	case len(msg.Ns) != 0:
		ttl = msg.Ns[0].Header().Ttl
	case len(msg.Extra) != 0:
		ttl = msg.Extra[0].Header().Ttl
	default:
		log.Debugln("[DNS] response msg empty: %#v", msg)
		return
	}

	c.SetWithExpire(key, msg.Copy(), time.Now().Add(time.Second*time.Duration(ttl)))
}

func setMsgTTL(msg *D.Msg, ttl uint32) {
	for _, answer := range msg.Answer {
		answer.Header().Ttl = ttl
	}

	for _, ns := range msg.Ns {
		ns.Header().Ttl = ttl
	}

	for _, extra := range msg.Extra {
		extra.Header().Ttl = ttl
	}
}

func isIPRequest(q D.Question) bool {
	return q.Qclass == D.ClassINET && (q.Qtype == D.TypeA || q.Qtype == D.TypeAAAA)
}

func transform(servers []NameServer, resolver *Resolver) []dnsClient {
	ret := []dnsClient{}
	for _, s := range servers {
		switch s.Net {
		case "https":
			ret = append(ret, newDoHClient(s.Addr, resolver, s.PreferH3, s.Params, s.ProxyAdapter))
			continue
		case "dhcp":
			ret = append(ret, newDHCPClient(s.Addr))
			continue
		case "quic":
			if doq, err := newDoQ(resolver, s.Addr, s.ProxyAdapter); err == nil {
				ret = append(ret, doq)
			} else {
				log.Fatalln("DoQ format error: %v", err)
			}
			continue
		}

		host, port, _ := net.SplitHostPort(s.Addr)
		ret = append(ret, &client{
			Client: &D.Client{
				Net: s.Net,
				TLSConfig: &tls.Config{
					ServerName: host,
				},
				UDPSize: 4096,
				Timeout: 5 * time.Second,
			},
			port:         port,
			host:         host,
			iface:        s.Interface,
			r:            resolver,
			proxyAdapter: s.ProxyAdapter,
		})
	}
	return ret
}

func handleMsgWithEmptyAnswer(r *D.Msg) *D.Msg {
	msg := &D.Msg{}
	msg.Answer = []D.RR{}

	msg.SetRcode(r, D.RcodeSuccess)
	msg.Authoritative = true
	msg.RecursionAvailable = true

	return msg
}

func msgToIP(msg *D.Msg) []netip.Addr {
	ips := []netip.Addr{}

	for _, answer := range msg.Answer {
		switch ans := answer.(type) {
		case *D.AAAA:
			ips = append(ips, nnip.IpToAddr(ans.AAAA))
		case *D.A:
			ips = append(ips, nnip.IpToAddr(ans.A))
		}
	}

	return ips
}

func msgToDomain(msg *D.Msg) string {
	if len(msg.Question) > 0 {
		return strings.TrimRight(msg.Question[0].Name, ".")
	}

	return ""
}

type dialHandler func(ctx context.Context, network, addr string) (net.Conn, error)

func getDialHandler(r *Resolver, proxyAdapter string, opts ...dialer.Option) dialHandler {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if len(proxyAdapter) == 0 {
			opts = append(opts, dialer.WithResolver(r))
			return dialer.DialContext(ctx, network, addr, opts...)
		} else {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			adapter, ok := tunnel.Proxies()[proxyAdapter]
			if !ok {
				opts = append(opts, dialer.WithInterface(proxyAdapter))
			}
			if strings.Contains(network, "tcp") {
				// tcp can resolve host by remote
				metadata := &C.Metadata{
					NetWork: C.TCP,
					Host:    host,
					DstPort: port,
				}
				if ok {
					return adapter.DialContext(ctx, metadata, opts...)
				}
				opts = append(opts, dialer.WithResolver(r))
				return dialer.DialContext(ctx, network, addr, opts...)
			} else {
				// udp must resolve host first
				dstIP, err := resolver.ResolveIPWithResolver(ctx, host, r)
				if err != nil {
					return nil, err
				}
				metadata := &C.Metadata{
					NetWork: C.UDP,
					Host:    "",
					DstIP:   dstIP,
					DstPort: port,
				}
				if !ok {
					return dialer.DialContext(ctx, network, addr, opts...)
				}

				if !adapter.SupportUDP() {
					return nil, fmt.Errorf("proxy adapter [%s] UDP is not supported", proxyAdapter)
				}

				packetConn, err := adapter.ListenPacketContext(ctx, metadata, opts...)
				if err != nil {
					return nil, err
				}

				return N.NewBindPacketConn(packetConn, metadata.UDPAddr()), nil
			}
		}
	}
}

func listenPacket(ctx context.Context, proxyAdapter string, network string, addr string, r *Resolver, opts ...dialer.Option) (net.PacketConn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	adapter, ok := tunnel.Proxies()[proxyAdapter]
	if !ok && len(proxyAdapter) != 0 {
		opts = append(opts, dialer.WithInterface(proxyAdapter))
	}

	// udp must resolve host first
	dstIP, err := resolver.ResolveIPWithResolver(ctx, host, r)
	if err != nil {
		return nil, err
	}
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Host:    "",
		DstIP:   dstIP,
		DstPort: port,
	}
	if !ok {
		return dialer.ListenPacket(ctx, dialer.ParseNetwork(network, dstIP), "", opts...)
	}

	if !adapter.SupportUDP() {
		return nil, fmt.Errorf("proxy adapter [%s] UDP is not supported", proxyAdapter)
	}

	return adapter.ListenPacketContext(ctx, metadata, opts...)
}

func batchExchange(ctx context.Context, clients []dnsClient, m *D.Msg) (msg *D.Msg, err error) {
	fast, ctx := picker.WithTimeout[*D.Msg](ctx, resolver.DefaultDNSTimeout)
	domain := msgToDomain(m)
	for _, client := range clients {
		r := client
		fast.Go(func() (*D.Msg, error) {
			log.Debugln("[DNS] resolve %s from %s", domain, r.Address())
			m, err := r.ExchangeContext(ctx, m)
			if err != nil {
				return nil, err
			} else if m.Rcode == D.RcodeServerFailure || m.Rcode == D.RcodeRefused {
				return nil, errors.New("server failure")
			}
			log.Debugln("[DNS] %s --> %s, from %s", domain, msgToIP(m), r.Address())
			return m, nil
		})
	}

	elm := fast.Wait()
	if elm == nil {
		err := errors.New("all DNS requests failed")
		if fErr := fast.Error(); fErr != nil {
			err = fmt.Errorf("%w, first error: %s", err, fErr.Error())
		}
		return nil, err
	}
	msg = elm
	return
}
