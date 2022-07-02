package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/common/nnip"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel"

	D "github.com/miekg/dns"
)

func putMsgToCache(c *cache.LruCache[string, *D.Msg], key string, msg *D.Msg) {
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
			ret = append(ret, newDoHClient(s.Addr, resolver, s.ProxyAdapter))
			continue
		case "dhcp":
			ret = append(ret, newDHCPClient(s.Addr))
			continue
		case "quic":
			ret = append(ret, newDOQ(resolver, s.Addr, s.ProxyAdapter))
			continue
		}

		host, port, _ := net.SplitHostPort(s.Addr)
		ret = append(ret, &client{
			Client: &D.Client{
				Net: s.Net,
				TLSConfig: &tls.Config{
					// alpn identifier, see https://tools.ietf.org/html/draft-hoffman-dprive-dns-tls-alpn-00#page-6
					NextProtos: []string{"dns"},
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

type wrapPacketConn struct {
	net.PacketConn
	rAddr net.Addr
}

func (wpc *wrapPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = wpc.PacketConn.ReadFrom(b)
	return n, err
}

func (wpc *wrapPacketConn) Write(b []byte) (n int, err error) {
	return wpc.PacketConn.WriteTo(b, wpc.rAddr)
}

func (wpc *wrapPacketConn) RemoteAddr() net.Addr {
	return wpc.rAddr
}

func (wpc *wrapPacketConn) LocalAddr() net.Addr {
	if wpc.PacketConn.LocalAddr() == nil {
		return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	} else {
		return wpc.PacketConn.LocalAddr()
	}
}

func dialContextExtra(ctx context.Context, adapterName string, network string, dstIP netip.Addr, port string, opts ...dialer.Option) (net.Conn, error) {
	networkType := C.TCP
	if network == "udp" {

		networkType = C.UDP
	}

	addrType := C.AtypIPv4
	if dstIP.Is6() {
		addrType = C.AtypIPv6
	}

	metadata := &C.Metadata{
		NetWork:  networkType,
		AddrType: addrType,
		Host:     "",
		DstIP:    dstIP,
		DstPort:  port,
	}

	adapter, ok := tunnel.Proxies()[adapterName]
	if !ok {
		opts = append(opts, dialer.WithInterface(adapterName))
		if C.TCP == networkType {
			return dialer.DialContext(ctx, network, dstIP.String()+":"+port, opts...)
		} else {
			packetConn, err := dialer.ListenPacket(ctx, network, dstIP.String()+":"+port, opts...)
			if err != nil {
				return nil, err
			}

			return &wrapPacketConn{
				PacketConn: packetConn,
				rAddr:      metadata.UDPAddr(),
			}, nil

		}
	}

	if networkType == C.UDP && !adapter.SupportUDP() {
		return nil, fmt.Errorf("proxy adapter [%s] UDP is not supported", adapterName)
	}

	if networkType == C.UDP {
		packetConn, err := adapter.ListenPacketContext(ctx, metadata, opts...)
		if err != nil {
			return nil, err
		}

		return &wrapPacketConn{
			PacketConn: packetConn,
			rAddr:      metadata.UDPAddr(),
		}, nil
	}

	return adapter.DialContext(ctx, metadata, opts...)
}
