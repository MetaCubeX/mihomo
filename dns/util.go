package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/Dreamacro/clash/common/cache"
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
			ret = append(ret, &quicClient{addr: s.Addr})
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

func msgToIP(msg *D.Msg) []net.IP {
	ips := []net.IP{}

	for _, answer := range msg.Answer {
		switch ans := answer.(type) {
		case *D.AAAA:
			ips = append(ips, ans.AAAA)
		case *D.A:
			ips = append(ips, ans.A)
		}
	}

	return ips
}

func ipToAddr(ip net.IP) netip.Addr {
	if ip == nil {
		return netip.Addr{}
	}

	l := len(ip)

	if l == 4 {
		return netip.AddrFrom4(*(*[4]byte)(ip))
	} else if l == 16 {
		return netip.AddrFrom16(*(*[16]byte)(ip))
	} else {
		return netip.Addr{}
	}
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

func dialContextWithProxyAdapter(ctx context.Context, adapterName string, network string, dstIP net.IP, port string, opts ...dialer.Option) (net.Conn, error) {
	adapter, ok := tunnel.Proxies()[adapterName]
	if !ok {
		return nil, fmt.Errorf("proxy adapter [%s] not found", adapterName)
	}

	networkType := C.TCP
	if network == "udp" {
		if !adapter.SupportUDP() {
			return nil, fmt.Errorf("proxy adapter [%s] UDP is not supported", adapterName)
		}
		networkType = C.UDP
	}

	addrType := C.AtypIPv4
	if dstIP.To4() == nil {
		addrType = C.AtypIPv6
	}

	metadata := &C.Metadata{
		NetWork:  networkType,
		AddrType: addrType,
		Host:     "",
		DstIP:    dstIP,
		DstPort:  port,
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
