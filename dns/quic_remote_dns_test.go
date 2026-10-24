package dns

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
	D "github.com/miekg/dns"
)

type remoteDNSResolver struct {
	resolver.Resolver
	calls atomic.Int32
}

func (*remoteDNSResolver) Invalid() bool { return true }
func (r *remoteDNSResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	r.calls.Add(1)
	return nil, errors.New("local DNS disabled")
}

type quicDomainProxy struct {
	C.ProxyAdapter
	peer        net.Addr
	target      string
	writes      atomic.Int32
	domainReply bool
}

func (p *quicDomainProxy) ListenPacketContext(ctx context.Context, m *C.Metadata) (C.PacketConn, error) {
	if err := p.resolveUDP(ctx, m); err != nil {
		return nil, err
	}
	if m.UDPRemoteAddr().String() != p.target {
		return nil, fmt.Errorf("lost domain in DNS dialer: %v", m.UDPRemoteAddr())
	}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &quicProxyPacketConn{EnhancePacketConn: N.NewEnhancePacketConn(&quicDomainPacketConn{PacketConn: socket, proxy: p}), proxy: p}, nil
}

type quicDomainPacketConn struct {
	net.PacketConn
	proxy *quicDomainProxy
}

func (c *quicDomainPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if !M.SocksaddrFromNet(addr).IsFqdn() || addr.String() != c.proxy.target {
		return 0, fmt.Errorf("QUIC lost domain: %v", addr)
	}
	c.proxy.writes.Add(1)
	return c.PacketConn.WriteTo(b, c.proxy.peer)
}
func (c *quicDomainPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if c.proxy.domainReply && err == nil {
		addr = M.ParseSocksaddr(c.proxy.target)
	}
	return n, addr, err
}

func TestDNSQUICDomainUpstream(t *testing.T) {
	cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"doq", "h3"} {
		for _, domainReply := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/domainReply=%v", protocol, domainReply), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				socket, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer socket.Close()
				serverTLS := &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{NextProtoDQ, "h3"}}
				serverErr := make(chan error, 1)
				if protocol == "doq" {
					listener, err := quic.Listen(socket, serverTLS, &quic.Config{})
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					go func() {
						serverErr <- func() error {
							conn, err := listener.Accept(ctx)
							if err != nil {
								return err
							}
							defer conn.CloseWithError(0, "")
							stream, err := conn.AcceptStream(ctx)
							if err != nil {
								return err
							}
							var length uint16
							if err = binary.Read(stream, binary.BigEndian, &length); err != nil {
								return err
							}
							data := make([]byte, length)
							if _, err = io.ReadFull(stream, data); err != nil {
								return err
							}
							var query D.Msg
							if err = query.Unpack(data); err != nil {
								return err
							}
							response := new(D.Msg)
							response.SetReply(&query)
							data, err = response.Pack()
							if err != nil {
								return err
							}
							if err = binary.Write(stream, binary.BigEndian, uint16(len(data))); err != nil {
								return err
							}
							if _, err = stream.Write(data); err != nil {
								return err
							}
							if err = stream.Close(); err != nil {
								return err
							}
							<-conn.Context().Done()
							return nil
						}()
					}()
				} else {
					server := &http3.Server{TLSConfig: serverTLS, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						data, err := io.ReadAll(r.Body)
						if r.Method == http.MethodGet {
							data, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
						}
						if err != nil {
							w.WriteHeader(400)
							return
						}
						var query D.Msg
						if err = query.Unpack(data); err != nil {
							w.WriteHeader(400)
							return
						}
						response := new(D.Msg)
						response.SetReply(&query)
						data, _ = response.Pack()
						w.Header().Set("Content-Type", "application/dns-message")
						w.Write(data)
					})}
					defer server.Close()
					go func() { _ = server.Serve(socket) }()
				}
				r := &remoteDNSResolver{}

				proxy := &quicDomainProxy{peer: socket.LocalAddr(), target: "remote-only.invalid:853", domainReply: domainReply}
				query := new(D.Msg)
				query.SetQuestion("example.org.", D.TypeA)
				var response *D.Msg
				if protocol == "doq" {
					client := newDoQ(proxy.target, r, map[string]string{"skip-cert-verify": "true"}, proxy, "")
					defer client.Close()
					response, err = client.ExchangeContext(ctx, query)
					client.Close()
					if err == nil {
						select {
						case err = <-serverErr:
						case <-ctx.Done():
							err = ctx.Err()
						}
					}
				} else {
					client := newDoHClient("https://"+proxy.target+"/dns-query", r, false, map[string]string{"skip-cert-verify": "true", "h3": "true"}, proxy, "").(*dnsOverHTTPS)
					defer client.Close()
					client.httpVersions = []C.HTTPVersion{C.HTTPVersion11, C.HTTPVersion3}
					// The UDP QUIC probe succeeds while the unsupported TCP proxy probe fails.
					addr, probeErr := client.probeH3(ctx, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}})
					if probeErr != nil || addr != proxy.target {
						t.Fatalf("probe: %s %v", addr, probeErr)
					}
					client.httpVersions = []C.HTTPVersion{C.HTTPVersion3}
					response, err = client.ExchangeContext(ctx, query)
				}
				if err != nil {
					t.Fatal(err)
				}
				if response == nil || !response.Response || response.Id != query.Id {
					t.Fatalf("wrong DNS response: %v", response)
				}
				if r.calls.Load() != 0 || proxy.writes.Load() == 0 {
					t.Fatalf("DNS calls=%d QUIC writes=%d", r.calls.Load(), proxy.writes.Load())
				}
			})
		}
	}
}

func (*quicDomainProxy) Name() string                     { return "quic-domain-test" }
func (*quicDomainProxy) Type() C.AdapterType              { return C.Socks5 }
func (*quicDomainProxy) SupportUDP() bool                 { return true }
func (*quicDomainProxy) ProxyInfo() C.ProxyInfo           { return C.ProxyInfo{UDPRemoteDNS: true} }
func (*quicDomainProxy) Unwrap(*C.Metadata, bool) C.Proxy { return nil }
func (*quicDomainProxy) IsL3Protocol(*C.Metadata) bool    { return false }
func (*quicDomainProxy) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	return nil, errors.New("TCP unavailable")
}
func (*quicDomainProxy) resolveUDP(_ context.Context, m *C.Metadata) error {
	if m.Host == "" {
		return errors.New("remote DNS not enabled")
	}
	m.DstIP = netip.Addr{}
	return nil
}

type quicProxyPacketConn struct {
	N.EnhancePacketConn
	proxy *quicDomainProxy
}

func (c *quicProxyPacketConn) Chains() C.Chain             { return C.Chain{c.proxy.Name()} }
func (*quicProxyPacketConn) ProviderChains() C.Chain       { return nil }
func (*quicProxyPacketConn) AppendToChains(C.ProxyAdapter) {}
func (c *quicProxyPacketConn) RemoteDestination() string   { return c.proxy.target }
func (c *quicProxyPacketConn) PrepareUDP(ctx context.Context, m *C.Metadata) error {
	return c.proxy.resolveUDP(ctx, m)
}

func (c *quicProxyPacketConn) ResolveUDP(context.Context, *C.Metadata) error {
	return errors.New("unexpected local resolution")
}
