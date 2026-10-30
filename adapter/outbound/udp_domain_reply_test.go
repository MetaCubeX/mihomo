package outbound

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/trojan"
	mux "github.com/metacubex/sing-mux"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	SN "github.com/metacubex/sing/common/network"
)

// Only the underlying byte transport is stubbed: protocol wrappers must decode
// actual wire frames rather than receiving an already-decoded domain address.
type wirePacketConn struct {
	net.PacketConn
	wire []byte
}

func (c *wirePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return copy(b, c.wire), &net.UDPAddr{}, nil
}
func (c *wirePacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	return bytes.Clone(c.wire), nil, &net.UDPAddr{}, nil
}
func (c *wirePacketConn) Upstream() any { return c.PacketConn }

type wireStreamConn struct {
	net.Conn
	io.Reader
}

func (c *wireStreamConn) Read(b []byte) (int, error) { return c.Reader.Read(b) }

func TestProtocolUDPReplyAddresses(t *testing.T) {
	for _, target := range []string{"remote-only.invalid:1234", "192.0.2.1:1234", "[2001:db8::1]:1234"} {
		for _, protocol := range []string{"trojan", "socks5", "ssr"} {
			for _, wait := range []bool{false, true} {
				t.Run(protocol+"/"+target+map[bool]string{false: "/read", true: "/wait"}[wait], func(t *testing.T) {
					address := socks5.ParseAddr(target)
					var pc N.EnhancePacketConn
					switch protocol {
					case "trojan":
						var wire bytes.Buffer
						if _, err := trojan.WritePacket(&wire, address, []byte("response")); err != nil {
							t.Fatal(err)
						}
						pc = trojan.NewPacketConn(&wireStreamConn{Reader: bytes.NewReader(wire.Bytes())})
					case "socks5":
						wire, err := socks5.EncodeUDPPacket(address, []byte("response"))
						if err != nil {
							t.Fatal(err)
						}
						pc = N.NewEnhancePacketConn(&socksPacketConn{PacketConn: &wirePacketConn{wire: wire}})
					case "ssr":
						pc = &ssrPacketConn{EnhancePacketConn: &wirePacketConn{wire: append(bytes.Clone(address), []byte("response")...)}}
					}
					var data []byte
					var from net.Addr
					var err error
					if wait {
						var put func()
						data, put, from, err = pc.WaitReadFrom()
						if put != nil {
							defer put()
						}
					} else {
						data = make([]byte, 1024)
						var n int
						n, from, err = pc.ReadFrom(data)
						data = data[:n]
					}
					if err != nil {
						t.Fatal(err)
					}
					if from == nil || from.String() != target || string(data) != "response" {
						t.Fatalf("decoded reply: %v %q", from, data)
					}
					if target == "remote-only.invalid:1234" && !M.SocksaddrFromNet(from).IsFqdn() {
						t.Fatal("lost domain")
					}
				})
			}
		}
	}
}

type muxTestProxy struct {
	*Base
	service *mux.Service
}

func (p *muxTestProxy) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	client, server := net.Pipe()
	go func() { defer server.Close(); _ = p.service.NewConnection(context.Background(), server, M.Metadata{}) }()
	return NewConn(client, p), nil
}

type muxEchoHandler struct {
	destinations chan M.Socksaddr
	replySource  M.Socksaddr
}

func (*muxEchoHandler) NewConnection(context.Context, net.Conn, M.Metadata) error {
	return errors.New("unexpected TCP")
}
func (h *muxEchoHandler) NewPacketConnection(_ context.Context, pc SN.PacketConn, metadata M.Metadata) error {
	defer pc.Close()

	b := buf.NewPacket()
	b.Resize(512, 0)
	defer b.Release()
	addr, err := pc.ReadPacket(b)
	if err != nil {
		return err
	}
	h.destinations <- addr
	if h.replySource.IsValid() {
		addr = h.replySource
	}
	return pc.WritePacket(b, addr)
}
func TestSingMuxUDPRemoteDNS(t *testing.T) {
	for _, protocol := range []string{"smux", "yamux", "h2mux"} {
		t.Run(protocol, func(t *testing.T) {
			r := &failingUDPResolver{}
			old := resolver.DefaultResolver
			resolver.DefaultResolver = r
			defer func() { resolver.DefaultResolver = old }()
			handler := &muxEchoHandler{destinations: make(chan M.Socksaddr, 1)}
			service, err := mux.NewService(mux.ServiceOptions{Handler: handler, Logger: log.SingLogger, NewStreamContext: func(ctx context.Context, _ net.Conn) context.Context { return ctx }})
			if err != nil {
				t.Fatal(err)
			}
			base := NewBase(BaseOption{Name: "mux-test"})
			base.SetUDPRemoteDNS(true)
			proxy, err := NewSingMux(SingMuxOption{Protocol: protocol}, &muxTestProxy{Base: base, service: service})
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			metadata := &C.Metadata{NetWork: C.UDP, Host: "remote-only.invalid", DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 1234}
			pc, err := proxy.ListenPacketContext(ctx, metadata)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			pc.SetDeadline(time.Now().Add(5 * time.Second))
			target := metadata.UDPRemoteAddr()
			if _, err = pc.WriteTo([]byte("request"), target); err != nil {
				t.Fatal(err)
			}
			data, put, from, err := pc.WaitReadFrom()
			if put != nil {
				defer put()
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "request" || from.String() != target.String() {
				t.Fatalf("reply: %v %q", from, data)
			}
			select {
			case dest := <-handler.destinations:
				if !dest.IsFqdn() || dest.String() != target.String() {
					t.Fatalf("handshake: %v", dest)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if r.calls != 0 || metadata.DstIP.IsValid() {
				t.Fatal("remote destination was resolved locally")
			}
		})
	}
}
