package tunnel

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

type udpTestPacket struct {
	C.UDPPacket
	data    []byte
	dropped atomic.Int32
}

func (p *udpTestPacket) Data() []byte { return p.data }
func (p *udpTestPacket) Drop()        { p.dropped.Add(1) }

func (p *udpTestPacket) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000}
}

type udpTestResolver struct {
	resolver.Resolver
	queries []string
	answer  netip.Addr
}

func (r *udpTestResolver) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	r.queries = append(r.queries, host)
	return []netip.Addr{r.answer}, nil
}

func (r *udpTestResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}

func (r *udpTestResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}

func (*udpTestResolver) Invalid() bool { return true }

func installUDPTestResolver(t *testing.T, r *udpTestResolver) {
	t.Helper()
	// These tests remain serial because routing uses the process resolver.
	previous := resolver.DefaultResolver
	resolver.DefaultResolver = r
	t.Cleanup(func() { resolver.DefaultResolver = previous })
}
