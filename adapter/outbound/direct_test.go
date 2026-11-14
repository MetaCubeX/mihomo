package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedResolver answers like the DNS resolver: an IP literal is itself, and
// any name gets ips, or err when ips is empty.
type fixedResolver struct {
	ips []netip.Addr
	err error
}

func (r fixedResolver) lookup(host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	if len(r.ips) == 0 {
		return nil, r.err
	}
	return r.ips, nil
}

func (r fixedResolver) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(host)
}
func (r fixedResolver) LookupIPv4(_ context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(host)
}
func (r fixedResolver) LookupIPv6(_ context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(host)
}
func (fixedResolver) ResolveECH(context.Context, string) ([]byte, error) { return nil, nil }
func (fixedResolver) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) {
	return nil, errors.New("not implemented")
}
func (fixedResolver) Invalid() bool    { return true }
func (fixedResolver) ClearCache()      {}
func (fixedResolver) ResetConnection() {}

func withDirectHostResolver(t *testing.T, r resolver.Resolver) {
	previous := resolver.DirectHostResolver
	resolver.DirectHostResolver = r
	t.Cleanup(func() { resolver.DirectHostResolver = previous })
}

func listenLoopback(t *testing.T) (netip.AddrPort, <-chan struct{}) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
			accepted <- struct{}{}
		}
	}()
	return netip.MustParseAddrPort(listener.Addr().String()), accepted
}

func waitAccepted(t *testing.T, accepted <-chan struct{}) {
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the listener was not dialed")
	}
}

func TestDirectDialsMappedIPWhenHostNoLongerResolves(t *testing.T) {
	for name, gone := range map[string]fixedResolver{
		"not found":    {err: resolver.ErrIPNotFound},
		"empty answer": {},
	} {
		t.Run(name, func(t *testing.T) {
			withDirectHostResolver(t, gone)
			target, accepted := listenLoopback(t)
			metadata := &C.Metadata{
				NetWork: C.TCP,
				Host:    "gone.example.com",
				DstIP:   target.Addr(),
				DstPort: target.Port(),
				DNSMode: C.DNSMapping,
			}
			conn, err := NewDirect().DialContext(context.Background(), metadata)
			require.NoError(t, err)
			defer conn.Close()
			waitAccepted(t, accepted)
			assert.Equal(t, "gone.example.com", metadata.Host, "the host stays for logs and statistics")
		})
	}
}

func TestDirectKeepsDialingResolvableMappedHost(t *testing.T) {
	// Unchanged behaviour: a mapped host that still resolves is dialed by
	// name, so direct-nameserver keeps choosing the address.
	target, accepted := listenLoopback(t)
	withDirectHostResolver(t, fixedResolver{ips: []netip.Addr{target.Addr()}})
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Host:    "resolvable.example.com",
		DstIP:   netip.MustParseAddr("192.0.2.1"), // TEST-NET-1: never the dialed address here
		DstPort: target.Port(),
		DNSMode: C.DNSMapping,
	}
	conn, err := NewDirect().DialContext(context.Background(), metadata)
	require.NoError(t, err)
	defer conn.Close()
	waitAccepted(t, accepted)
}

func TestDirectDoesNotFallBackForRequestedHost(t *testing.T) {
	withDirectHostResolver(t, fixedResolver{err: resolver.ErrIPNotFound})
	target, accepted := listenLoopback(t)
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Host:    "gone.example.com",
		DstIP:   target.Addr(),
		DstPort: target.Port(),
		DNSMode: C.DNSNormal,
	}
	_, err := NewDirect().DialContext(context.Background(), metadata)
	require.ErrorIs(t, err, resolver.ErrIPNotFound)
	select {
	case <-accepted:
		t.Fatal("a host the client asked for by name was replaced by an IP")
	case <-time.After(100 * time.Millisecond):
	}
}
