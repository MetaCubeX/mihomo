package ebpf

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type memoryDestinationMap struct {
	entries map[netip.Addr]struct{}
	proxies map[netip.Addr]struct{}
	fail    bool
}

func (m *memoryDestinationMap) Apply(diff DestinationSets) error {
	if m.fail {
		return errors.New("injected map batch failure")
	}
	if m.entries == nil {
		m.entries = make(map[netip.Addr]struct{})
	}
	if m.proxies == nil {
		m.proxies = make(map[netip.Addr]struct{})
	}
	for _, ip := range diff.DirectRemove {
		delete(m.entries, ip)
	}
	for _, ip := range diff.DirectAdd {
		m.entries[ip] = struct{}{}
	}
	for _, ip := range diff.ProxyRemove {
		delete(m.proxies, ip)
	}
	for _, ip := range diff.ProxyAdd {
		m.proxies[ip] = struct{}{}
		delete(m.entries, ip)
	}
	return nil
}

func TestOffloaderSharedCDNConflict(t *testing.T) {
	writer := &memoryDestinationMap{}
	offloader := NewOffloader(writer)
	ip := netip.MustParseAddr("203.0.113.10")
	require.NoError(t, offloader.Observe("direct.example", []netip.Addr{ip}, time.Hour, Direct))
	require.Contains(t, writer.entries, ip)
	require.NoError(t, offloader.Observe("proxy.example", []netip.Addr{ip}, time.Hour, Proxy))
	require.NotContains(t, writer.entries, ip)
	require.Contains(t, writer.proxies, ip)
	require.NoError(t, offloader.Observe("proxy.example", nil, time.Hour, Proxy))
	require.Contains(t, writer.entries, ip)
	require.NotContains(t, writer.proxies, ip)
}

func TestOffloaderTTLAndOutOfOrderDeadline(t *testing.T) {
	writer := &memoryDestinationMap{}
	offloader := NewOffloader(writer)
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	offloader.now = func() time.Time { return now }
	ip := netip.MustParseAddr("2001:db8::10")
	require.NoError(t, offloader.Observe("ttl.example", []netip.Addr{ip}, time.Minute, Direct))
	now = now.Add(30 * time.Second)
	require.NoError(t, offloader.Observe("ttl.example", []netip.Addr{ip}, time.Hour, Direct))
	now = now.Add(31 * time.Second) // old deadline fires but must be ignored
	require.NoError(t, offloader.Expire())
	require.Contains(t, writer.entries, ip)
	now = now.Add(time.Hour)
	require.NoError(t, offloader.Expire())
	require.NotContains(t, writer.entries, ip)
}

func TestOffloaderRejectsUnsafeAddresses(t *testing.T) {
	writer := &memoryDestinationMap{}
	offloader := NewOffloader(writer)
	ips := []netip.Addr{
		netip.MustParseAddr("198.18.0.1"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("169.254.1.1"),
		netip.MustParseAddr("224.0.0.1"),
		netip.MustParseAddr("203.0.113.11"),
	}
	require.NoError(t, offloader.Observe("safe.example", ips, time.Hour, Direct))
	require.Equal(t, map[netip.Addr]struct{}{netip.MustParseAddr("203.0.113.11"): {}}, writer.entries)
}

func TestOffloaderRetainsDirtyDiffAfterMapFailure(t *testing.T) {
	writer := &memoryDestinationMap{fail: true}
	offloader := NewOffloader(writer)
	ip := netip.MustParseAddr("203.0.113.12")
	require.Error(t, offloader.Observe("retry.example", []netip.Addr{ip}, time.Hour, Direct))
	require.Empty(t, writer.entries)
	writer.fail = false
	require.NoError(t, offloader.Expire())
	require.Contains(t, writer.entries, ip)
}

func TestOffloaderSeparatesAAndAAAA(t *testing.T) {
	writer := &memoryDestinationMap{}
	offloader := NewOffloader(writer)
	v4, v6 := netip.MustParseAddr("203.0.113.13"), netip.MustParseAddr("2001:db8::13")
	require.NoError(t, offloader.Observe("dual.example", []netip.Addr{v4, v6}, time.Hour, Direct))
	require.Contains(t, writer.entries, v4)
	require.Contains(t, writer.entries, v6)
	require.NoError(t, offloader.Observe("dual.example", []netip.Addr{v6}, time.Hour, Direct))
	require.NotContains(t, writer.entries, v4)
	require.Contains(t, writer.entries, v6)
}
