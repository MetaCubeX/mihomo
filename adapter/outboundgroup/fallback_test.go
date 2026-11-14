package outboundgroup

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/provider"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/stretchr/testify/require"
)

// newTestFallback builds a fallback group whose first member is dead and second alive for url.
func newTestFallback(t *testing.T, url string) *Fallback {
	t.Helper()
	dead, err := adapter.ParseProxy(map[string]any{"name": "dead", "type": "socks5", "server": "127.0.0.1", "port": 1})
	require.NoError(t, err)
	alive := adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: "alive"}))
	proxies := []C.Proxy{dead, alive}
	for _, proxy := range proxies {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = proxy.URLTest(ctx, url, nil)
		cancel()
	}
	require.False(t, dead.AliveForTestUrl(url))
	require.True(t, alive.AliveForTestUrl(url))

	pd, err := provider.NewCompatibleProvider("fallback-test", proxies, provider.NewHealthCheck(proxies, "", 0, 0, true, nil))
	require.NoError(t, err)
	group, err := NewFallback(GroupCommonOption{Name: "fallback", URL: url}, FallbackOption{}, adapter.NewProxy(outbound.NewCompatible()), []P.ProxyProvider{pd})
	require.NoError(t, err)
	return group
}

// A selected proxy the group does not have -- renamed or removed by a provider update, restored
// by store-selected under a name the group no longer lists, or in a provider that has not loaded
// yet -- is passed over: the group picks its first alive proxy, as if nothing were selected, and
// keeps the selection for when a provider lists the proxy.
func TestFallbackSelectedProxyNotInGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	group := newTestFallback(t, server.URL)
	group.ForceSet("renamed")
	require.Equal(t, "alive", group.Now())
	require.Equal(t, "renamed", group.selected)
	require.Equal(t, "alive", group.findAliveProxy(true).Name())
}

// A selected proxy the group has is still used while it is alive.
func TestFallbackSelectedProxyInGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	group := newTestFallback(t, server.URL)
	group.ForceSet("alive")
	require.Equal(t, "alive", group.Now())
	require.Equal(t, "alive", group.selected)
}
