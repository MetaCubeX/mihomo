package provider

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Provider initialization opens the cache database; keep it away from user data.
	home, err := os.MkdirTemp("", "mihomo-provider-test-")
	if err != nil {
		panic(err)
	}
	C.SetHomeDir(home)
	code := m.Run()
	if cache := cachefile.Cache(); cache.DB != nil {
		_ = cache.Close()
	}
	_ = os.RemoveAll(home)
	os.Exit(code)
}

func TestProxyProviderInitialConnections(t *testing.T) {
	for _, vehicleType := range []string{"http", "file"} {
		for _, tc := range []struct {
			name   string
			option any
			close  bool
		}{
			{name: "default", close: true},
			{name: "enabled", option: true, close: true},
			{name: "disabled", option: false},
		} {
			t.Run(vehicleType+"/"+tc.name, func(t *testing.T) {
				name := t.Name()
				path := filepath.Join(C.Path.HomeDir(), vehicleType+"-"+tc.name+".yaml")
				require.NoError(t, os.WriteFile(path, []byte("proxies:\n  - {name: node, type: socks5, server: 127.0.0.1, port: 1080}\n"), 0o600))
				mapping := map[string]any{"type": vehicleType, "path": path, "url": "https://example.invalid/proxies"}
				if tc.option != nil {
					mapping["close-connections-on-reload"] = tc.option
				}
				parse := func() *ProxySetProvider {
					pd, err := ParseProxyProvider(name, mapping, nil)
					require.NoError(t, err)
					provider := pd.(*ProxySetProvider)
					t.Cleanup(func() { _ = provider.Close() })
					return provider
				}
				old := parse()
				require.NoError(t, old.Initial())
				conn, peer := trackedProviderPipe(t, "node", name)
				other, otherPeer := trackedProviderPipe(t, name, name+"-other")
				assertProviderPipeWorks(t, conn, peer)

				replacement := parse()
				require.NoError(t, replacement.Initial())
				require.Equal(t, "node", replacement.Proxies()[0].Name())
				// Releasing the replaced provider must not close retained connections.
				require.NoError(t, old.Close())
				if tc.close {
					require.Nil(t, statistic.DefaultManager.Get(conn.ID()))
					_, err := peer.Write([]byte("closed"))
					require.ErrorIs(t, err, io.ErrClosedPipe)
				} else {
					require.NotNil(t, statistic.DefaultManager.Get(conn.ID()))
					assertProviderPipeWorks(t, conn, peer)
				}
				// Matching a proxy name is insufficient; only its provider matters.
				assertProviderPipeWorks(t, other, otherPeer)
			})
		}
	}
}

func trackedProviderPipe(t *testing.T, name, provider string) (statistic.Tracker, net.Conn) {
	t.Helper()
	local, peer := net.Pipe()
	base := outbound.NewBase(outbound.BaseOption{Name: name, ProviderName: provider})
	conn := statistic.NewTCPTracker(outbound.NewConn(local, base), statistic.DefaultManager, &C.Metadata{}, nil, 0, 0, false)
	t.Cleanup(func() {
		_ = conn.Close()
		_ = peer.Close()
	})
	return conn, peer
}

func assertProviderPipeWorks(t *testing.T, conn statistic.Tracker, peer net.Conn) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	require.NoError(t, conn.(net.Conn).SetDeadline(deadline))
	require.NoError(t, peer.SetDeadline(deadline))
	writeErr := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte("alive"))
		writeErr <- err
	}()
	buf := make([]byte, 5)
	_, err := io.ReadFull(conn.(io.Reader), buf)
	require.NoError(t, err)
	require.NoError(t, <-writeErr)
	require.Equal(t, "alive", string(buf))
}
