package main

import (
	"net"
	"testing"
	"time"

	"github.com/Dreamacro/clash/adapter/outbound"

	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/require"
)

func TestClash_Shadowsocks(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageShadowsocksRust,
		Entrypoint:   []string{"ssserver"},
		Cmd:          []string{"-s", "0.0.0.0:10002", "-m", "chacha20-ietf-poly1305", "-k", "FzcLbKs2dY9mhL", "-U"},
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
	}

	id, err := startContainer(cfg, hostCfg, "ss")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewShadowSocks(outbound.ShadowSocksOption{
		Name:     "ss",
		Server:   localIP.String(),
		Port:     10002,
		Password: "FzcLbKs2dY9mhL",
		Cipher:   "chacha20-ietf-poly1305",
		UDP:      true,
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_ShadowsocksObfsHTTP(t *testing.T) {
	cfg := &container.Config{
		Image: ImageShadowsocks,
		Env: []string{
			"SS_MODULE=ss-server",
			"SS_CONFIG=-s 0.0.0.0 -u -p 10002 -m chacha20-ietf-poly1305 -k FzcLbKs2dY9mhL --plugin obfs-server --plugin-opts obfs=http",
		},
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
	}

	id, err := startContainer(cfg, hostCfg, "ss-obfs-http")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewShadowSocks(outbound.ShadowSocksOption{
		Name:     "ss",
		Server:   localIP.String(),
		Port:     10002,
		Password: "FzcLbKs2dY9mhL",
		Cipher:   "chacha20-ietf-poly1305",
		UDP:      true,
		Plugin:   "obfs",
		PluginOpts: map[string]any{
			"mode": "http",
		},
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_ShadowsocksObfsTLS(t *testing.T) {
	cfg := &container.Config{
		Image: ImageShadowsocks,
		Env: []string{
			"SS_MODULE=ss-server",
			"SS_CONFIG=-s 0.0.0.0 -u -p 10002 -m chacha20-ietf-poly1305 -k FzcLbKs2dY9mhL --plugin obfs-server --plugin-opts obfs=tls",
		},
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
	}

	id, err := startContainer(cfg, hostCfg, "ss-obfs-tls")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewShadowSocks(outbound.ShadowSocksOption{
		Name:     "ss",
		Server:   localIP.String(),
		Port:     10002,
		Password: "FzcLbKs2dY9mhL",
		Cipher:   "chacha20-ietf-poly1305",
		UDP:      true,
		Plugin:   "obfs",
		PluginOpts: map[string]any{
			"mode": "tls",
		},
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_ShadowsocksV2RayPlugin(t *testing.T) {
	cfg := &container.Config{
		Image: ImageShadowsocks,
		Env: []string{
			"SS_MODULE=ss-server",
			"SS_CONFIG=-s 0.0.0.0 -u -p 10002 -m chacha20-ietf-poly1305 -k FzcLbKs2dY9mhL --plugin v2ray-plugin --plugin-opts=server",
		},
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
	}

	id, err := startContainer(cfg, hostCfg, "ss-v2ray-plugin")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewShadowSocks(outbound.ShadowSocksOption{
		Name:     "ss",
		Server:   localIP.String(),
		Port:     10002,
		Password: "FzcLbKs2dY9mhL",
		Cipher:   "chacha20-ietf-poly1305",
		UDP:      true,
		Plugin:   "v2ray-plugin",
		PluginOpts: map[string]any{
			"mode": "websocket",
		},
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func Benchmark_Shadowsocks(b *testing.B) {
	cfg := &container.Config{
		Image:        ImageShadowsocksRust,
		Entrypoint:   []string{"ssserver"},
		Cmd:          []string{"-s", "0.0.0.0:10002", "-m", "aes-256-gcm", "-k", "FzcLbKs2dY9mhL", "-U"},
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
	}

	id, err := startContainer(cfg, hostCfg, "ss-bench")
	require.NoError(b, err)

	b.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewShadowSocks(outbound.ShadowSocksOption{
		Name:     "ss",
		Server:   localIP.String(),
		Port:     10002,
		Password: "FzcLbKs2dY9mhL",
		Cipher:   "aes-256-gcm",
		UDP:      true,
	})
	require.NoError(b, err)

	require.True(b, TCPing(net.JoinHostPort(localIP.String(), "10002")))
	benchmarkProxy(b, proxy)
}
