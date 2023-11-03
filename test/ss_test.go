package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestMihomo_Shadowsocks(t *testing.T) {
	for _, method := range []string{
		"aes-128-ctr",
		"aes-192-ctr",
		"aes-256-ctr",
		"aes-128-cfb",
		"aes-192-cfb",
		"aes-256-cfb",
		"rc4-md5",
		"chacha20-ietf",
		"aes-128-gcm",
		"aes-256-gcm",
		"chacha20-ietf-poly1305",
		"xchacha20-ietf-poly1305",
	} {
		t.Run(method, func(t *testing.T) {
			testMihomo_Shadowsocks(t, method, "FzcLbKs2dY9mhL")
		})
	}
	for _, method := range []string{
		"aes-128-gcm",
		"aes-256-gcm",
		"chacha20-ietf-poly1305",
	} {
		t.Run(method, func(t *testing.T) {
			testMihomo_ShadowsocksRust(t, method, "FzcLbKs2dY9mhL")
		})
	}
}

func TestMihomo_Shadowsocks2022(t *testing.T) {
	for _, method := range []string{
		"2022-blake3-aes-128-gcm",
	} {
		t.Run(method, func(t *testing.T) {
			testMihomo_ShadowsocksRust(t, method, mkKey(16))
		})
	}
	for _, method := range []string{
		"2022-blake3-aes-256-gcm",
		"2022-blake3-chacha20-poly1305",
	} {
		t.Run(method, func(t *testing.T) {
			testMihomo_ShadowsocksRust(t, method, mkKey(32))
		})
	}
}

func mkKey(bits int) string {
	k := make([]byte, bits)
	rand.Read(k)
	return base64.StdEncoding.EncodeToString(k)
}

func testMihomo_Shadowsocks(t *testing.T, method string, password string) {
	cfg := &container.Config{
		Image: ImageShadowsocks,
		Env: []string{
			"SS_MODULE=ss-server",
			"SS_CONFIG=-s 0.0.0.0 -u -p 10002 -m " + method + " -k " + password,
		},
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
		Password: password,
		Cipher:   method,
		UDP:      true,
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func testMihomo_ShadowsocksRust(t *testing.T, method string, password string) {
	cfg := &container.Config{
		Image:        ImageShadowsocksRust,
		Entrypoint:   []string{"ssserver"},
		Cmd:          []string{"-s", "0.0.0.0:10002", "-m", method, "-k", password, "-U", "-v"},
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
	}

	id, err := startContainer(cfg, hostCfg, "ss-rust")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewShadowSocks(outbound.ShadowSocksOption{
		Name:     "ss",
		Server:   localIP.String(),
		Port:     10002,
		Password: password,
		Cipher:   method,
		UDP:      true,
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestMihomo_ShadowsocksObfsHTTP(t *testing.T) {
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

func TestMihomo_ShadowsocksObfsTLS(t *testing.T) {
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

func TestMihomo_ShadowsocksV2RayPlugin(t *testing.T) {
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

func TestMihomo_ShadowsocksUoT(t *testing.T) {
	configPath := C.Path.Resolve("xray-shadowsocks.json")

	cfg := &container.Config{
		Image:        ImageVless,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds:        []string{fmt.Sprintf("%s:/etc/xray/config.json", configPath)},
	}

	id, err := startContainer(cfg, hostCfg, "xray-ss")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewShadowSocks(outbound.ShadowSocksOption{
		Name:       "ss",
		Server:     localIP.String(),
		Port:       10002,
		Password:   "FzcLbKs2dY9mhL",
		Cipher:     "aes-128-gcm",
		UDP:        true,
		UDPOverTCP: true,
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}
