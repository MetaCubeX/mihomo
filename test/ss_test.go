package main

import (
	"testing"
	"time"

	"github.com/Dreamacro/clash/adapter/outbound"

	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
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
	if err != nil {
		assert.FailNow(t, err.Error())
	}

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
	if err != nil {
		assert.FailNow(t, err.Error())
	}

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
	if err != nil {
		assert.FailNow(t, err.Error())
	}

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
	if err != nil {
		assert.FailNow(t, err.Error())
	}

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
	if err != nil {
		assert.FailNow(t, err.Error())
	}

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
	if err != nil {
		assert.FailNow(t, err.Error())
	}

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
	if err != nil {
		assert.FailNow(t, err.Error())
	}

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
	if err != nil {
		assert.FailNow(t, err.Error())
	}

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

	id, err := startContainer(cfg, hostCfg, "ss")
	if err != nil {
		assert.FailNow(b, err.Error())
	}

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
	if err != nil {
		assert.FailNow(b, err.Error())
	}

	time.Sleep(waitTime)
	benchmarkProxy(b, proxy)
}
