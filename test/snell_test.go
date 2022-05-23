package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/Dreamacro/clash/adapter/outbound"
	C "github.com/Dreamacro/clash/constant"

	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/require"
)

func TestClash_SnellObfsHTTP(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageSnell,
		ExposedPorts: defaultExposedPorts,
		Cmd:          []string{"-c", "/config.conf"},
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds:        []string{fmt.Sprintf("%s:/config.conf", C.Path.Resolve("snell-http.conf"))},
	}

	id, err := startContainer(cfg, hostCfg, "snell-http")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewSnell(outbound.SnellOption{
		Name:   "snell",
		Server: localIP.String(),
		Port:   10002,
		Psk:    "password",
		ObfsOpts: map[string]any{
			"mode": "http",
		},
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_SnellObfsTLS(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageSnell,
		ExposedPorts: defaultExposedPorts,
		Cmd:          []string{"-c", "/config.conf"},
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds:        []string{fmt.Sprintf("%s:/config.conf", C.Path.Resolve("snell-tls.conf"))},
	}

	id, err := startContainer(cfg, hostCfg, "snell-tls")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewSnell(outbound.SnellOption{
		Name:   "snell",
		Server: localIP.String(),
		Port:   10002,
		Psk:    "password",
		ObfsOpts: map[string]any{
			"mode": "tls",
		},
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_Snell(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageSnell,
		ExposedPorts: defaultExposedPorts,
		Cmd:          []string{"-c", "/config.conf"},
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds:        []string{fmt.Sprintf("%s:/config.conf", C.Path.Resolve("snell.conf"))},
	}

	id, err := startContainer(cfg, hostCfg, "snell")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewSnell(outbound.SnellOption{
		Name:   "snell",
		Server: localIP.String(),
		Port:   10002,
		Psk:    "password",
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_Snellv3(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageSnell,
		ExposedPorts: defaultExposedPorts,
		Cmd:          []string{"-c", "/config.conf"},
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds:        []string{fmt.Sprintf("%s:/config.conf", C.Path.Resolve("snell.conf"))},
	}

	id, err := startContainer(cfg, hostCfg, "snell")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewSnell(outbound.SnellOption{
		Name:    "snell",
		Server:  localIP.String(),
		Port:    10002,
		Psk:     "password",
		UDP:     true,
		Version: 3,
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func Benchmark_Snell(b *testing.B) {
	cfg := &container.Config{
		Image:        ImageSnell,
		ExposedPorts: defaultExposedPorts,
		Cmd:          []string{"-c", "/config.conf"},
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds:        []string{fmt.Sprintf("%s:/config.conf", C.Path.Resolve("snell-http.conf"))},
	}

	id, err := startContainer(cfg, hostCfg, "snell-bench")
	require.NoError(b, err)

	b.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewSnell(outbound.SnellOption{
		Name:   "snell",
		Server: localIP.String(),
		Port:   10002,
		Psk:    "password",
		ObfsOpts: map[string]any{
			"mode": "http",
		},
	})
	require.NoError(b, err)

	time.Sleep(waitTime)
	benchmarkProxy(b, proxy)
}
