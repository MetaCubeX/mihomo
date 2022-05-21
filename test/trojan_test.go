package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Dreamacro/clash/adapter/outbound"
	C "github.com/Dreamacro/clash/constant"

	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/require"
)

func TestClash_Trojan(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageTrojan,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/config/config.json", C.Path.Resolve("trojan.json")),
			fmt.Sprintf("%s:/path/to/certificate.crt", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/path/to/private.key", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "trojan")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewTrojan(outbound.TrojanOption{
		Name:           "trojan",
		Server:         localIP.String(),
		Port:           10002,
		Password:       "password",
		SNI:            "example.org",
		SkipCertVerify: true,
		UDP:            true,
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_TrojanGrpc(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageXray,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/xray/config.json", C.Path.Resolve("trojan-grpc.json")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/fullchain.pem", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/privkey.pem", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "trojan-grpc")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewTrojan(outbound.TrojanOption{
		Name:           "trojan",
		Server:         localIP.String(),
		Port:           10002,
		Password:       "example",
		SNI:            "example.org",
		SkipCertVerify: true,
		UDP:            true,
		Network:        "grpc",
		GrpcOpts: outbound.GrpcOptions{
			GrpcServiceName: "example",
		},
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_TrojanWebsocket(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageTrojanGo,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/trojan-go/config.json", C.Path.Resolve("trojan-ws.json")),
			fmt.Sprintf("%s:/fullchain.pem", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/privkey.pem", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "trojan-ws")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewTrojan(outbound.TrojanOption{
		Name:           "trojan",
		Server:         localIP.String(),
		Port:           10002,
		Password:       "example",
		SNI:            "example.org",
		SkipCertVerify: true,
		UDP:            true,
		Network:        "ws",
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func Benchmark_Trojan(b *testing.B) {
	cfg := &container.Config{
		Image:        ImageTrojan,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/config/config.json", C.Path.Resolve("trojan.json")),
			fmt.Sprintf("%s:/path/to/certificate.crt", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/path/to/private.key", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "trojan-bench")
	require.NoError(b, err)

	b.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewTrojan(outbound.TrojanOption{
		Name:           "trojan",
		Server:         localIP.String(),
		Port:           10002,
		Password:       "password",
		SNI:            "example.org",
		SkipCertVerify: true,
		UDP:            true,
	})
	require.NoError(b, err)

	require.True(b, TCPing(net.JoinHostPort(localIP.String(), "10002")))
	benchmarkProxy(b, proxy)
}
