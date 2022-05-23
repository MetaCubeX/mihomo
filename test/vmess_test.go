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

func TestClash_Vmess(t *testing.T) {
	configPath := C.Path.Resolve("vmess.json")

	cfg := &container.Config{
		Image:        ImageVmess,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds:        []string{fmt.Sprintf("%s:/etc/v2ray/config.json", configPath)},
	}

	id, err := startContainer(cfg, hostCfg, "vmess")
	require.NoError(t, err)

	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewVmess(outbound.VmessOption{
		Name:   "vmess",
		Server: localIP.String(),
		Port:   10002,
		UUID:   "b831381d-6324-4d53-ad4f-8cda48b30811",
		Cipher: "auto",
		UDP:    true,
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_VmessTLS(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageVmess,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/v2ray/config.json", C.Path.Resolve("vmess-tls.json")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/fullchain.pem", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/privkey.pem", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "vmess-tls")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewVmess(outbound.VmessOption{
		Name:           "vmess",
		Server:         localIP.String(),
		Port:           10002,
		UUID:           "b831381d-6324-4d53-ad4f-8cda48b30811",
		Cipher:         "auto",
		TLS:            true,
		SkipCertVerify: true,
		ServerName:     "example.org",
		UDP:            true,
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_VmessHTTP2(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageVmess,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/v2ray/config.json", C.Path.Resolve("vmess-http2.json")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/fullchain.pem", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/privkey.pem", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "vmess-http2")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewVmess(outbound.VmessOption{
		Name:           "vmess",
		Server:         localIP.String(),
		Port:           10002,
		UUID:           "b831381d-6324-4d53-ad4f-8cda48b30811",
		Cipher:         "auto",
		Network:        "h2",
		TLS:            true,
		SkipCertVerify: true,
		ServerName:     "example.org",
		UDP:            true,
		HTTP2Opts: outbound.HTTP2Options{
			Host: []string{"example.org"},
			Path: "/test",
		},
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_VmessHTTP(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageVmess,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/v2ray/config.json", C.Path.Resolve("vmess-http.json")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "vmess-http")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewVmess(outbound.VmessOption{
		Name:    "vmess",
		Server:  localIP.String(),
		Port:    10002,
		UUID:    "b831381d-6324-4d53-ad4f-8cda48b30811",
		Cipher:  "auto",
		Network: "http",
		UDP:     true,
		HTTPOpts: outbound.HTTPOptions{
			Method: "GET",
			Path:   []string{"/"},
			Headers: map[string][]string{
				"Host": {"www.amazon.com"},
				"User-Agent": {
					"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36 Edg/84.0.522.49",
				},
				"Accept-Encoding": {
					"gzip, deflate",
				},
				"Connection": {
					"keep-alive",
				},
				"Pragma": {"no-cache"},
			},
		},
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_VmessWebsocket(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageVmess,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/v2ray/config.json", C.Path.Resolve("vmess-ws.json")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "vmess-ws")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewVmess(outbound.VmessOption{
		Name:    "vmess",
		Server:  localIP.String(),
		Port:    10002,
		UUID:    "b831381d-6324-4d53-ad4f-8cda48b30811",
		Cipher:  "auto",
		Network: "ws",
		UDP:     true,
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_VmessWebsocketTLS(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageVmess,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/v2ray/config.json", C.Path.Resolve("vmess-ws-tls.json")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/fullchain.pem", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/privkey.pem", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "vmess-ws")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewVmess(outbound.VmessOption{
		Name:           "vmess",
		Server:         localIP.String(),
		Port:           10002,
		UUID:           "b831381d-6324-4d53-ad4f-8cda48b30811",
		Cipher:         "auto",
		Network:        "ws",
		TLS:            true,
		SkipCertVerify: true,
		UDP:            true,
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_VmessGrpc(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageVmess,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/v2ray/config.json", C.Path.Resolve("vmess-grpc.json")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/fullchain.pem", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/etc/ssl/v2ray/privkey.pem", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "vmess-grpc")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewVmess(outbound.VmessOption{
		Name:           "vmess",
		Server:         localIP.String(),
		Port:           10002,
		UUID:           "b831381d-6324-4d53-ad4f-8cda48b30811",
		Cipher:         "auto",
		Network:        "grpc",
		TLS:            true,
		SkipCertVerify: true,
		UDP:            true,
		ServerName:     "example.org",
		GrpcOpts: outbound.GrpcOptions{
			GrpcServiceName: "example!",
		},
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_VmessWebsocket0RTT(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageVmess,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/v2ray/config.json", C.Path.Resolve("vmess-ws-0rtt.json")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "vmess-ws-0rtt")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewVmess(outbound.VmessOption{
		Name:       "vmess",
		Server:     localIP.String(),
		Port:       10002,
		UUID:       "b831381d-6324-4d53-ad4f-8cda48b30811",
		Cipher:     "auto",
		Network:    "ws",
		UDP:        true,
		ServerName: "example.org",
		WSOpts: outbound.WSOptions{
			MaxEarlyData:        2048,
			EarlyDataHeaderName: "Sec-WebSocket-Protocol",
		},
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_VmessWebsocketXray0RTT(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageXray,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/xray/config.json", C.Path.Resolve("vmess-ws-0rtt.json")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "vmess-xray-ws-0rtt")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewVmess(outbound.VmessOption{
		Name:       "vmess",
		Server:     localIP.String(),
		Port:       10002,
		UUID:       "b831381d-6324-4d53-ad4f-8cda48b30811",
		Cipher:     "auto",
		Network:    "ws",
		UDP:        true,
		ServerName: "example.org",
		WSOpts: outbound.WSOptions{
			Path: "/?ed=2048",
		},
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func Benchmark_Vmess(b *testing.B) {
	configPath := C.Path.Resolve("vmess.json")

	cfg := &container.Config{
		Image:        ImageVmess,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds:        []string{fmt.Sprintf("%s:/etc/v2ray/config.json", configPath)},
	}

	id, err := startContainer(cfg, hostCfg, "vmess-bench")
	require.NoError(b, err)

	b.Cleanup(func() {
		cleanContainer(id)
	})

	proxy, err := outbound.NewVmess(outbound.VmessOption{
		Name:    "vmess",
		Server:  localIP.String(),
		Port:    10002,
		UUID:    "b831381d-6324-4d53-ad4f-8cda48b30811",
		Cipher:  "auto",
		AlterID: 0,
		UDP:     true,
	})
	require.NoError(b, err)

	time.Sleep(waitTime)
	benchmarkProxy(b, proxy)
}
