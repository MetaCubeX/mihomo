package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/Dreamacro/clash/adapter/outbound"
	C "github.com/Dreamacro/clash/constant"

	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
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
	if err != nil {
		assert.FailNow(t, err.Error())
	}

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
	if err != nil {
		assert.FailNow(t, err.Error())
	}

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
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	defer cleanContainer(id)

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
	if err != nil {
		assert.FailNow(t, err.Error())
	}

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
	if err != nil {
		assert.FailNow(t, err.Error())
	}
	defer cleanContainer(id)

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
	if err != nil {
		assert.FailNow(t, err.Error())
	}

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

	id, err := startContainer(cfg, hostCfg, "trojan")
	if err != nil {
		assert.FailNow(b, err.Error())
	}

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
	if err != nil {
		assert.FailNow(b, err.Error())
	}

	time.Sleep(waitTime)
	benchmarkProxy(b, proxy)
}
