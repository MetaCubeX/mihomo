package inbound_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/stretchr/testify/assert"
)

func testInboundTrojan(t *testing.T, inboundOptions inbound.TrojanOption, outboundOptions outbound.TrojanOption) {
	t.Parallel()
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "trojan_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Users = []inbound.TrojanUser{
		{Username: "test", Password: userUUID},
	}
	in, err := inbound.NewTrojan(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = in.Listen(tunnel)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	outboundOptions.Name = "trojan_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.Password = userUUID

	out, err := outbound.NewTrojan(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)

	if outboundOptions.Network == "grpc" { // don't test sing-mux over grpc
		return
	}
	testSingMux(t, tunnel, out)
}

func testInboundTrojanTLS(t *testing.T, inboundOptions inbound.TrojanOption, outboundOptions outbound.TrojanOption) {
	testInboundTrojan(t, inboundOptions, outboundOptions)
	t.Run("ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundTrojan(t, inboundOptions, outboundOptions)
	})
	t.Run("mTLS", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.ClientAuthCert = tlsAuthCertificate
		outboundOptions.Certificate = tlsAuthCertificate
		outboundOptions.PrivateKey = tlsAuthPrivateKey
		testInboundTrojan(t, inboundOptions, outboundOptions)
	})
	t.Run("mTLS+ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.ClientAuthCert = tlsAuthCertificate
		outboundOptions.Certificate = tlsAuthCertificate
		outboundOptions.PrivateKey = tlsAuthPrivateKey
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundTrojan(t, inboundOptions, outboundOptions)
	})
}

func TestInboundTrojan_TLS(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	}
	outboundOptions := outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
	}
	testInboundTrojanTLS(t, inboundOptions, outboundOptions)
}

func TestInboundTrojan_Wss1(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
		WsPath:      "/ws",
	}
	outboundOptions := outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
		Network:     "ws",
		WSOpts: outbound.WSOptions{
			Path: "/ws",
		},
	}
	testInboundTrojanTLS(t, inboundOptions, outboundOptions)
}

func TestInboundTrojan_Wss2(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		Certificate:     tlsCertificate,
		PrivateKey:      tlsPrivateKey,
		WsPath:          "/ws",
		GrpcServiceName: "GunService",
	}
	outboundOptions := outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
		Network:     "ws",
		WSOpts: outbound.WSOptions{
			Path: "/ws",
		},
	}
	testInboundTrojanTLS(t, inboundOptions, outboundOptions)
}

func TestInboundTrojan_Grpc1(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		Certificate:     tlsCertificate,
		PrivateKey:      tlsPrivateKey,
		GrpcServiceName: "GunService",
	}
	outboundOptions := outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
		Network:     "grpc",
		GrpcOpts:    outbound.GrpcOptions{GrpcServiceName: "GunService"},
	}
	testInboundTrojanTLS(t, inboundOptions, outboundOptions)
}

func TestInboundTrojan_Grpc2(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		Certificate:     tlsCertificate,
		PrivateKey:      tlsPrivateKey,
		WsPath:          "/ws",
		GrpcServiceName: "GunService",
	}
	outboundOptions := outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
		Network:     "grpc",
		GrpcOpts:    outbound.GrpcOptions{GrpcServiceName: "GunService"},
	}
	testInboundTrojanTLS(t, inboundOptions, outboundOptions)
}

func TestInboundTrojan_Reality(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		RealityConfig: inbound.RealityConfig{
			Dest:        net.JoinHostPort(realityDest, "443"),
			PrivateKey:  realityPrivateKey,
			ShortID:     []string{realityShortid},
			ServerNames: []string{realityDest},
		},
	}
	outboundOptions := outbound.TrojanOption{
		SNI: realityDest,
		RealityOpts: outbound.RealityOptions{
			PublicKey: realityPublickey,
			ShortID:   realityShortid,
		},
		ClientFingerprint: "chrome",
	}
	testInboundTrojan(t, inboundOptions, outboundOptions)
}

func TestInboundTrojan_Reality_Grpc(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		RealityConfig: inbound.RealityConfig{
			Dest:        net.JoinHostPort(realityDest, "443"),
			PrivateKey:  realityPrivateKey,
			ShortID:     []string{realityShortid},
			ServerNames: []string{realityDest},
		},
		GrpcServiceName: "GunService",
	}
	outboundOptions := outbound.TrojanOption{
		SNI: realityDest,
		RealityOpts: outbound.RealityOptions{
			PublicKey: realityPublickey,
			ShortID:   realityShortid,
		},
		ClientFingerprint: "chrome",
		Network:           "grpc",
		GrpcOpts:          outbound.GrpcOptions{GrpcServiceName: "GunService"},
	}
	testInboundTrojan(t, inboundOptions, outboundOptions)
}

func TestInboundTrojan_TLS_TrojanSS(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
		SSOption: inbound.TrojanSSOption{
			Enabled:  true,
			Method:   "",
			Password: "password",
		},
	}
	outboundOptions := outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
		SSOpts: outbound.TrojanSSOption{
			Enabled:  true,
			Method:   "",
			Password: "password",
		},
	}
	testInboundTrojanTLS(t, inboundOptions, outboundOptions)
}

func TestInboundTrojan_Wss_TrojanSS(t *testing.T) {
	inboundOptions := inbound.TrojanOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
		SSOption: inbound.TrojanSSOption{
			Enabled:  true,
			Method:   "",
			Password: "password",
		},
		WsPath: "/ws",
	}
	outboundOptions := outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
		SSOpts: outbound.TrojanSSOption{
			Enabled:  true,
			Method:   "",
			Password: "password",
		},
		Network: "ws",
		WSOpts: outbound.WSOptions{
			Path: "/ws",
		},
	}
	testInboundTrojanTLS(t, inboundOptions, outboundOptions)
}

func testOutboundTrojanXHTTP(t *testing.T, outboundOptions outbound.TrojanOption, frontendOption testXHTTPFrontendOption) {
	t.Parallel()

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	frontendOption.BackendAddr = startTestTrojanBackend(t, tunnel, userUUID)
	addrPort, err := netip.ParseAddrPort(startTestXHTTPFrontend(t, frontendOption))
	if err != nil {
		t.Fatal(err)
	}

	outboundOptions.Name = "trojan_xhttp_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.Password = userUUID

	out, err := outbound.NewTrojan(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)
	testSingMux(t, tunnel, out)
}

func TestOutboundTrojan_XHTTP(t *testing.T) {
	testOutboundTrojanXHTTP(t, outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
		Network:     "xhttp",
		ALPN:        []string{"h2"},
		XHTTPOpts: outbound.XHTTPOptions{
			Path: "/trojan-xhttp",
			Host: "example.com",
			Mode: "auto",
		},
	}, testXHTTPFrontendOption{
		Path: "/trojan-xhttp",
		Host: "example.com",
		Mode: "auto",
	})
}

func TestOutboundTrojan_XHTTP_StreamOne(t *testing.T) {
	testOutboundTrojanXHTTP(t, outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
		Network:     "xhttp",
		ALPN:        []string{"h2"},
		XHTTPOpts: outbound.XHTTPOptions{
			Path: "/trojan-xhttp-stream-one",
			Host: "example.com",
			Mode: "stream-one",
		},
	}, testXHTTPFrontendOption{
		Path: "/trojan-xhttp-stream-one",
		Host: "example.com",
		Mode: "stream-one",
	})
}

func TestOutboundTrojan_XHTTP_StreamUp(t *testing.T) {
	testOutboundTrojanXHTTP(t, outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
		Network:     "xhttp",
		ALPN:        []string{"h2"},
		XHTTPOpts: outbound.XHTTPOptions{
			Path: "/trojan-xhttp-stream-up",
			Host: "example.com",
			Mode: "stream-up",
		},
	}, testXHTTPFrontendOption{
		Path: "/trojan-xhttp-stream-up",
		Host: "example.com",
		Mode: "stream-up",
	})
}

func TestOutboundTrojan_XHTTP_DownloadSettings(t *testing.T) {
	t.Parallel()

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	addrs := startTestSharedXHTTPFrontends(t, startTestTrojanBackend(t, tunnel, userUUID), "auto",
		testXHTTPFrontendOption{
			Path: "/trojan-xhttp-upload",
			Host: "upload.example.com",
		},
		testXHTTPFrontendOption{
			Path: "/trojan-xhttp-download",
			Host: "download.example.com",
		},
	)

	uploadAddr, err := netip.ParseAddrPort(addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	downloadAddr, err := netip.ParseAddrPort(addrs[1])
	if err != nil {
		t.Fatal(err)
	}

	out, err := outbound.NewTrojan(outbound.TrojanOption{
		Name:        "trojan_xhttp_outbound",
		Server:      uploadAddr.Addr().String(),
		Port:        int(uploadAddr.Port()),
		Password:    userUUID,
		Fingerprint: tlsFingerprint,
		SNI:         "upload.example.com",
		Network:     "xhttp",
		ALPN:        []string{"h2"},
		XHTTPOpts: outbound.XHTTPOptions{
			Path: "/trojan-xhttp-upload",
			Host: "upload.example.com",
			Mode: "auto",
			DownloadSettings: &outbound.XHTTPDownloadSettings{
				Server:     downloadAddr.Addr().String(),
				Port:       int(downloadAddr.Port()),
				TLS:        boolPtr(true),
				ServerName: "download.example.com",
				Host:       "download.example.com",
				Path:       "/trojan-xhttp-download",
			},
		},
	})
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)
	testSingMux(t, tunnel, out)
}

func TestOutboundTrojan_SplitHTTP_PacketUp(t *testing.T) {
	testOutboundTrojanXHTTP(t, outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
		Network:     "splithttp",
		ALPN:        []string{"h2"},
		SplitHTTPOpts: outbound.SplitHTTPOptions{
			Path: "/trojan-splithttp-packet-up",
			Host: "example.com",
			Mode: "packet-up",
		},
	}, testXHTTPFrontendOption{
		Path: "/trojan-splithttp-packet-up",
		Host: "example.com",
		Mode: "packet-up",
	})
}

func TestOutboundTrojan_SplitHTTP_Auto_H3(t *testing.T) {
	testOutboundTrojanXHTTP(t, outbound.TrojanOption{
		Fingerprint: tlsFingerprint,
		Network:     "splithttp",
		ALPN:        []string{"h3"},
		SplitHTTPOpts: outbound.SplitHTTPOptions{
			Path: "/trojan-splithttp-auto-h3",
			Host: "example.com",
			Mode: "auto",
		},
	}, testXHTTPFrontendOption{
		Path:     "/trojan-splithttp-auto-h3",
		Host:     "example.com",
		Mode:     "auto",
		UseHTTP3: true,
	})
}
