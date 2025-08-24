package inbound_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/vless/encryption"
	"github.com/stretchr/testify/assert"
)

func testInboundVless(t *testing.T, inboundOptions inbound.VlessOption, outboundOptions outbound.VlessOption) {
	t.Parallel()
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "vless_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Users = []inbound.VlessUser{
		{Username: "test", UUID: userUUID, Flow: "xtls-rprx-vision"},
	}
	in, err := inbound.NewVless(&inboundOptions)
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

	outboundOptions.Name = "vless_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.UUID = userUUID

	out, err := outbound.NewVless(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)

	testSingMux(t, tunnel, out)
}

func TestInboundVless_TLS(t *testing.T) {
	inboundOptions := inbound.VlessOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	}
	outboundOptions := outbound.VlessOption{
		TLS:         true,
		Fingerprint: tlsFingerprint,
	}
	testInboundVless(t, inboundOptions, outboundOptions)
	t.Run("xtls-rprx-vision", func(t *testing.T) {
		outboundOptions := outboundOptions
		outboundOptions.Flow = "xtls-rprx-vision"
		testInboundVless(t, inboundOptions, outboundOptions)
	})
	t.Run("ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundVless(t, inboundOptions, outboundOptions)
		t.Run("xtls-rprx-vision", func(t *testing.T) {
			outboundOptions := outboundOptions
			outboundOptions.Flow = "xtls-rprx-vision"
			testInboundVless(t, inboundOptions, outboundOptions)
		})
	})
}

func TestInboundVless_Encryption(t *testing.T) {
	seedBase64, clientBase64, _, err := encryption.GenMLKEM768("")
	if err != nil {
		t.Fatal(err)
		return
	}
	privateKeyBase64, passwordBase64, _, err := encryption.GenX25519("")
	if err != nil {
		t.Fatal(err)
		return
	}
	var modes = []string{
		"native",
		"xorpub",
		"random",
	}
	for i := range modes {
		mode := modes[i]
		t.Run(mode, func(t *testing.T) {
			inboundOptions := inbound.VlessOption{
				Decryption: "mlkem768x25519plus." + mode + ".600s." + privateKeyBase64 + "." + seedBase64,
			}
			outboundOptions := outbound.VlessOption{
				Encryption: "mlkem768x25519plus." + mode + ".0rtt." + passwordBase64 + "." + clientBase64,
			}
			testInboundVless(t, inboundOptions, outboundOptions)
			t.Run("xtls-rprx-vision", func(t *testing.T) {
				outboundOptions := outboundOptions
				outboundOptions.Flow = "xtls-rprx-vision"
				testInboundVless(t, inboundOptions, outboundOptions)
			})
		})
	}
}

func TestInboundVless_Wss1(t *testing.T) {
	inboundOptions := inbound.VlessOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
		WsPath:      "/ws",
	}
	outboundOptions := outbound.VlessOption{
		TLS:         true,
		Fingerprint: tlsFingerprint,
		Network:     "ws",
		WSOpts: outbound.WSOptions{
			Path: "/ws",
		},
	}
	testInboundVless(t, inboundOptions, outboundOptions)
	t.Run("xtls-rprx-vision", func(t *testing.T) {
		outboundOptions := outboundOptions
		outboundOptions.Flow = "xtls-rprx-vision"
		testInboundVless(t, inboundOptions, outboundOptions)
	})
	t.Run("ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundVless(t, inboundOptions, outboundOptions)
		t.Run("xtls-rprx-vision", func(t *testing.T) {
			outboundOptions := outboundOptions
			outboundOptions.Flow = "xtls-rprx-vision"
			testInboundVless(t, inboundOptions, outboundOptions)
		})
	})
}

func TestInboundVless_Wss2(t *testing.T) {
	inboundOptions := inbound.VlessOption{
		Certificate:     tlsCertificate,
		PrivateKey:      tlsPrivateKey,
		WsPath:          "/ws",
		GrpcServiceName: "GunService",
	}
	outboundOptions := outbound.VlessOption{
		TLS:         true,
		Fingerprint: tlsFingerprint,
		Network:     "ws",
		WSOpts: outbound.WSOptions{
			Path: "/ws",
		},
	}
	testInboundVless(t, inboundOptions, outboundOptions)
	t.Run("xtls-rprx-vision", func(t *testing.T) {
		outboundOptions := outboundOptions
		outboundOptions.Flow = "xtls-rprx-vision"
		testInboundVless(t, inboundOptions, outboundOptions)
	})
	t.Run("ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundVless(t, inboundOptions, outboundOptions)
		t.Run("xtls-rprx-vision", func(t *testing.T) {
			outboundOptions := outboundOptions
			outboundOptions.Flow = "xtls-rprx-vision"
			testInboundVless(t, inboundOptions, outboundOptions)
		})
	})
}

func TestInboundVless_Grpc1(t *testing.T) {
	inboundOptions := inbound.VlessOption{
		Certificate:     tlsCertificate,
		PrivateKey:      tlsPrivateKey,
		GrpcServiceName: "GunService",
	}
	outboundOptions := outbound.VlessOption{
		TLS:         true,
		Fingerprint: tlsFingerprint,
		Network:     "grpc",
		GrpcOpts:    outbound.GrpcOptions{GrpcServiceName: "GunService"},
	}
	testInboundVless(t, inboundOptions, outboundOptions)
	t.Run("ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundVless(t, inboundOptions, outboundOptions)
	})
}

func TestInboundVless_Grpc2(t *testing.T) {
	inboundOptions := inbound.VlessOption{
		Certificate:     tlsCertificate,
		PrivateKey:      tlsPrivateKey,
		WsPath:          "/ws",
		GrpcServiceName: "GunService",
	}
	outboundOptions := outbound.VlessOption{
		TLS:         true,
		Fingerprint: tlsFingerprint,
		Network:     "grpc",
		GrpcOpts:    outbound.GrpcOptions{GrpcServiceName: "GunService"},
	}
	testInboundVless(t, inboundOptions, outboundOptions)
	t.Run("ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundVless(t, inboundOptions, outboundOptions)
	})
}

func TestInboundVless_Reality(t *testing.T) {
	inboundOptions := inbound.VlessOption{
		RealityConfig: inbound.RealityConfig{
			Dest:        net.JoinHostPort(realityDest, "443"),
			PrivateKey:  realityPrivateKey,
			ShortID:     []string{realityShortid},
			ServerNames: []string{realityDest},
		},
	}
	outboundOptions := outbound.VlessOption{
		TLS:        true,
		ServerName: realityDest,
		RealityOpts: outbound.RealityOptions{
			PublicKey: realityPublickey,
			ShortID:   realityShortid,
		},
		ClientFingerprint: "chrome",
	}
	testInboundVless(t, inboundOptions, outboundOptions)
	t.Run("xtls-rprx-vision", func(t *testing.T) {
		outboundOptions := outboundOptions
		outboundOptions.Flow = "xtls-rprx-vision"
		testInboundVless(t, inboundOptions, outboundOptions)
	})
	t.Run("X25519MLKEM768", func(t *testing.T) {
		outboundOptions := outboundOptions
		outboundOptions.RealityOpts.SupportX25519MLKEM768 = true
		testInboundVless(t, inboundOptions, outboundOptions)
		t.Run("xtls-rprx-vision", func(t *testing.T) {
			outboundOptions := outboundOptions
			outboundOptions.Flow = "xtls-rprx-vision"
			testInboundVless(t, inboundOptions, outboundOptions)
		})
	})
}

func TestInboundVless_Reality_Grpc(t *testing.T) {
	inboundOptions := inbound.VlessOption{
		RealityConfig: inbound.RealityConfig{
			Dest:        net.JoinHostPort(realityDest, "443"),
			PrivateKey:  realityPrivateKey,
			ShortID:     []string{realityShortid},
			ServerNames: []string{realityDest},
		},
		GrpcServiceName: "GunService",
	}
	outboundOptions := outbound.VlessOption{
		TLS:        true,
		ServerName: realityDest,
		RealityOpts: outbound.RealityOptions{
			PublicKey: realityPublickey,
			ShortID:   realityShortid,
		},
		ClientFingerprint: "chrome",
		Network:           "grpc",
		GrpcOpts:          outbound.GrpcOptions{GrpcServiceName: "GunService"},
	}
	testInboundVless(t, inboundOptions, outboundOptions)
	t.Run("X25519MLKEM768", func(t *testing.T) {
		outboundOptions := outboundOptions
		outboundOptions.RealityOpts.SupportX25519MLKEM768 = true
		testInboundVless(t, inboundOptions, outboundOptions)
	})
}
