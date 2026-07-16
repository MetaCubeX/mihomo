package inbound_test

import (
	"encoding/base64"
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/vless/encryption"
	utls "github.com/metacubex/utls"
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
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel

	out, err := outbound.NewVless(outboundOptions)
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

func testInboundVlessTLS(t *testing.T, inboundOptions inbound.VlessOption, outboundOptions outbound.VlessOption, testVision bool) {
	testInboundVless(t, inboundOptions, outboundOptions)
	if testVision {
		t.Run("xtls-rprx-vision", func(t *testing.T) {
			outboundOptions := outboundOptions
			outboundOptions.Flow = "xtls-rprx-vision"
			testInboundVless(t, inboundOptions, outboundOptions)
		})
	}
	t.Run("ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundVless(t, inboundOptions, outboundOptions)
		if testVision {
			t.Run("xtls-rprx-vision", func(t *testing.T) {
				outboundOptions := outboundOptions
				outboundOptions.Flow = "xtls-rprx-vision"
				testInboundVless(t, inboundOptions, outboundOptions)
			})
		}
	})
	t.Run("mTLS", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.ClientAuthCert = tlsAuthCertificate
		outboundOptions.Certificate = tlsAuthCertificate
		outboundOptions.PrivateKey = tlsAuthPrivateKey
		testInboundVless(t, inboundOptions, outboundOptions)
		if testVision {
			t.Run("xtls-rprx-vision", func(t *testing.T) {
				outboundOptions := outboundOptions
				outboundOptions.Flow = "xtls-rprx-vision"
				testInboundVless(t, inboundOptions, outboundOptions)
			})
		}
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
		testInboundVless(t, inboundOptions, outboundOptions)
		if testVision {
			t.Run("xtls-rprx-vision", func(t *testing.T) {
				outboundOptions := outboundOptions
				outboundOptions.Flow = "xtls-rprx-vision"
				testInboundVless(t, inboundOptions, outboundOptions)
			})
		}
	})
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
	testInboundVlessTLS(t, inboundOptions, outboundOptions, true)
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
	paddings := []struct {
		name string
		data string
	}{
		{"unconfigured-padding", ""},
		{"default-padding", "100-111-1111.75-0-111.50-0-3333."},
		{"old-padding", "100-100-1000."}, // Xray-core v25.8.29
		{"custom-padding", "100-1234-7890.33-0-1111.66-0-6666.55-111-777."},
	}
	var modes = []string{
		"native",
		"xorpub",
		"random",
	}
	for i := range modes {
		mode := modes[i]
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			for i := range paddings {
				padding := paddings[i].data
				t.Run(paddings[i].name, func(t *testing.T) {
					t.Parallel()
					inboundOptions := inbound.VlessOption{
						Decryption: "mlkem768x25519plus." + mode + ".600s." + padding + privateKeyBase64 + "." + seedBase64,
					}
					outboundOptions := outbound.VlessOption{
						Encryption: "mlkem768x25519plus." + mode + ".0rtt." + padding + passwordBase64 + "." + clientBase64,
					}
					t.Run("raw", func(t *testing.T) {
						testInboundVless(t, inboundOptions, outboundOptions)
						t.Run("xtls-rprx-vision", func(t *testing.T) {
							outboundOptions := outboundOptions
							outboundOptions.Flow = "xtls-rprx-vision"
							testInboundVless(t, inboundOptions, outboundOptions)
						})
					})
					t.Run("ws", func(t *testing.T) {
						inboundOptions := inboundOptions
						inboundOptions.WsPath = "/ws"
						outboundOptions := outboundOptions
						outboundOptions.Network = "ws"
						outboundOptions.WSOpts = outbound.WSOptions{Path: "/ws"}
						testInboundVless(t, inboundOptions, outboundOptions)
						t.Run("xtls-rprx-vision", func(t *testing.T) {
							outboundOptions := outboundOptions
							outboundOptions.Flow = "xtls-rprx-vision"
							testInboundVless(t, inboundOptions, outboundOptions)
						})
					})
					t.Run("grpc", func(t *testing.T) {
						inboundOptions := inboundOptions
						inboundOptions.GrpcServiceName = "GunService"
						outboundOptions := outboundOptions
						outboundOptions.Network = "grpc"
						outboundOptions.GrpcOpts = outbound.GrpcOptions{GrpcServiceName: "GunService"}
						testInboundVless(t, inboundOptions, outboundOptions)
						t.Run("xtls-rprx-vision", func(t *testing.T) {
							outboundOptions := outboundOptions
							outboundOptions.Flow = "xtls-rprx-vision"
							testInboundVless(t, inboundOptions, outboundOptions)
						})
					})
				})
			}
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
		WSOpts:      outbound.WSOptions{Path: "/ws"},
	}
	testInboundVlessTLS(t, inboundOptions, outboundOptions, false)
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
		WSOpts:      outbound.WSOptions{Path: "/ws"},
	}
	testInboundVlessTLS(t, inboundOptions, outboundOptions, false)
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
	testInboundVlessTLS(t, inboundOptions, outboundOptions, false)
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
	testInboundVlessTLS(t, inboundOptions, outboundOptions, false)
}

func testInboundVlessUTLS(t *testing.T, inboundOptions inbound.VlessOption, outboundOptions outbound.VlessOption) {
	t.Parallel()
	t.Run("Conn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		testInboundVless(t, inboundOptions, outboundOptions)
	})
	t.Run("UConn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		outboundOptions.ClientFingerprint = "chrome"
		testInboundVless(t, inboundOptions, outboundOptions)
	})
}

func TestInboundVless_ShadowTLS(t *testing.T) {
	const password = "shadow-tls-password"
	inboundOptions := inbound.VlessOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   3,
			Users:     []inbound.ShadowTLSUser{{Name: "test", Password: password}},
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.VlessOption{
		TLS:           true,
		ServerName:    realityDest,
		Fingerprint:   tlsFingerprint,
		ShadowTLSOpts: outbound.ShadowTLSOptions{Password: password, Version: 3},
	}
	testInboundVlessUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundVless_Restls(t *testing.T) {
	const password = "restls-password"
	inboundOptions := inbound.VlessOption{
		ResTLS: inbound.ResTLS{
			Enable:   true,
			Dest:     net.JoinHostPort(realityDest, "443"),
			Password: password,
		},
	}
	outboundOptions := outbound.VlessOption{
		TLS:         true,
		ServerName:  realityDest,
		Fingerprint: tlsFingerprint,
		RestlsOpts:  outbound.RestlsOptions{Password: password, VersionHint: "tls13"},
	}
	testInboundVlessUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundVless_JLS(t *testing.T) {
	const username = "jls-user"
	const password = "jls-password"
	inboundOptions := inbound.VlessOption{
		JLSConfig: inbound.JLSConfig{
			Enable: true,
			Users:  []inbound.JLSUser{{Username: username, Password: password}},
			SNI:    realityDest,
			Dest:   net.JoinHostPort(realityDest, "443"),
		},
	}
	outboundOptions := outbound.VlessOption{
		TLS:        true,
		ServerName: realityDest,
		JLSOpts:    outbound.JLSOptions{Username: username, Password: password},
	}
	testInboundVlessUTLS(t, inboundOptions, outboundOptions)
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
	t.Run("X25519MLKEM768 and ML-DSA-65", func(t *testing.T) {
		seed := make([]byte, 32)
		seed[0] = 1
		_, verifyKey, err := utls.RealityMldsa65KeyFromSeed(seed)
		if !assert.NoError(t, err) {
			return
		}
		inboundOptions := inboundOptions
		inboundOptions.RealityConfig.Mldsa65Seed = base64.RawURLEncoding.EncodeToString(seed)
		inboundOptions.RealityConfig.Show = true
		outboundOptions := outboundOptions
		outboundOptions.RealityOpts.Mldsa65Verify = base64.RawURLEncoding.EncodeToString(verifyKey)
		outboundOptions.RealityOpts.Show = true
		testInboundVless(t, inboundOptions, outboundOptions)
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
}

func TestInboundVless_XHTTP(t *testing.T) {
	testCases := []struct {
		mode string
	}{
		{mode: "auto"},
		{mode: "stream-one"},
		{mode: "stream-up"},
		{mode: "packet-up"},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.mode, func(t *testing.T) {
			getConfig := func() (inbound.VlessOption, outbound.VlessOption) {
				inboundOptions := inbound.VlessOption{
					Certificate: tlsCertificate,
					PrivateKey:  tlsPrivateKey,
					XHTTPConfig: inbound.XHTTPConfig{
						Path: "/vless-xhttp",
						Host: "example.com",
						Mode: testCase.mode,
					},
				}
				outboundOptions := outbound.VlessOption{
					TLS:               true,
					Fingerprint:       tlsFingerprint,
					ServerName:        "example.org",
					ClientFingerprint: "chrome",
					Network:           "xhttp",
					XHTTPOpts: outbound.XHTTPOptions{
						Path: "/vless-xhttp",
						Host: "example.com",
						Mode: testCase.mode,
					},
				}
				return inboundOptions, outboundOptions
			}
			testInboundVless_XHTTP(t, getConfig, testCase.mode)
		})
	}
}

func testInboundVless_XHTTP(t *testing.T, getConfig func() (inbound.VlessOption, outbound.VlessOption), mode string) {
	t.Run("nosplit", func(t *testing.T) {
		t.Run("single", func(t *testing.T) {
			inboundOptions, outboundOptions := getConfig()
			testInboundVlessTLS(t, inboundOptions, outboundOptions, false)
		})

		t.Run("reuse", func(t *testing.T) {
			inboundOptions, outboundOptions := getConfig()
			testInboundVlessTLS(t, inboundOptions, withXHTTPReuse(outboundOptions), false)
		})
	})

	t.Run("split", func(t *testing.T) {
		if mode == "stream-one" { // stream-one not supported download settings
			return
		}

		t.Run("single", func(t *testing.T) {
			inboundOptions, outboundOptions := getConfig()
			outboundOptions.XHTTPOpts.DownloadSettings = &outbound.XHTTPDownloadSettings{}
			testInboundVlessTLS(t, inboundOptions, outboundOptions, false)
		})

		t.Run("reuse", func(t *testing.T) {
			inboundOptions, outboundOptions := getConfig()
			outboundOptions.XHTTPOpts.DownloadSettings = &outbound.XHTTPDownloadSettings{}
			testInboundVlessTLS(t, inboundOptions, withXHTTPReuse(outboundOptions), false)
		})
	})
}

func TestInboundVless_XHTTP_Reality(t *testing.T) {
	testCases := []struct {
		mode string
	}{
		{mode: "auto"},
		{mode: "stream-one"},
		{mode: "stream-up"},
		{mode: "packet-up"},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.mode, func(t *testing.T) {
			getConfig := func() (inbound.VlessOption, outbound.VlessOption) {
				inboundOptions := inbound.VlessOption{
					RealityConfig: inbound.RealityConfig{
						Dest:        net.JoinHostPort(realityDest, "443"),
						PrivateKey:  realityPrivateKey,
						ShortID:     []string{realityShortid},
						ServerNames: []string{realityDest},
					},
					XHTTPConfig: inbound.XHTTPConfig{
						Path: "/vless-xhttp",
						Host: "example.com",
						Mode: testCase.mode,
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
					Network:           "xhttp",
					XHTTPOpts: outbound.XHTTPOptions{
						Path: "/vless-xhttp",
						Host: "example.com",
						Mode: testCase.mode,
					},
				}
				return inboundOptions, outboundOptions
			}
			testInboundVless_XHTTP_Reality(t, getConfig, testCase.mode)
		})
	}
}

func testInboundVless_XHTTP_Reality(t *testing.T, getConfig func() (inbound.VlessOption, outbound.VlessOption), mode string) {
	t.Run("nosplit", func(t *testing.T) {
		t.Run("single", func(t *testing.T) {
			inboundOptions, outboundOptions := getConfig()
			testInboundVless(t, inboundOptions, outboundOptions)
		})

		t.Run("reuse", func(t *testing.T) {
			inboundOptions, outboundOptions := getConfig()
			testInboundVless(t, inboundOptions, withXHTTPReuse(outboundOptions))
		})
	})

	t.Run("split", func(t *testing.T) {
		if mode == "stream-one" { // stream-one not supported download settings
			return
		}

		t.Run("single", func(t *testing.T) {
			inboundOptions, outboundOptions := getConfig()
			outboundOptions.XHTTPOpts.DownloadSettings = &outbound.XHTTPDownloadSettings{}
			testInboundVless(t, inboundOptions, outboundOptions)
		})

		t.Run("reuse", func(t *testing.T) {
			inboundOptions, outboundOptions := getConfig()
			outboundOptions.XHTTPOpts.DownloadSettings = &outbound.XHTTPDownloadSettings{}
			testInboundVless(t, inboundOptions, withXHTTPReuse(outboundOptions))
		})
	})
}

func TestInboundVless_XHTTP_Encryption(t *testing.T) {
	privateKeyBase64, passwordBase64, _, err := encryption.GenX25519("")
	if err != nil {
		t.Fatal(err)
		return
	}
	testCases := []struct {
		mode string
	}{
		{mode: "auto"},
		{mode: "stream-one"},
		{mode: "stream-up"},
		{mode: "packet-up"},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.mode, func(t *testing.T) {
			getConfig := func() (inbound.VlessOption, outbound.VlessOption) {
				inboundOptions := inbound.VlessOption{
					Decryption: "mlkem768x25519plus.native.600s." + privateKeyBase64,
					XHTTPConfig: inbound.XHTTPConfig{
						Path: "/vless-xhttp",
						Host: "example.com",
						Mode: testCase.mode,
					},
				}
				outboundOptions := outbound.VlessOption{
					Encryption: "mlkem768x25519plus.native.0rtt." + passwordBase64,
					Network:    "xhttp",
					XHTTPOpts: outbound.XHTTPOptions{
						Path: "/vless-xhttp",
						Host: "example.com",
						Mode: testCase.mode,
					},
				}
				return inboundOptions, outboundOptions
			}
			testInboundVless_XHTTP_Encryption(t, getConfig, testCase.mode)
		})
	}
}

func testInboundVless_XHTTP_Encryption(t *testing.T, getConfig func() (inbound.VlessOption, outbound.VlessOption), mode string) {
	t.Run("nosplit", func(t *testing.T) {
		t.Run("single", func(t *testing.T) {
			inboundOptions, outboundOptions := getConfig()
			testInboundVless(t, inboundOptions, outboundOptions)
		})

		t.Run("reuse", func(t *testing.T) {
			inboundOptions, outboundOptions := getConfig()
			testInboundVless(t, inboundOptions, withXHTTPReuse(outboundOptions))
		})
	})

	t.Run("split", func(t *testing.T) {
		if mode == "stream-one" { // stream-one not supported download settings
			return
		}

		t.Run("single", func(t *testing.T) {
			inboundOptions, outboundOptions := getConfig()
			outboundOptions.XHTTPOpts.DownloadSettings = &outbound.XHTTPDownloadSettings{}
			testInboundVless(t, inboundOptions, outboundOptions)
		})

		t.Run("reuse", func(t *testing.T) {
			inboundOptions, outboundOptions := getConfig()
			outboundOptions.XHTTPOpts.DownloadSettings = &outbound.XHTTPDownloadSettings{}
			testInboundVless(t, inboundOptions, withXHTTPReuse(outboundOptions))
		})
	})
}

func TestInboundVless_XHTTP_H1(t *testing.T) {
	testCases := []struct {
		mode string
	}{
		{mode: "auto"},
		{mode: "stream-one"},
		{mode: "stream-up"},
		{mode: "packet-up"},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.mode, func(t *testing.T) {
			getConfig := func() (inbound.VlessOption, outbound.VlessOption) {
				inboundOptions := inbound.VlessOption{
					Certificate: tlsCertificate,
					PrivateKey:  tlsPrivateKey,
					XHTTPConfig: inbound.XHTTPConfig{
						Path: "/vless-xhttp",
						Host: "example.com",
						Mode: testCase.mode,
					},
				}
				outboundOptions := outbound.VlessOption{
					TLS:         true,
					Fingerprint: tlsFingerprint,
					Network:     "xhttp",
					ALPN:        []string{"http/1.1"},
					XHTTPOpts: outbound.XHTTPOptions{
						Path: "/vless-xhttp",
						Host: "example.com",
						Mode: testCase.mode,
					},
				}
				return inboundOptions, outboundOptions
			}
			testInboundVless_XHTTP(t, getConfig, testCase.mode)
		})
	}
}

func TestInboundVless_XHTTP_H1_Encryption(t *testing.T) {
	privateKeyBase64, passwordBase64, _, err := encryption.GenX25519("")
	if err != nil {
		t.Fatal(err)
		return
	}
	testCases := []struct {
		mode string
	}{
		{mode: "auto"},
		{mode: "stream-one"},
		{mode: "stream-up"},
		{mode: "packet-up"},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.mode, func(t *testing.T) {
			getConfig := func() (inbound.VlessOption, outbound.VlessOption) {
				inboundOptions := inbound.VlessOption{
					Decryption: "mlkem768x25519plus.native.600s." + privateKeyBase64,
					XHTTPConfig: inbound.XHTTPConfig{
						Path: "/vless-xhttp",
						Host: "example.com",
						Mode: testCase.mode,
					},
				}
				outboundOptions := outbound.VlessOption{
					Encryption: "mlkem768x25519plus.native.0rtt." + passwordBase64,
					Network:    "xhttp",
					ALPN:       []string{"http/1.1"},
					XHTTPOpts: outbound.XHTTPOptions{
						Path: "/vless-xhttp",
						Host: "example.com",
						Mode: testCase.mode,
					},
				}
				return inboundOptions, outboundOptions
			}
			testInboundVless_XHTTP_Encryption(t, getConfig, testCase.mode)
		})
	}
}

func withXHTTPReuse(out outbound.VlessOption) outbound.VlessOption {
	out.XHTTPOpts.ReuseSettings = &outbound.XHTTPReuseSettings{
		MaxConnections:   "0",
		MaxConcurrency:   "16-32",
		CMaxReuseTimes:   "0",
		HMaxRequestTimes: "600-900",
		HMaxReusableSecs: "1800-3000",
	}
	if out.XHTTPOpts.DownloadSettings != nil {
		out.XHTTPOpts.DownloadSettings.ReuseSettings = &outbound.XHTTPReuseSettings{
			MaxConnections:   "0",
			MaxConcurrency:   "16-32",
			CMaxReuseTimes:   "0",
			HMaxRequestTimes: "600-900",
			HMaxReusableSecs: "1800-3000",
		}
	}
	return out
}
