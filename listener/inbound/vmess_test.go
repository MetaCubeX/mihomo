package inbound_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/tlsmirror"

	"github.com/stretchr/testify/assert"
)

func testInboundVMess(t *testing.T, inboundOptions inbound.VmessOption, outboundOptions outbound.VmessOption) {
	testInboundVMessWithMuxCool(t, inboundOptions, outboundOptions, false)
}

func testInboundVMessWithMuxCool(t *testing.T, inboundOptions inbound.VmessOption, outboundOptions outbound.VmessOption, runMuxCool bool) {
	t.Parallel()
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "vmess_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Users = []inbound.VmessUser{
		{Username: "test", UUID: userUUID, AlterID: 0},
	}
	in, err := inbound.NewVmess(&inboundOptions)
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

	outboundOptions.Name = "vmess_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.UUID = userUUID
	outboundOptions.AlterID = 0
	outboundOptions.Cipher = "auto"
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel

	out, err := outbound.NewVmess(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)

	if outboundOptions.Network == "grpc" { // don't test sing-mux over grpc
		return
	}
	if outboundOptions.Network == "mkcp" { // don't test sing-mux over mkcp
		return
	}
	if outboundOptions.Network == "mekya" { // don't test sing-mux over mekya
		return
	}
	if outboundOptions.TLSMirrorOpts.PrimaryKey != "" { // don't test sing-mux over tlsmirror
		return
	}
	testSingMux(t, tunnel, out)
	if runMuxCool {
		testMuxCool(t, tunnel, out)
	}
}

func TestInboundVMess_Basic(t *testing.T) {
	inboundOptions := inbound.VmessOption{}
	outboundOptions := outbound.VmessOption{}
	testInboundVMess(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_MuxCool(t *testing.T) {
	testInboundVMessWithMuxCool(t, inbound.VmessOption{}, outbound.VmessOption{}, true)
}

func testInboundVMessTLS(t *testing.T, inboundOptions inbound.VmessOption, outboundOptions outbound.VmessOption) {
	testInboundVMess(t, inboundOptions, outboundOptions)
	t.Run("ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundVMess(t, inboundOptions, outboundOptions)
	})
	t.Run("mTLS", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.ClientAuthCert = tlsAuthCertificate
		outboundOptions.Certificate = tlsAuthCertificate
		outboundOptions.PrivateKey = tlsAuthPrivateKey
		testInboundVMess(t, inboundOptions, outboundOptions)
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
		testInboundVMess(t, inboundOptions, outboundOptions)
	})
}

func testInboundVMessTLSMirror(t *testing.T, inboundOptions inbound.VmessOption, outboundOptions outbound.VmessOption) {
	testInboundVMess(t, inboundOptions, outboundOptions)
	t.Run("uTLS", func(t *testing.T) {
		outboundOptions := outboundOptions
		outboundOptions.ClientFingerprint = "chrome"
		testInboundVMess(t, inboundOptions, outboundOptions)
	})
}

var tlsMirrorPrimaryKey = tlsmirror.GeneratePrimaryKey()

func TestInboundVMess_TLS(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	}
	outboundOptions := outbound.VmessOption{
		TLS:         true,
		Fingerprint: tlsFingerprint,
	}
	testInboundVMessTLS(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_Ws(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		WsPath: "/ws",
	}
	outboundOptions := outbound.VmessOption{
		Network: "ws",
		WSOpts: outbound.WSOptions{
			Path: "/ws",
		},
	}
	testInboundVMess(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_MKCP(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		inboundOptions := inbound.VmessOption{
			MKCPConfig: inbound.MKCPConfig{Enable: true},
		}
		outboundOptions := outbound.VmessOption{
			Network: "mkcp",
		}
		testInboundVMess(t, inboundOptions, outboundOptions)
	})

	tests := []struct {
		name   string
		seed   string
		header string
	}{
		{name: "seed", seed: "mihomo-mkcp-test"},
		{name: "header srtp", header: "srtp"},
		{name: "seed header srtp", seed: "mihomo-mkcp-test", header: "srtp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inboundOptions := inbound.VmessOption{
				MKCPConfig: inbound.MKCPConfig{
					Enable: true,
					Seed:   tt.seed,
					Header: tt.header,
				},
			}
			outboundOptions := outbound.VmessOption{
				Network: "mkcp",
				MKCPOpts: outbound.MKCPOptions{
					Seed:   tt.seed,
					Header: tt.header,
				},
			}
			testInboundVMess(t, inboundOptions, outboundOptions)
		})
	}
}

func TestInboundVMess_Mekya(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		MekyaConfig: inbound.MekyaConfig{
			Enable:                         true,
			MaxWriteSize:                   1 << 20,
			MaxWriteDurationMs:             100,
			MaxSimultaneousWriteConnection: 16,
			PacketWritingBuffer:            1024,
			KCP: inbound.MKCPConfig{
				TTI: 15,
			},
		},
	}
	outboundOptions := outbound.VmessOption{
		Network: "mekya",
		MekyaOpts: outbound.MekyaOptions{
			MaxWriteDelay:          20,
			MaxRequestSize:         96000,
			PollingIntervalInitial: 20,
			H2PoolSize:             8,
			KCP: outbound.MKCPOptions{
				TTI: 15,
			},
		},
	}
	testInboundVMess(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_TLSMirror(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		TLSMirrorConfig: inbound.TLSMirrorConfig{
			PrimaryKey: tlsMirrorPrimaryKey,
			Dest:       net.JoinHostPort(realityDest, "443"),
		},
	}
	outboundOptions := outbound.VmessOption{
		ServerName: realityDest,
		TLS:        true,
		TLSMirrorOpts: outbound.TLSMirrorOptions{
			PrimaryKey: tlsMirrorPrimaryKey,
		},
	}
	if !realityRealDial {
		outboundOptions.Fingerprint = tlsFingerprint
	}
	testInboundVMessTLSMirror(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_TLSMirror_Ws(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		WsPath: "/ws",
		TLSMirrorConfig: inbound.TLSMirrorConfig{
			PrimaryKey: tlsMirrorPrimaryKey,
			Dest:       net.JoinHostPort(realityDest, "443"),
		},
	}
	outboundOptions := outbound.VmessOption{
		Network:    "ws",
		ServerName: realityDest,
		TLS:        true,
		WSOpts: outbound.WSOptions{
			Path: "/ws",
		},
		TLSMirrorOpts: outbound.TLSMirrorOptions{
			PrimaryKey: tlsMirrorPrimaryKey,
		},
	}
	if !realityRealDial {
		outboundOptions.Fingerprint = tlsFingerprint
	}
	testInboundVMessTLSMirror(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_TLSMirror_Grpc(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		GrpcServiceName: "GunService",
		TLSMirrorConfig: inbound.TLSMirrorConfig{
			PrimaryKey: tlsMirrorPrimaryKey,
			Dest:       net.JoinHostPort(realityDest, "443"),
		},
	}
	outboundOptions := outbound.VmessOption{
		Network:    "grpc",
		ServerName: realityDest,
		TLS:        true,
		GrpcOpts:   outbound.GrpcOptions{GrpcServiceName: "GunService"},
		TLSMirrorOpts: outbound.TLSMirrorOptions{
			PrimaryKey: tlsMirrorPrimaryKey,
		},
	}
	if !realityRealDial {
		outboundOptions.Fingerprint = tlsFingerprint
	}
	testInboundVMessTLSMirror(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_TLSMirror_AdvancedOptions(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		TLSMirrorConfig: inbound.TLSMirrorConfig{
			PrimaryKey:                tlsMirrorPrimaryKey,
			Dest:                      net.JoinHostPort(realityDest, "443"),
			ExplicitNonceCipherSuites: tlsmirror.RecommendedExplicitNonceCipherSuites,
			DeferInstanceDerivedWriteTime: inbound.TLSMirrorTimeSpec{
				BaseNanoseconds: 1000000,
			},
			TransportLayerPadding:       inbound.TLSMirrorTransportLayerPadding{Enabled: true},
			SequenceWatermarkingEnabled: true,
		},
	}
	outboundOptions := outbound.VmessOption{
		ServerName: realityDest,
		TLS:        true,
		TLSMirrorOpts: outbound.TLSMirrorOptions{
			PrimaryKey:                tlsMirrorPrimaryKey,
			ExplicitNonceCipherSuites: tlsmirror.RecommendedExplicitNonceCipherSuites,
			DeferInstanceDerivedWriteTime: outbound.TLSMirrorTimeSpec{
				BaseNanoseconds: 1000000,
			},
			TransportLayerPadding:       outbound.TLSMirrorTransportLayerPadding{Enabled: true},
			SequenceWatermarkingEnabled: true,
		},
	}
	if !realityRealDial {
		outboundOptions.Fingerprint = tlsFingerprint
	}
	testInboundVMessTLSMirror(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_TLSMirror_ConnectionEnrolment(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		TLSMirrorConfig: inbound.TLSMirrorConfig{
			PrimaryKey: tlsMirrorPrimaryKey,
			Dest:       net.JoinHostPort(realityDest, "443"),
			ConnectionEnrolment: &inbound.TLSMirrorConnectionEnrolment{
				PrimaryIngressOutbound: "tlsmirror-enrollment",
			},
		},
	}
	outboundOptions := outbound.VmessOption{
		ServerName: realityDest,
		TLS:        true,
		TLSMirrorOpts: outbound.TLSMirrorOptions{
			PrimaryKey: tlsMirrorPrimaryKey,
			ConnectionEnrolment: &outbound.TLSMirrorConnectionEnrolment{
				PrimaryIngressOutbound: "tlsmirror-enrollment",
			},
		},
	}
	if !realityRealDial {
		outboundOptions.Fingerprint = tlsFingerprint
	}
	testInboundVMessTLSMirror(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_TLSMirror_EmbeddedTrafficGenerator(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		TLSMirrorConfig: inbound.TLSMirrorConfig{
			PrimaryKey: tlsMirrorPrimaryKey,
			Dest:       net.JoinHostPort(realityDest, "443"),
		},
	}
	outboundOptions := outbound.VmessOption{
		ServerName: realityDest,
		TLS:        true,
		TLSMirrorOpts: outbound.TLSMirrorOptions{
			PrimaryKey: tlsMirrorPrimaryKey,
			EmbeddedTrafficGenerator: outbound.TLSMirrorTrafficGenerator{Steps: []outbound.TLSMirrorTrafficStep{{
				Host:                 realityDest,
				Path:                 httpPath + "?size=1",
				Method:               "GET",
				ConnectionReady:      true,
				ConnectionRecallExit: true,
				WaitTime: outbound.TLSMirrorTimeSpec{
					BaseNanoseconds: 1000000,
				},
				NextStep: []outbound.TLSMirrorTrafficTransferCandidate{{
					Weight:       1,
					GotoLocation: 0,
				}},
			}}},
		},
	}
	if !realityRealDial {
		outboundOptions.Fingerprint = tlsFingerprint
	}
	testInboundVMessTLSMirror(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_Ws_ed1(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		WsPath: "/ws",
	}
	outboundOptions := outbound.VmessOption{
		Network: "ws",
		WSOpts: outbound.WSOptions{
			Path: "/ws?ed=2048",
		},
	}
	testInboundVMess(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_Ws_ed2(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		WsPath: "/ws",
	}
	outboundOptions := outbound.VmessOption{
		Network: "ws",
		WSOpts: outbound.WSOptions{
			Path:                "/ws",
			MaxEarlyData:        2048,
			EarlyDataHeaderName: "Sec-WebSocket-Protocol",
		},
	}
	testInboundVMess(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_Ws_Upgrade1(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		WsPath: "/ws",
	}
	outboundOptions := outbound.VmessOption{
		Network: "ws",
		WSOpts: outbound.WSOptions{
			Path:             "/ws",
			V2rayHttpUpgrade: true,
		},
	}
	testInboundVMess(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_Ws_Upgrade2(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		WsPath: "/ws",
	}
	outboundOptions := outbound.VmessOption{
		Network: "ws",
		WSOpts: outbound.WSOptions{
			Path:                     "/ws",
			V2rayHttpUpgrade:         true,
			V2rayHttpUpgradeFastOpen: true,
		},
	}
	testInboundVMess(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_Wss1(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
		WsPath:      "/ws",
	}
	outboundOptions := outbound.VmessOption{
		TLS:         true,
		Fingerprint: tlsFingerprint,
		Network:     "ws",
		WSOpts: outbound.WSOptions{
			Path: "/ws",
		},
	}
	testInboundVMessTLS(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_Wss2(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		Certificate:     tlsCertificate,
		PrivateKey:      tlsPrivateKey,
		WsPath:          "/ws",
		GrpcServiceName: "GunService",
	}
	outboundOptions := outbound.VmessOption{
		TLS:         true,
		Fingerprint: tlsFingerprint,
		Network:     "ws",
		WSOpts: outbound.WSOptions{
			Path: "/ws",
		},
	}
	testInboundVMessTLS(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_Grpc1(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		Certificate:     tlsCertificate,
		PrivateKey:      tlsPrivateKey,
		GrpcServiceName: "GunService",
	}
	outboundOptions := outbound.VmessOption{
		TLS:         true,
		Fingerprint: tlsFingerprint,
		Network:     "grpc",
		GrpcOpts:    outbound.GrpcOptions{GrpcServiceName: "GunService"},
	}
	testInboundVMessTLS(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_Grpc2(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		Certificate:     tlsCertificate,
		PrivateKey:      tlsPrivateKey,
		WsPath:          "/ws",
		GrpcServiceName: "GunService",
	}
	outboundOptions := outbound.VmessOption{
		TLS:         true,
		Fingerprint: tlsFingerprint,
		Network:     "grpc",
		GrpcOpts:    outbound.GrpcOptions{GrpcServiceName: "GunService"},
	}
	testInboundVMessTLS(t, inboundOptions, outboundOptions)
}

func testInboundVMessUTLS(t *testing.T, inboundOptions inbound.VmessOption, outboundOptions outbound.VmessOption) {
	t.Parallel()
	t.Run("Conn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		testInboundVMess(t, inboundOptions, outboundOptions)
	})
	t.Run("UConn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		outboundOptions.ClientFingerprint = "chrome"
		testInboundVMess(t, inboundOptions, outboundOptions)
	})
}

func TestInboundVMess_ShadowTLS(t *testing.T) {
	const password = "shadow-tls-password"
	inboundOptions := inbound.VmessOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   3,
			Users:     []inbound.ShadowTLSUser{{Name: "test", Password: password}},
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.VmessOption{
		TLS:           true,
		ServerName:    realityDest,
		Fingerprint:   tlsFingerprint,
		ShadowTLSOpts: outbound.ShadowTLSOptions{Password: password, Version: 3},
	}
	testInboundVMessUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_Restls(t *testing.T) {
	const password = "restls-password"
	inboundOptions := inbound.VmessOption{
		ResTLS: inbound.ResTLS{
			Enable:   true,
			Dest:     net.JoinHostPort(realityDest, "443"),
			Password: password,
		},
	}
	outboundOptions := outbound.VmessOption{
		TLS:         true,
		ServerName:  realityDest,
		Fingerprint: tlsFingerprint,
		RestlsOpts:  outbound.RestlsOptions{Password: password, VersionHint: "tls13"},
	}
	testInboundVMessUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_JLS(t *testing.T) {
	const username = "jls-user"
	const password = "jls-password"
	inboundOptions := inbound.VmessOption{
		JLSConfig: inbound.JLSConfig{
			Enable: true,
			Users:  []inbound.JLSUser{{Username: username, Password: password}},
			SNI:    realityDest,
			Dest:   net.JoinHostPort(realityDest, "443"),
		},
	}
	outboundOptions := outbound.VmessOption{
		TLS:        true,
		ServerName: realityDest,
		JLSOpts:    outbound.JLSOptions{Username: username, Password: password},
	}
	testInboundVMessUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_Reality(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		RealityConfig: inbound.RealityConfig{
			Dest:        net.JoinHostPort(realityDest, "443"),
			PrivateKey:  realityPrivateKey,
			ShortID:     []string{realityShortid},
			ServerNames: []string{realityDest},
		},
	}
	outboundOptions := outbound.VmessOption{
		TLS:        true,
		ServerName: realityDest,
		RealityOpts: outbound.RealityOptions{
			PublicKey: realityPublickey,
			ShortID:   realityShortid,
		},
		ClientFingerprint: "chrome",
	}
	testInboundVMess(t, inboundOptions, outboundOptions)
}

func TestInboundVMess_Reality_Grpc(t *testing.T) {
	inboundOptions := inbound.VmessOption{
		RealityConfig: inbound.RealityConfig{
			Dest:        net.JoinHostPort(realityDest, "443"),
			PrivateKey:  realityPrivateKey,
			ShortID:     []string{realityShortid},
			ServerNames: []string{realityDest},
		},
		GrpcServiceName: "GunService",
	}
	outboundOptions := outbound.VmessOption{
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
	testInboundVMess(t, inboundOptions, outboundOptions)
}
