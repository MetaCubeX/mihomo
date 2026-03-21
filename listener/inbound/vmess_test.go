package inbound_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/stretchr/testify/assert"
)

func testInboundVMess(t *testing.T, inboundOptions inbound.VmessOption, outboundOptions outbound.VmessOption) {
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

	out, err := outbound.NewVmess(outboundOptions)
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

func TestInboundVMess_Basic(t *testing.T) {
	inboundOptions := inbound.VmessOption{}
	outboundOptions := outbound.VmessOption{}
	testInboundVMess(t, inboundOptions, outboundOptions)
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
