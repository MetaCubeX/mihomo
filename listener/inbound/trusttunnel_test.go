package inbound_test

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
)

func testInboundTrustTunnel(t *testing.T, inboundOptions inbound.TrustTunnelOption, outboundOptions outbound.TrustTunnelOption) {
	t.Parallel()
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "trusttunnel_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Users = []inbound.AuthUser{{Username: "test", Password: userUUID}}
	in, err := inbound.NewTrustTunnel(&inboundOptions)
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

	outboundOptions.Name = "trusttunnel_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.UserName = "test"
	outboundOptions.Password = userUUID

	out, err := outbound.NewTrustTunnel(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)
}

func testInboundTrustTunnelTLS(t *testing.T, quic bool) {
	inboundOptions := inbound.TrustTunnelOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	}
	outboundOptions := outbound.TrustTunnelOption{
		Fingerprint: tlsFingerprint,
		HealthCheck: true,
	}
	if quic {
		inboundOptions.Network = []string{"udp"}
		inboundOptions.CongestionController = "bbr"
		outboundOptions.Quic = true
	}
	testInboundTrustTunnel(t, inboundOptions, outboundOptions)
	t.Run("ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundTrustTunnel(t, inboundOptions, outboundOptions)
	})
	t.Run("mTLS", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.ClientAuthCert = tlsAuthCertificate
		outboundOptions.Certificate = tlsAuthCertificate
		outboundOptions.PrivateKey = tlsAuthPrivateKey
		testInboundTrustTunnel(t, inboundOptions, outboundOptions)
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
		testInboundTrustTunnel(t, inboundOptions, outboundOptions)
	})
}

func TestInboundTrustTunnel_H2(t *testing.T) {
	testInboundTrustTunnelTLS(t, true)
}

func TestInboundTrustTunnel_QUIC(t *testing.T) {
	testInboundTrustTunnelTLS(t, true)
}
