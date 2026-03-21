package inbound_test

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
)

func testInboundHysteria2(t *testing.T, inboundOptions inbound.Hysteria2Option, outboundOptions outbound.Hysteria2Option) {
	t.Parallel()
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "hysteria2_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Users = map[string]string{"test": userUUID}
	in, err := inbound.NewHysteria2(&inboundOptions)
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

	outboundOptions.Name = "hysteria2_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.Password = userUUID

	out, err := outbound.NewHysteria2(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)
}

func testInboundHysteria2TLS(t *testing.T, inboundOptions inbound.Hysteria2Option, outboundOptions outbound.Hysteria2Option) {
	testInboundHysteria2(t, inboundOptions, outboundOptions)
	t.Run("ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundHysteria2(t, inboundOptions, outboundOptions)
	})
	t.Run("mTLS", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.ClientAuthCert = tlsAuthCertificate
		outboundOptions.Certificate = tlsAuthCertificate
		outboundOptions.PrivateKey = tlsAuthPrivateKey
		testInboundHysteria2(t, inboundOptions, outboundOptions)
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
		testInboundHysteria2(t, inboundOptions, outboundOptions)
	})
}

func TestInboundHysteria2_TLS(t *testing.T) {
	inboundOptions := inbound.Hysteria2Option{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	}
	outboundOptions := outbound.Hysteria2Option{
		Fingerprint: tlsFingerprint,
	}
	testInboundHysteria2TLS(t, inboundOptions, outboundOptions)
}

func TestInboundHysteria2_Salamander(t *testing.T) {
	inboundOptions := inbound.Hysteria2Option{
		Certificate:  tlsCertificate,
		PrivateKey:   tlsPrivateKey,
		Obfs:         "salamander",
		ObfsPassword: userUUID,
	}
	outboundOptions := outbound.Hysteria2Option{
		Fingerprint:  tlsFingerprint,
		Obfs:         "salamander",
		ObfsPassword: userUUID,
	}
	testInboundHysteria2TLS(t, inboundOptions, outboundOptions)
}

func TestInboundHysteria2_Brutal(t *testing.T) {
	inboundOptions := inbound.Hysteria2Option{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
		Up:          "30 Mbps",
		Down:        "200 Mbps",
	}
	outboundOptions := outbound.Hysteria2Option{
		Fingerprint: tlsFingerprint,
		Up:          "30 Mbps",
		Down:        "200 Mbps",
	}
	testInboundHysteria2TLS(t, inboundOptions, outboundOptions)
}
