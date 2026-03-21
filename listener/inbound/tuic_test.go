package inbound_test

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
)

var tuicCCs = []string{"cubic", "new_reno", "bbr"}

func testInboundTuic(t *testing.T, inboundOptions inbound.TuicOption, outboundOptions outbound.TuicOption) {
	t.Parallel()
	inboundOptions.Users = map[string]string{userUUID: userUUID}
	inboundOptions.Token = []string{userUUID}

	for _, tuicCC := range tuicCCs {
		tuicCC := tuicCC
		t.Run(tuicCC, func(t *testing.T) {
			t.Parallel()
			t.Run("v4", func(t *testing.T) {
				inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
				outboundOptions.Token = userUUID
				outboundOptions.CongestionController = tuicCC
				inboundOptions.CongestionController = tuicCC
				testInboundTuic0(t, inboundOptions, outboundOptions)
			})
			t.Run("v5", func(t *testing.T) {
				inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
				outboundOptions.UUID = userUUID
				outboundOptions.Password = userUUID
				outboundOptions.CongestionController = tuicCC
				inboundOptions.CongestionController = tuicCC
				testInboundTuic0(t, inboundOptions, outboundOptions)
			})
		})
	}
}

func testInboundTuic0(t *testing.T, inboundOptions inbound.TuicOption, outboundOptions outbound.TuicOption) {
	t.Parallel()
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "tuic_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	in, err := inbound.NewTuic(&inboundOptions)
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

	outboundOptions.Name = "tuic_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())

	out, err := outbound.NewTuic(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)
}

func TestInboundTuic_TLS(t *testing.T) {
	inboundOptions := inbound.TuicOption{
		Certificate:           tlsCertificate,
		PrivateKey:            tlsPrivateKey,
		AuthenticationTimeout: 5000,
	}
	outboundOptions := outbound.TuicOption{
		Fingerprint: tlsFingerprint,
	}
	testInboundTuic(t, inboundOptions, outboundOptions)
	t.Run("ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundTuic(t, inboundOptions, outboundOptions)
	})
	t.Run("mTLS", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.ClientAuthCert = tlsAuthCertificate
		outboundOptions.Certificate = tlsAuthCertificate
		outboundOptions.PrivateKey = tlsAuthPrivateKey
		testInboundTuic(t, inboundOptions, outboundOptions)
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
		testInboundTuic(t, inboundOptions, outboundOptions)
	})
}
