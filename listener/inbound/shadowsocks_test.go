package inbound_test

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/kcptun"
	shadowtls "github.com/metacubex/mihomo/transport/sing-shadowtls"

	shadowsocks "github.com/metacubex/sing-shadowsocks"
	"github.com/metacubex/sing-shadowsocks/shadowaead"
	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
	"github.com/metacubex/sing-shadowsocks/shadowstream"
	"github.com/stretchr/testify/assert"
)

var noneList = []string{shadowsocks.MethodNone}
var shadowsocksCipherLists = [][]string{noneList, shadowaead.List, shadowaead_2022.List, shadowstream.List}
var shadowsocksCipherShortLists = [][]string{noneList, shadowaead.List[:5]} // for test shadowTLS and kcptun
var shadowsocksPassword32 string
var shadowsocksPassword16 string

func init() {
	passwordBytes := make([]byte, 32)
	rand.Read(passwordBytes)
	shadowsocksPassword32 = base64.StdEncoding.EncodeToString(passwordBytes)
	shadowsocksPassword16 = base64.StdEncoding.EncodeToString(passwordBytes[:16])
}

func testInboundShadowSocks(t *testing.T, inboundOptions inbound.ShadowSocksOption, outboundOptions outbound.ShadowSocksOption, cipherLists [][]string, enableSingMux bool) {
	t.Parallel()
	for _, cipherList := range cipherLists {
		for i, cipher := range cipherList {
			enableSingMux := enableSingMux && i == 0
			cipher := cipher
			t.Run(cipher, func(t *testing.T) {
				inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
				inboundOptions.Cipher = cipher
				outboundOptions.Cipher = cipher
				testInboundShadowSocks0(t, inboundOptions, outboundOptions, enableSingMux)
			})
		}
	}
}

func testInboundShadowSocks0(t *testing.T, inboundOptions inbound.ShadowSocksOption, outboundOptions outbound.ShadowSocksOption, enableSingMux bool) {
	t.Parallel()
	password := shadowsocksPassword32
	if strings.Contains(inboundOptions.Cipher, "-128-") {
		password = shadowsocksPassword16
	}
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "shadowsocks_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Password = password
	in, err := inbound.NewShadowSocks(&inboundOptions)
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

	outboundOptions.Name = "shadowsocks_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.Password = password

	out, err := outbound.NewShadowSocks(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)

	if enableSingMux {
		testSingMux(t, tunnel, out)
	}
}

func TestInboundShadowSocks_Basic(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{}
	outboundOptions := outbound.ShadowSocksOption{}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherLists, true)
}

func testInboundShadowSocksShadowTls(t *testing.T, inboundOptions inbound.ShadowSocksOption, outboundOptions outbound.ShadowSocksOption) {
	t.Parallel()
	t.Run("Conn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, true)
	})
	t.Run("UConn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		outboundOptions.ClientFingerprint = "chrome"
		testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, true)
	})
}

func TestInboundShadowSocks_ShadowTlsv1(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   1,
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     shadowtls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "fingerprint": tlsFingerprint, "version": 1},
	}
	testInboundShadowSocksShadowTls(t, inboundOptions, outboundOptions)
}

func TestInboundShadowSocks_ShadowTlsv2(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   2,
			Password:  shadowsocksPassword16,
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     shadowtls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version": 2},
	}
	outboundOptions.PluginOpts["alpn"] = []string{"http/1.1"} // shadowtls v2 work confuse with http/2 server, so we set alpn to http/1.1 to pass the test
	testInboundShadowSocksShadowTls(t, inboundOptions, outboundOptions)
}

func TestInboundShadowSocks_ShadowTlsv3(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   3,
			Users:     []inbound.ShadowTLSUser{{Name: "test", Password: shadowsocksPassword16}},
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     shadowtls.Mode,
		PluginOpts: map[string]any{"host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version": 3},
	}
	testInboundShadowSocksShadowTls(t, inboundOptions, outboundOptions)
}

func TestInboundShadowSocks_KcpTun(t *testing.T) {
	inboundOptions := inbound.ShadowSocksOption{
		KcpTun: inbound.KcpTun{
			Enable: true,
			Key:    shadowsocksPassword16,
		},
	}
	outboundOptions := outbound.ShadowSocksOption{
		Plugin:     kcptun.Mode,
		PluginOpts: map[string]any{"key": shadowsocksPassword16},
	}
	testInboundShadowSocks(t, inboundOptions, outboundOptions, shadowsocksCipherShortLists, false)
}
