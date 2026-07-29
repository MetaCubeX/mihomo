package inbound_test

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
)

func TestInboundShadowQuic(t *testing.T) {
	for _, test := range []struct {
		name    string
		version string
	}{
		{name: "v1", version: "v1"},
		{name: "v2", version: "v2"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			testInboundShadowQuic(t, test.version)
		})
	}
}

func testInboundShadowQuic(t *testing.T, version string) {
	const username = "shadowquic-user"
	const password = "shadowquic-password"

	inboundOptions := inbound.ShadowQuicOption{
		BaseOption: inbound.BaseOption{
			NameStr: "shadowquic_inbound",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		ALPN:                 []string{"h3"},
		QUICVersions:         []string{version},
		ZeroRTT:              true,
		MaxIdleTime:          30000,
		MaxDatagramFrameSize: 1400,
		Users:                []inbound.ShadowQuicUser{{Username: username, Password: password}},
		JLSUpstream:          inbound.ShadowQuicJLSUpstream{Addr: "127.0.0.1:1"},
	}
	in, err := inbound.NewShadowQuic(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	tunnel.HandleUDPPacketFn = func(packet C.UDPPacket, metadata *C.Metadata) {
		packet.Drop()
		t.Errorf("authenticated ShadowQUIC connection unexpectedly accessed JLS upstream %s", metadata.RemoteAddress())
	}

	if !assert.NoError(t, in.Listen(tunnel)) {
		return
	}
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	outboundOptions := outbound.ShadowQuicOption{
		Name:                 "shadowquic_outbound",
		Server:               addrPort.Addr().String(),
		Port:                 int(addrPort.Port()),
		ALPN:                 []string{"h3"},
		QUICVersions:         []string{version},
		ZeroRTT:              true,
		MaxDatagramFrameSize: 1400,
		Username:             username,
		Password:             password,
	}
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel
	out, err := outbound.NewShadowQuic(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)
}
