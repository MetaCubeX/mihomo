package inbound_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/jls"
	"github.com/metacubex/mihomo/transport/restls"
	"github.com/metacubex/mihomo/transport/shadowtls"

	"github.com/stretchr/testify/assert"
)

func testInboundSnell(t *testing.T, inboundOptions inbound.SnellOption, outboundOptions outbound.SnellOption) {
	t.Parallel()
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "snell_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Psk = userUUID
	in, err := inbound.NewSnell(&inboundOptions)
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

	outboundOptions.Name = "snell_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.Psk = userUUID
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel

	out, err := outbound.NewSnell(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)
}

func TestInboundSnell(t *testing.T) {
	testCase := []struct {
		name    string
		version int
	}{
		{"v1", 1},
		{"v2", 2},
		{"v3", 3},
		{"v4", 4},
		{"v5", 5},
	}
	for _, tc := range testCase {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			inboundOptions := inbound.SnellOption{Version: tc.version}
			outboundOptions := outbound.SnellOption{Version: tc.version}
			testInboundSnell(t, inboundOptions, outboundOptions)
		})
	}
}

func testInboundSnellUTLS(t *testing.T, inboundOptions inbound.SnellOption, outboundOptions outbound.SnellOption) {
	t.Parallel()
	t.Run("Conn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		testInboundSnell(t, inboundOptions, outboundOptions)
	})
	t.Run("UConn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		outboundOptions.ClientFingerprint = "chrome"
		testInboundSnell(t, inboundOptions, outboundOptions)
	})
}

func TestInboundSnell_ShadowTlsv2(t *testing.T) {
	inboundOptions := inbound.SnellOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   2,
			Password:  shadowsocksPassword16,
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.SnellOption{
		Version:  5,
		ObfsOpts: map[string]any{"mode": shadowtls.Mode, "host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version": 2},
	}
	outboundOptions.ObfsOpts["alpn"] = []string{"http/1.1"} // shadowtls v2 work confuse with http/2 server, so we set alpn to http/1.1 to pass the test
	testInboundSnellUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundSnell_ShadowTlsv3(t *testing.T) {
	inboundOptions := inbound.SnellOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   3,
			Users:     []inbound.ShadowTLSUser{{Name: "test", Password: shadowsocksPassword16}},
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.SnellOption{
		Version:  5,
		ObfsOpts: map[string]any{"mode": shadowtls.Mode, "host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version": 3},
	}
	testInboundSnellUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundSnell_Restls(t *testing.T) {
	const password = "restls-password"
	inboundOptions := inbound.SnellOption{
		ResTLS: inbound.ResTLS{
			Enable:   true,
			Dest:     net.JoinHostPort(realityDest, "443"),
			Password: password,
		},
	}
	outboundOptions := outbound.SnellOption{
		Version:  5,
		ObfsOpts: map[string]any{"mode": restls.Mode, "host": realityDest, "password": password, "fingerprint": tlsFingerprint, "version-hint": "tls13"},
	}
	testInboundSnellUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundSnell_JLS(t *testing.T) {
	const username = "jls-user"
	const password = "jls-password"
	inboundOptions := inbound.SnellOption{
		JLSConfig: inbound.JLSConfig{
			Enable: true,
			Users:  []inbound.JLSUser{{Username: username, Password: password}},
			SNI:    realityDest,
			Dest:   net.JoinHostPort(realityDest, "443"),
		},
	}
	outboundOptions := outbound.SnellOption{
		Version:  5,
		ObfsOpts: map[string]any{"mode": jls.Mode, "host": realityDest, "username": username, "password": password},
	}
	testInboundSnellUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundSnell_V6(t *testing.T) {
	for _, mode := range []string{"default", "unshaped", "unsafe-raw"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			t.Run("TCP", func(t *testing.T) {
				inboundOptions := inbound.SnellOption{Version: 6, Mode: mode}
				outboundOptions := outbound.SnellOption{Version: 6, Mode: mode}
				testInboundSnell(t, inboundOptions, outboundOptions)
			})
			t.Run("TCPReuse", func(t *testing.T) {
				inboundOptions := inbound.SnellOption{Version: 6, Mode: mode}
				outboundOptions := outbound.SnellOption{Version: 6, Mode: mode, Reuse: true}
				testInboundSnell(t, inboundOptions, outboundOptions)
			})
			t.Run("UDP", func(t *testing.T) {
				testInboundSnellV6UDP(t, mode)
			})
		})
	}
}

func TestInboundSnell_V6_ShadowTlsv3(t *testing.T) {
	inboundOptions := inbound.SnellOption{
		Version: 6,
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   3,
			Users:     []inbound.ShadowTLSUser{{Name: "test", Password: shadowsocksPassword16}},
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.SnellOption{
		Version:  6,
		ObfsOpts: map[string]any{"mode": shadowtls.Mode, "host": realityDest, "password": shadowsocksPassword16, "fingerprint": tlsFingerprint, "version": 3},
	}
	testInboundSnellUTLS(t, inboundOptions, outboundOptions)
}

// testInboundSnellV6UDP runs a UDP-over-TCP echo through the v6 inbound: the
// test tunnel reflects every datagram back to the source it came from.
func testInboundSnellV6UDP(t *testing.T, mode string) {
	t.Parallel()
	inboundOptions := inbound.SnellOption{
		BaseOption: inbound.BaseOption{
			NameStr: "snell_inbound_udp",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Psk:     userUUID,
		Version: 6,
		Mode:    mode,
		UDP:     true,
	}
	in, err := inbound.NewSnell(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	tunnel.HandleUDPPacketFn = func(packet C.UDPPacket, metadata *C.Metadata) {
		defer packet.Drop()
		if !assert.Equal(t, C.SNELL, metadata.Type) {
			return
		}
		_, err := packet.WriteBack(packet.Data(), metadata.UDPAddr())
		assert.NoError(t, err)
	}

	err = in.Listen(tunnel)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	outboundOptions := outbound.SnellOption{
		Name:    "snell_outbound_udp",
		Server:  addrPort.Addr().String(),
		Port:    int(addrPort.Port()),
		Psk:     userUUID,
		Version: 6,
		Mode:    mode,
		UDP:     true,
	}
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel
	out, err := outbound.NewSnell(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
	pc, err := out.ListenPacketContext(ctx, &C.Metadata{
		NetWork: C.UDP,
		DstIP:   netip.MustParseAddr("127.0.0.1"),
		DstPort: 53,
	})
	if !assert.NoError(t, err) {
		return
	}
	defer pc.Close()

	for round := 0; round < 5; round++ {
		message := make([]byte, 1200)
		_, err = rand.Read(message)
		if !assert.NoError(t, err) {
			return
		}
		_, err = pc.WriteTo(message, target)
		if !assert.NoError(t, err) {
			return
		}

		received := make([]byte, 2048)
		if !assert.NoError(t, pc.SetReadDeadline(time.Now().Add(10*time.Second))) {
			return
		}
		n, from, err := pc.ReadFrom(received)
		if !assert.NoError(t, err, "round %d", round) {
			return
		}
		assert.Equal(t, target.String(), from.String())
		assert.True(t, bytes.Equal(message, received[:n]), "round %d payload mismatch", round)
	}
}

func TestInboundSnell_V6_Validation(t *testing.T) {
	t.Parallel()
	newInbound := func(options inbound.SnellOption) error {
		options.BaseOption = inbound.BaseOption{
			NameStr: "snell_inbound_validation",
			Listen:  "127.0.0.1",
			Port:    "0",
		}
		if options.Psk == "" {
			options.Psk = userUUID
		}
		in, err := inbound.NewSnell(&options)
		if err != nil {
			return err
		}
		tunnel := NewHttpTestTunnel()
		defer tunnel.Close()
		err = in.Listen(tunnel)
		if err == nil {
			_ = in.Close()
		}
		return err
	}

	assert.Error(t, newInbound(inbound.SnellOption{Version: 6, Psk: "short"}), "psk shorter than 12 bytes must be rejected")
	assert.Error(t, newInbound(inbound.SnellOption{Version: 6, ObfsOpts: inbound.SnellObfsOption{Mode: "http"}}), "v6 has no simple-obfs layer")
	assert.Error(t, newInbound(inbound.SnellOption{Version: 6, ObfsOpts: inbound.SnellObfsOption{Mode: "tls"}}), "v6 has no simple-obfs layer")
	assert.Error(t, newInbound(inbound.SnellOption{Version: 6, Mode: "bogus"}), "unknown mode must be rejected")
	assert.Error(t, newInbound(inbound.SnellOption{Version: 4, Mode: "unshaped"}), "mode is v6 only")
	assert.Error(t, newInbound(inbound.SnellOption{Version: 7}), "unknown version must be rejected")
	assert.NoError(t, newInbound(inbound.SnellOption{Version: 6, Mode: "unshaped"}))
}
