package inbound_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
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
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel

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
	if quic && winGo120 {
		return // subsequent tests frequently fail; skipping them for now.
	}
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
	testInboundTrustTunnelTLS(t, false)
}

func TestInboundTrustTunnel_QUIC(t *testing.T) {
	testInboundTrustTunnelTLS(t, true)
}

// what the client wrote before Close reaches the server whole.
func TestInboundTrustTunnelUploadThenClose(t *testing.T) {
	for _, quic := range []bool{false, true} {
		in := inbound.TrustTunnelOption{
			BaseOption:  inbound.BaseOption{NameStr: "trusttunnel_close_inbound", Listen: "127.0.0.1", Port: "0"},
			Users:       []inbound.AuthUser{{Username: "test", Password: userUUID}},
			Certificate: tlsCertificate, PrivateKey: tlsPrivateKey,
		}
		out := outbound.TrustTunnelOption{Name: "trusttunnel_close_outbound", UserName: "test", Password: userUUID, Fingerprint: tlsFingerprint, Quic: quic}
		if quic {
			in.Network, in.CongestionController = []string{"udp"}, "bbr"
		}
		server, err := inbound.NewTrustTunnel(&in)
		if err != nil {
			t.Fatal(err)
		}
		tunnel := NewHttpTestTunnel()
		got := make(chan int64, 1)
		tunnel.HandleTCPConnFn = func(conn net.Conn, _ *C.Metadata) {
			n, _ := io.Copy(io.Discard, conn)
			conn.Close()
			got <- n
		}
		if err := server.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		addrPort := netip.MustParseAddrPort(server.Address())
		out.Server, out.Port = addrPort.Addr().String(), int(addrPort.Port())
		out.DialerForAPI, out.TunnelForAPI = tunnel.NewDialer(), tunnel
		client, err := outbound.NewTrustTunnel(out)
		if err != nil {
			t.Fatal(err)
		}
		for _, size := range []int64{32 << 10, 4 << 20} { // a small upload closes before the stream is under way
			conn, err := client.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(make([]byte, size)); err != nil {
				t.Fatal(err)
			}
			conn.Close()
			select {
			case n := <-got:
				if n != size {
					t.Errorf("quic=%v: server got %d of %d bytes written before Close", quic, n, size)
				}
			case <-time.After(10 * time.Second):
				t.Errorf("quic=%v: server did not see the end of a %d-byte upload", quic, size)
			}
		}
		client.Close()
		server.Close()
		tunnel.Close()
	}
}
