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
)

// what the client wrote before Close reaches the server, and the server
// sees the end of the upload, in every XHTTP mode.
func TestInboundVlessXHTTPUploadThenClose(t *testing.T) {
	for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
		t.Run(mode, func(t *testing.T) {
			in, err := inbound.NewVless(&inbound.VlessOption{
				BaseOption:  inbound.BaseOption{NameStr: "vless_xhttp_close_inbound", Listen: "127.0.0.1", Port: "0"},
				Users:       []inbound.VlessUser{{Username: "test", UUID: userUUID}},
				Certificate: tlsCertificate, PrivateKey: tlsPrivateKey,
				XHTTPConfig: inbound.XHTTPConfig{Path: "/vless-xhttp", Host: "example.com", Mode: mode},
			})
			if err != nil {
				t.Fatal(err)
			}
			tunnel := NewHttpTestTunnel()
			defer tunnel.Close()
			got := make(chan int64, 1)
			tunnel.HandleTCPConnFn = func(conn net.Conn, _ *C.Metadata) {
				n, _ := io.Copy(io.Discard, conn)
				conn.Close()
				got <- n
			}
			if err := in.Listen(tunnel); err != nil {
				t.Fatal(err)
			}
			defer in.Close()
			addrPort := netip.MustParseAddrPort(in.Address())
			outOptions := outbound.VlessOption{
				Name: "vless_xhttp_close_outbound", Server: addrPort.Addr().String(), Port: int(addrPort.Port()), UUID: userUUID,
				TLS: true, Fingerprint: tlsFingerprint, ServerName: "example.org", ClientFingerprint: "chrome", Network: "xhttp",
				XHTTPOpts: outbound.XHTTPOptions{Path: "/vless-xhttp", Host: "example.com", Mode: mode},
			}
			outOptions.DialerForAPI, outOptions.TunnelForAPI = tunnel.NewDialer(), tunnel
			out, err := outbound.NewVless(outOptions)
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			for _, size := range []int64{32 << 10, 4 << 20} {
				conn, err := out.DialContext(context.Background(), &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443})
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
						t.Errorf("server got %d of %d bytes written before Close", n, size)
					}
				case <-time.After(10 * time.Second):
					t.Errorf("server did not see the end of a %d-byte upload", size)
				}
			}
		})
	}
}
