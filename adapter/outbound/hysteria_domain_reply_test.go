package outbound

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/hysteria/core"
	"github.com/metacubex/quic-go"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
)

func TestHysteriaDomainUDPWireReply(t *testing.T) {
	cert, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{DefaultALPN}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- func() error {
			session, err := listener.Accept(ctx)
			if err != nil {
				return err
			}
			defer session.CloseWithError(0, "")
			control, err := session.AcceptStream(ctx)
			if err != nil {
				return err
			}
			if _, err = core.ReadClientHello(control); err != nil {
				return err
			}
			if err = core.WriteServerHello(control, core.ServerHello{OK: true, SendBPS: 125000, RecvBPS: 125000}); err != nil {
				return err
			}
			stream, err := session.AcceptStream(ctx)
			if err != nil {
				return err
			}
			request, err := core.ReadClientRequest(stream)
			if err != nil {
				return err
			}
			if !request.UDP {
				return fmt.Errorf("not UDP")
			}
			if err = core.WriteServerResponse(stream, core.ServerResponse{OK: true, UDPSessionID: 1}); err != nil {
				return err
			}
			// Echo the actual Hysteria datagrams. The client must unpack their host,
			// port, fragmentation header and payload before reaching hyPacketConn.
			for i := 0; i < 6; i++ {
				wire, err := session.ReceiveDatagram(ctx)
				if err != nil {
					return err
				}
				if len(wire) < 6 || binary.BigEndian.Uint32(wire) != 1 {
					return fmt.Errorf("invalid session header")
				}
				if err = session.SendDatagram(wire); err != nil {
					return err
				}
			}
			<-session.Context().Done()
			return nil
		}()
	}()
	port := listener.Addr().(*net.UDPAddr).Port
	proxy, err := NewHysteria(HysteriaOption{BasicOption: BasicOption{UDPRemoteDNS: true}, Name: "hy-test", Server: "127.0.0.1", Port: port, Up: "1", Down: "1", SkipCertVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	pc, err := proxy.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, Host: "remote-only.invalid", DstPort: 1234})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	for _, destination := range []string{"remote-only.invalid:1234", "192.0.2.1:1234", "[2001:db8::1]:1234"} {
		for _, wait := range []bool{false, true} {
			target := M.ParseSocksaddr(destination)
			if _, err = pc.WriteTo([]byte("response"), target); err != nil {
				t.Fatal(err)
			}
			var data []byte
			var from net.Addr
			if wait {
				var put func()
				data, put, from, err = pc.WaitReadFrom()
				if put != nil {
					defer put()
				}
			} else {
				data = make([]byte, 1024)
				var n int
				n, from, err = pc.ReadFrom(data)
				data = data[:n]
			}
			if err != nil {
				t.Fatal(err)
			}
			if from == nil || M.SocksaddrFromNet(from).IsFqdn() != target.IsFqdn() || from.String() != target.String() || string(data) != "response" {
				t.Fatalf("decoded reply: %v %q", from, data)
			}
		}
	}
	pc.Close()
	proxy.Close()
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
