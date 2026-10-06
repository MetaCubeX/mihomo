package outbound

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/vless"
	vmess "github.com/metacubex/sing-vmess"
	M "github.com/metacubex/sing/common/metadata"
)

type failingUDPResolver struct {
	resolver.Resolver
	calls int
	ip    netip.Addr
}

func (r *failingUDPResolver) Invalid() bool { return true }
func (r *failingUDPResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	r.calls++
	if r.ip.IsValid() {
		return []netip.Addr{r.ip}, nil
	}
	return nil, errors.New("local DNS is unavailable")
}

// Enabling remote DNS must never change ResolveUDP's local-resolution contract.
func TestResolveUDPRemainsLocal(t *testing.T) {
	previous := resolver.DefaultResolver
	r := &failingUDPResolver{ip: netip.MustParseAddr("192.0.2.1")}
	resolver.DefaultResolver = r
	t.Cleanup(func() { resolver.DefaultResolver = previous })
	for _, enabled := range []bool{false, true} {
		b := NewBase(BaseOption{})
		b.SetUDPRemoteDNS(enabled)
		pc := NewPacketConn(&wirePacketConn{}, b)
		for _, resolve := range []func(context.Context, *C.Metadata) error{b.ResolveUDP, pc.ResolveUDP} {
			ctx := C.WithUDPRemoteDNSDomain(context.Background(), "first.invalid")
			m := &C.Metadata{NetWork: C.UDP, Host: "first.invalid", DstPort: 53}
			before := r.calls
			if err := resolve(ctx, m); err != nil || m.DstIP != r.ip || r.calls != before+1 {
				t.Fatalf("enabled=%v: local resolution returned %+v, %v", enabled, m, err)
			}
			// A pre-resolved target must keep its IP, even with a matching domain scope.
			m.DstIP = netip.MustParseAddr("192.0.2.2")
			if err := resolve(ctx, m); err != nil || m.DstIP.String() != "192.0.2.2" || r.calls != before+1 {
				t.Fatal("ResolveUDP changed a resolved target", err)
			}
			r.ip = netip.Addr{}
			m.DstIP = netip.Addr{}
			if err := resolve(ctx, m); err == nil || m.DstIP.IsValid() || r.calls != before+2 {
				t.Fatal("ResolveUDP bypassed a local DNS failure", err)
			}
			r.ip = netip.MustParseAddr("192.0.2.1")
		}
	}
}

func TestPrepareUDPRemoteDNS(t *testing.T) {
	previous := resolver.DefaultResolver
	r := &failingUDPResolver{}
	resolver.DefaultResolver = r
	t.Cleanup(func() { resolver.DefaultResolver = previous })
	localCalls := 0
	for _, tc := range []struct {
		name   string
		option bool
		remote bool // the domain must be kept for the outbound
	}{
		{"remote DNS enabled", true, true},
		{"remote DNS disabled", false, false},
	} {
		b := NewBase(BaseOption{})
		b.SetUDPRemoteDNS(tc.option)
		metadata := &C.Metadata{NetWork: C.UDP, Host: "remote-only.invalid", DstPort: 53}
		err := prepareUDP(context.Background(), metadata, b)
		if tc.remote {
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if metadata.DstIP.IsValid() {
				t.Fatalf("%s: domain was resolved locally", tc.name)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s: local DNS must be used", tc.name)
		}
		localCalls++
	}
	if r.calls != localCalls {
		t.Fatalf("DNS called %d times; expected %d", r.calls, localCalls)
	}
	b := NewBase(BaseOption{})
	b.SetUDPRemoteDNS(true)
	m := &C.Metadata{NetWork: C.UDP, Host: "remote-only.invalid", DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 53}
	if err := prepareUDP(context.Background(), m, b); err != nil {
		t.Fatal(err)
	}
	if m.DstIP.IsValid() || m.UDPRemoteAddr().String() != "remote-only.invalid:53" {
		t.Fatal("remote mode must preserve domain even after rule resolution")
	}
	m.Host = ""
	m.DstIP = netip.MustParseAddr("2001:db8::1")
	if err := prepareUDP(context.Background(), m, b); err != nil || m.UDPRemoteAddr().String() != "[2001:db8::1]:53" {
		t.Fatal("literal IP must be preserved", err)
	}
}

func TestUDPRemoteDNSDomainContext(t *testing.T) {
	previous := resolver.DefaultResolver
	r := &failingUDPResolver{}
	resolver.DefaultResolver = r
	t.Cleanup(func() { resolver.DefaultResolver = previous })
	b := NewBase(BaseOption{})
	b.SetUDPRemoteDNS(true)
	pc := NewPacketConn(&wirePacketConn{}, b)
	for _, tc := range []struct {
		first, host string
		remote      bool
	}{
		{"first.invalid", "first.invalid", true},
		{"first.invalid", "second.invalid", false},
		{"", "first.invalid", false},
	} {
		m := &C.Metadata{NetWork: C.UDP, Host: tc.host, DstPort: 443}
		before := r.calls
		err := pc.PrepareUDP(C.WithUDPRemoteDNSDomain(context.Background(), tc.first), m)
		if tc.remote {
			if err != nil || m.DstIP.IsValid() || r.calls != before {
				t.Fatalf("%s: remote DNS failed: %v", tc.host, err)
			}
		} else if err == nil || r.calls != before+1 {
			t.Fatalf("first=%q host=%q did not use local DNS: %v", tc.first, tc.host, err)
		}
	}
}

// Exchange actual SOCKS5 frames with a local server using an unresolvable
// domain. The request keeps the domain; a peer answers with the source IP
// (domain replies belong to the reverse mapping feature).
func TestSocks5UDPRemoteDNSRoundTrip(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := tcp.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, cmd, _, err := socks5.ServerHandshake(conn, nil)
		if err != nil {
			serverErr <- err
			return
		}
		if cmd != socks5.CmdUDPAssociate {
			serverErr <- errors.New("wrong SOCKS command")
			return
		}
		io.Copy(io.Discard, conn)
		serverErr <- nil
	}()
	remoteDNS := &failingUDPResolver{}
	previous := resolver.DefaultResolver
	resolver.DefaultResolver = remoteDNS
	t.Cleanup(func() { resolver.DefaultResolver = previous })
	port := tcp.Addr().(*net.TCPAddr).Port
	proxy, err := NewSocks5(Socks5Option{BasicOption: BasicOption{UDPRemoteDNS: true}, Name: "remote", Server: "127.0.0.1", Port: port, UDP: true})
	if err != nil {
		t.Fatal(err)
	}
	metadata := &C.Metadata{NetWork: C.UDP, Host: "remote-only.invalid", DstPort: 1234}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pc, err := proxy.ListenPacketContext(ctx, metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	udp.SetDeadline(time.Now().Add(5 * time.Second))
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 1024)
	var firstPeer net.Addr
	for _, tc := range []struct{ target, source, payload string }{
		{"remote-only.invalid:1234", "192.0.2.1:1234", "request"},
		{"second.invalid:4321", "192.0.2.1:4321", "second"},
	} {
		if _, err = pc.WriteTo([]byte(tc.payload), M.ParseSocksaddr(tc.target)); err != nil {
			t.Fatal(err)
		}
		n, peer, err := udp.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		addr, data, err := socks5.DecodeUDPPacket(buffer[:n])
		if err != nil {
			t.Fatal(err)
		}
		if addr[0] != socks5.AtypDomainName || addr.String() != tc.target || string(data) != tc.payload {
			t.Fatalf("unexpected wire packet: %s %q", addr, data)
		}
		if firstPeer == nil {
			firstPeer = peer
		} else if peer.String() != firstPeer.String() {
			t.Fatalf("UDP association was not reused: %s, want %s", peer, firstPeer)
		}
		reply, err := socks5.EncodeUDPPacket(socks5.ParseAddr(tc.source), []byte("response"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = udp.WriteTo(reply, peer); err != nil {
			t.Fatal(err)
		}
		data, put, from, err := pc.WaitReadFrom()
		if put != nil {
			defer put()
		}
		if err != nil {
			t.Fatal(err)
		}
		if from == nil || from.String() != tc.source || string(data) != "response" {
			t.Fatalf("unexpected reply: %v %q", from, data)
		}
	}
	if remoteDNS.calls != 0 {
		t.Fatalf("unexpected local DNS calls: %d", remoteDNS.calls)
	}
	pc.Close()
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestRemoteDNSPacketAddrDisabled(t *testing.T) {
	for _, kind := range []string{"vmess", "vless"} {
		for _, encoding := range []string{"packetaddr", "packet", "xudp"} {
			t.Run(kind+"/"+encoding, func(t *testing.T) {
				option := BasicOption{UDPRemoteDNS: true}
				var proxy ProxyAdapter
				var enabled bool
				var err error
				if kind == "vmess" {
					var v *Vmess
					v, err = NewVmess(VmessOption{BasicOption: option, UUID: "00000000-0000-0000-0000-000000000001", Cipher: "auto", PacketEncoding: encoding})
					if err == nil {
						proxy, enabled = v, v.option.UDPRemoteDNS
					}
				} else {
					var v *Vless
					v, err = NewVless(VlessOption{BasicOption: option, UUID: "00000000-0000-0000-0000-000000000001", PacketEncoding: encoding})
					if err == nil {
						proxy, enabled = v, v.option.UDPRemoteDNS
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				defer proxy.Close()
				want := encoding == "xudp"
				if enabled != want || proxy.ProxyInfo().UDPRemoteDNS != want {
					t.Fatalf("encoding %s: option=%v, proxy flag=%v, want %v", encoding, enabled, proxy.ProxyInfo().UDPRemoteDNS, want)
				}
			})
		}
	}
}

func TestVlessUDPRemoteDNSRoundTrip(t *testing.T) {
	for _, xudp := range []bool{false, true} {
		t.Run(fmt.Sprintf("xudp=%v", xudp), func(t *testing.T) {
			tcp, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			serverErr := make(chan error, 1)
			go func() {
				conn, err := tcp.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				serverErr <- echoVlessDomainUDP(conn, xudp)
			}()
			r := &failingUDPResolver{}
			old := resolver.DefaultResolver
			resolver.DefaultResolver = r
			t.Cleanup(func() { resolver.DefaultResolver = old })
			proxy, err := NewVless(VlessOption{BasicOption: BasicOption{UDPRemoteDNS: true}, Name: "remote", Server: "127.0.0.1", Port: tcp.Addr().(*net.TCPAddr).Port, UUID: "00000000-0000-0000-0000-000000000001", UDP: true, XUDP: xudp})
			if err != nil {
				t.Fatal(err)
			}
			// NewVless defaults to XUDP; also exercise the internal legacy stream.
			proxy.option.XUDP = xudp

			defer proxy.Close()
			m := &C.Metadata{NetWork: C.UDP, Host: "remote-only.invalid", DstPort: 1234,
				SrcIP: netip.MustParseAddr("192.0.2.10"), SrcPort: 54321}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pc, err := proxy.ListenPacketContext(ctx, m)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			pc.SetDeadline(time.Now().Add(5 * time.Second))
			destinations := []string{"remote-only.invalid:1234"}
			if xudp {
				destinations = append(destinations, "second.invalid:4321")
			}
			for _, destination := range destinations {
				if _, err = pc.WriteTo([]byte("request"), M.ParseSocksaddr(destination)); err != nil {
					t.Fatal(err)
				}
				data, put, from, err := pc.WaitReadFrom()
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != "request" || from == nil || from.String() != destination {
					if put != nil {
						put()
					}
					t.Fatalf("wrong reply: %v %q", from, data)
				}
				if put != nil {
					put()
				}
			}
			if !xudp {
				if _, err = pc.WriteTo([]byte("wrong target"), M.ParseSocksaddr("second.invalid:4321")); !errors.Is(err, ErrUDPRemoteAddrMismatch) {
					t.Fatal("legacy UDP accepted a second target", err)
				}
			}
			if r.calls != 0 {
				t.Fatalf("unexpected local DNS calls: %d", r.calls)
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func echoVlessDomainUDP(conn net.Conn, xudp bool) error {
	var prefix [18]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return err
	}
	if prefix[0] != vless.Version {
		return errors.New("wrong VLESS version")
	}
	if _, err := io.CopyN(io.Discard, conn, int64(prefix[17])); err != nil {
		return err
	}
	var command [1]byte
	if _, err := io.ReadFull(conn, command[:]); err != nil {
		return err
	}
	if xudp {
		if command[0] != vless.CommandMux {
			return errors.New("XUDP must use VLESS mux")
		}
		for i, want := range []string{"remote-only.invalid:1234", "second.invalid:4321"} {
			var size uint16
			if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
				return err
			}
			header := make([]byte, size)
			if _, err := io.ReadFull(conn, header); err != nil {
				return err
			}
			if len(header) < 5 || header[4] != vmess.NetworkUDP {
				return errors.New("not UDP mux frame")
			}
			addressReader := bytes.NewReader(header[5:])
			target, err := vmess.AddressSerializer.ReadAddrPort(addressReader)
			if err != nil {
				return err
			}
			if !target.IsFqdn() || target.String() != want {
				return fmt.Errorf("wire destination: %s, want %s", target, want)
			}
			if i == 0 && addressReader.Len() != 8 {
				return errors.New("remote DNS must preserve the source-wide XUDP global ID")
			}
			if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
				return err
			}
			payload := make([]byte, size)
			if _, err := io.ReadFull(conn, payload); err != nil {
				return err
			}
			var reply bytes.Buffer
			if i == 0 {
				reply.Write([]byte{vless.Version, 0})
			}
			var frame bytes.Buffer
			frame.Write([]byte{0, 0, vmess.StatusKeep, 1, vmess.NetworkUDP})
			if err := vmess.AddressSerializer.WriteAddrPort(&frame, target); err != nil {
				return err
			}
			binary.Write(&reply, binary.BigEndian, uint16(frame.Len()))
			reply.Write(frame.Bytes())
			binary.Write(&reply, binary.BigEndian, uint16(len(payload)))
			reply.Write(payload)
			if _, err := conn.Write(reply.Bytes()); err != nil {
				return err
			}
		}
		return nil
	}
	if command[0] != vless.CommandUDP {
		return errors.New("not VLESS UDP")
	}
	var addressHeader [4]byte
	if _, err := io.ReadFull(conn, addressHeader[:]); err != nil {
		return err
	}
	if binary.BigEndian.Uint16(addressHeader[:2]) != 1234 || addressHeader[2] != vless.AtypDomainName {
		return errors.New("VLESS handshake lost domain")
	}
	host := make([]byte, addressHeader[3])
	if _, err := io.ReadFull(conn, host); err != nil {
		return err
	}
	if string(host) != "remote-only.invalid" {
		return fmt.Errorf("wrong domain %s", host)
	}
	var size uint16
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
		return err
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return err
	}
	var reply bytes.Buffer
	reply.Write([]byte{vless.Version, 0})
	binary.Write(&reply, binary.BigEndian, size)
	reply.Write(payload)
	_, err := conn.Write(reply.Bytes())
	return err
}

// Legacy replies carry no address; an arbitrary server-side source must not
// change the client's handshake-bound address (symmetric NAT semantics).
type legacyVMessHandler struct {
	muxEchoHandler
	errors chan error
}

func (h *legacyVMessHandler) NewError(_ context.Context, err error) { h.errors <- err }

func TestVMessLegacyUDPBoundReply(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(fmt.Sprintf("remoteDNS=%v", remote), func(t *testing.T) {
			tcp, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			handler := &legacyVMessHandler{
				muxEchoHandler: muxEchoHandler{destinations: make(chan M.Socksaddr, 1), replySource: M.ParseSocksaddr("192.0.2.2:4321")},
				errors:         make(chan error, 1),
			}
			const uuid = "00000000-0000-0000-0000-000000000001"
			service := vmess.NewService[string](handler)
			if err = service.UpdateUsers([]string{"test"}, []string{uuid}, []int{0}); err != nil {
				t.Fatal(err)
			}
			serverErr := make(chan error, 1)
			go func() {
				conn, err := tcp.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				serverErr <- service.NewConnection(context.Background(), conn, M.Metadata{})
			}()
			proxy, err := NewVmess(VmessOption{BasicOption: BasicOption{UDPRemoteDNS: remote}, Name: "legacy", Server: "127.0.0.1", Port: tcp.Addr().(*net.TCPAddr).Port, UUID: uuid, Cipher: "auto", UDP: true})
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			metadata := &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 1234}
			if remote {
				metadata.Host = "remote-only.invalid"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pc, err := proxy.ListenPacketContext(ctx, metadata)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			pc.SetDeadline(time.Now().Add(5 * time.Second))
			target := metadata.UDPRemoteAddr()
			if _, err = pc.WriteTo([]byte("request"), target); err != nil {
				t.Fatal(err)
			}
			data, put, from, err := pc.WaitReadFrom()
			if put != nil {
				defer put()
			}
			if err != nil || from == nil || from.String() != target.String() || string(data) != "request" {
				t.Fatalf("bound reply: %v %q %v", from, data, err)
			}
			select {
			case dest := <-handler.destinations:
				if dest.String() != target.String() {
					t.Fatalf("handshake: %s, want %s", dest, target)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if remote {
				if _, err := pc.WriteTo([]byte("wrong target"), handler.replySource); !errors.Is(err, ErrUDPRemoteAddrMismatch) {
					t.Fatalf("legacy accepted another target: %v", err)
				}
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-handler.errors:
				t.Fatal(err)
			default:
			}
		})
	}
}
