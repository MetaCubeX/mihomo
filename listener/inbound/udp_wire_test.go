package inbound_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/hysteria/core"
	ssCore "github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/ssr/protocol"

	"github.com/metacubex/quic-go"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

func newUDPSSRPeer(t *testing.T, echo *udpEchoHandler) C.ProxyAdapter {
	t.Helper()
	const password = "udp-remote-resolve-test"
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	peerCipher, err := ssCore.PickCipher("aes-128-cfb", nil, password)
	require.NoError(t, err)
	peerProtocol, err := protocol.PickProtocol("origin", &protocol.Base{})
	require.NoError(t, err)
	// SSR uses SOCKS addresses inside the production cipher/protocol packet
	// stack. Stream obfuscation is not applied to its UDP transport.
	peer := peerProtocol.PacketConn(peerCipher.PacketConn(N.NewEnhancePacketConn(server)))
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 64*1024)
		for {
			n, client, err := peer.ReadFrom(buffer)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					echo.onResult(udpEchoResult{err: err})
				}
				return
			}
			header := socks5.SplitAddr(buffer[:n])
			address := header.NetAddr()
			if address == nil {
				echo.onResult(udpEchoResult{err: errors.New("invalid SSR peer destination")})
				return
			}
			destination := M.SocksaddrFromNet(address)
			metadata := &C.Metadata{
				NetWork: C.UDP, Host: destination.Fqdn, DstIP: destination.Addr, DstPort: destination.Port,
			}
			packet := &udpSSRProtocolPacket{data: buffer[len(header):n], client: client, peer: peer}
			// The echo consumes and replies synchronously before the buffer is reused.
			echo.Handle(packet, metadata)
		}
	}()
	t.Cleanup(func() {
		_ = peer.Close()
		<-done
	})
	proxy, err := outbound.NewShadowSocksR(outbound.ShadowSocksROption{
		Name: "ssr", Server: "127.0.0.1", Port: server.LocalAddr().(*net.UDPAddr).Port,
		Password: password, Cipher: "aes-128-cfb", Protocol: "origin", Obfs: "plain", UDP: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

type udpSSRProtocolPacket struct {
	data   []byte
	client net.Addr
	peer   N.EnhancePacketConn
}

func (p *udpSSRProtocolPacket) Data() []byte        { return p.data }
func (p *udpSSRProtocolPacket) LocalAddr() net.Addr { return p.client }
func (*udpSSRProtocolPacket) Drop()                 {}

func (p *udpSSRProtocolPacket) WriteBack(data []byte, address net.Addr) (int, error) {
	header := socks5.ParseAddrToSocksAddr(address)
	if header == nil {
		return 0, errors.New("invalid SSR peer response address")
	}
	buffer := make([]byte, len(header)+len(data))
	copy(buffer, header)
	copy(buffer[len(header):], data)
	if _, err := p.peer.WriteTo(buffer, p.client); err != nil {
		return 0, err
	}
	return len(data), nil
}

func newUDPHysteriaPeer(t *testing.T, echo *udpEchoHandler) C.ProxyAdapter {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	transport := &quic.Transport{Conn: pc}
	listener, err := transport.Listen(&tls.Config{
		Certificates: []tls.Certificate{tlsConfigCert}, NextProtos: []string{outbound.DefaultALPN}, MinVersion: tls.VersionTLS13,
	}, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := serveUDPHysteriaPeer(ctx, listener, echo); err != nil && ctx.Err() == nil {
			echo.onResult(udpEchoResult{err: err})
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		_ = transport.Close()
		_ = pc.Close()
		<-done
	})
	server := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	proxy, err := outbound.NewHysteria(outbound.HysteriaOption{
		BasicOption: outbound.BasicOption{IPVersion: C.IPv4Only},
		Name:        "udp_hysteria_out", Server: server.Addr().String(), Port: int(server.Port()),
		Up: "10 Mbps", Down: "10 Mbps", Fingerprint: tlsFingerprint,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, proxy.Close()) })
	return proxy
}

func serveUDPHysteriaPeer(ctx context.Context, listener *quic.Listener, echo *udpEchoHandler) error {
	conn, err := listener.Accept(ctx)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "test finished")
	control, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	hello, err := core.ReadClientHello(control)
	if err != nil {
		return err
	}
	if err = core.WriteServerHello(control, core.ServerHello{OK: true, SendBPS: hello.RecvBPS, RecvBPS: hello.SendBPS}); err != nil {
		return err
	}
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	request, err := core.ReadClientRequest(stream)
	if err != nil {
		return err
	}
	if !request.UDP {
		return fmt.Errorf("expected Hysteria UDP request")
	}
	if err = core.WriteServerResponse(stream, core.ServerResponse{OK: true, UDPSessionID: 1}); err != nil {
		return err
	}
	for {
		packet, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return err
		}
		// Hysteria v1 has no in-tree server. Decode its wire header here;
		// handshakes and the client still use the production QUIC transport.
		reader := bytes.NewReader(packet)
		var session uint32
		var hostLen uint16
		if err = binary.Read(reader, binary.BigEndian, &session); err != nil {
			return err
		}
		if err = binary.Read(reader, binary.BigEndian, &hostLen); err != nil {
			return err
		}
		host := make([]byte, hostLen)
		if _, err = io.ReadFull(reader, host); err != nil {
			return err
		}
		var suffix struct {
			Port      uint16
			MessageID uint16
			FragID    uint8
			FragCount uint8
			Length    uint16
		}
		if err = binary.Read(reader, binary.BigEndian, &suffix); err != nil {
			return err
		}
		if session != 1 || suffix.FragCount != 1 || int(suffix.Length) != reader.Len() {
			return fmt.Errorf("unexpected Hysteria test datagram framing")
		}
		data := make([]byte, reader.Len())
		if _, err = io.ReadFull(reader, data); err != nil {
			return err
		}
		target := M.ParseSocksaddrHostPort(string(host), suffix.Port)
		var reply bytes.Buffer
		_ = binary.Write(&reply, binary.BigEndian, session)
		_ = binary.Write(&reply, binary.BigEndian, uint16(len(host)))
		reply.Write(host)
		_ = binary.Write(&reply, binary.BigEndian, suffix)
		reply.Write(data)
		err = conn.SendDatagram(reply.Bytes())
		echo.onResult(udpEchoResult{
			metadata: C.Metadata{NetWork: C.UDP, Host: target.Fqdn, DstIP: target.Addr, DstPort: target.Port},
			data:     data, err: err,
		})
	}
}

func readGostUDPRequest(reader io.Reader) (M.Socksaddr, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return M.Socksaddr{}, err
	}
	if header[0] != 1 || header[1] != 0x81 {
		return M.Socksaddr{}, fmt.Errorf("unexpected Gost UDP request: %x", header)
	}
	features := make([]byte, binary.BigEndian.Uint16(header[2:]))
	if _, err := io.ReadFull(reader, features); err != nil {
		return M.Socksaddr{}, err
	}
	var target M.Socksaddr
	var udpNetwork bool
	for len(features) > 0 {
		if len(features) < 3 {
			return target, io.ErrUnexpectedEOF
		}
		kind, size := features[0], int(binary.BigEndian.Uint16(features[1:3]))
		features = features[3:]
		if size > len(features) {
			return target, io.ErrUnexpectedEOF
		}
		switch kind {
		case 2:
			// Gost's address feature uses the SOCKS address encoding.
			address := socks5.SplitAddr(features[:size])
			if address == nil || len(address) != size {
				return target, fmt.Errorf("invalid Gost target feature")
			}
			target = M.ParseSocksaddr(address.String())
		case 4:
			udpNetwork = bytes.Equal(features[:size], []byte{0, 1})
		}
		features = features[size:]
	}
	if !udpNetwork {
		return target, fmt.Errorf("Gost request is missing the UDP network feature")
	}
	return target, nil
}

func newUDPGostPeer(t *testing.T, echo *udpEchoHandler) C.ProxyAdapter {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	accepted := make(chan net.Conn, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		accepted <- conn
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		target, err := readGostUDPRequest(conn)
		if err != nil {
			echo.onResult(udpEchoResult{err: err})
			return
		}
		if _, err = conn.Write([]byte{1, 0, 0, 0}); err != nil {
			echo.onResult(udpEchoResult{err: err})
			return
		}
		// Relay UDP frames contain only a length and payload, so neither an
		// IP nor a domain source can be sent independently of the handshake.
		for {
			var header [2]byte
			if _, err := io.ReadFull(conn, header[:]); err != nil {
				return
			}
			data := make([]byte, binary.BigEndian.Uint16(header[:]))
			if _, err := io.ReadFull(conn, data); err != nil {
				return
			}
			_, err := conn.Write(append(header[:], data...))
			echo.onResult(udpEchoResult{
				metadata: C.Metadata{NetWork: C.UDP, Host: target.Fqdn, DstIP: target.Addr, DstPort: target.Port},
				data:     data, err: err,
			})
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		if conn := <-accepted; conn != nil {
			_ = conn.Close()
		}
		<-done
	})
	proxy, err := outbound.NewGostRelay(outbound.GostRelayOption{
		BasicOption: outbound.BasicOption{IPVersion: C.IPv4Only},
		Name:        "udp_gost_out", Server: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port,
		UDP: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, proxy.Close()) })
	return proxy
}
