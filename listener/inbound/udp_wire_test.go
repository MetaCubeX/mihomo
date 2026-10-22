package inbound_test

import (
	"errors"
	"net"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/ssr/protocol"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func newUDPSSRPeer(t *testing.T, echo *udpEchoHandler) C.ProxyAdapter {
	t.Helper()
	const password = "udp-remote-resolve-test"
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	peerCipher, err := core.PickCipher("aes-128-cfb", nil, password)
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
