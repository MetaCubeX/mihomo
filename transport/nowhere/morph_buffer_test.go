package nowhere

import (
	"errors"
	"net"
	"testing"

	quic "github.com/metacubex/quic-go"
)

type bufferTrackingConn struct {
	net.PacketConn
	readSize, writeSize int
	err                 error
}

func (c *bufferTrackingConn) SetReadBuffer(n int) error {
	c.readSize = n
	if c.err != nil {
		return c.err
	}
	return c.PacketConn.(*net.UDPConn).SetReadBuffer(n)
}
func (c *bufferTrackingConn) SetWriteBuffer(n int) error {
	c.writeSize = n
	if c.err != nil {
		return c.err
	}
	return c.PacketConn.(*net.UDPConn).SetWriteBuffer(n)
}

func TestMorphBufferErrors(t *testing.T) {
	want := errors.New("socket buffer tuning failed")
	wire := &bufferTrackingConn{err: want}
	c := &morphPacketConn{PacketConn: wire}
	if err := c.SetReadBuffer(123); !errors.Is(err, want) || wire.readSize != 123 {
		t.Fatalf("read buffer error/size not forwarded: %v, %d", err, wire.readSize)
	}
	if err := c.SetWriteBuffer(456); !errors.Is(err, want) || wire.writeSize != 456 {
		t.Fatalf("write buffer error/size not forwarded: %v, %d", err, wire.writeSize)
	}
	c.PacketConn = &struct{ net.PacketConn }{}
	if c.SetReadBuffer(1) == nil || c.SetWriteBuffer(1) == nil {
		t.Fatal("unsupported buffer tuning reported success")
	}
}

func TestMorphPreservesQUICSocketBuffers(t *testing.T) {
	for _, client := range []bool{false, true} {
		t.Run(map[bool]string{false: "server", true: "client"}[client], func(t *testing.T) {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			wire := &bufferTrackingConn{PacketConn: pc}
			wrapped := wrapMorphUDP(wire, newMorphKeys("secret"), client)
			listener, err := quic.Listen(wrapped, testCertificate(t), quicConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if wire.readSize == 0 || wire.writeSize == 0 {
				t.Fatalf("Morph hid QUIC socket buffer configuration: read=%d write=%d", wire.readSize, wire.writeSize)
			}
			if _, ok := wrapped.(quic.OOBCapablePacketConn); ok {
				t.Fatal("raw UDP optimization would bypass Morph encoding")
			}
		})
	}
}
