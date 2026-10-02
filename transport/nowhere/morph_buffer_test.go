package nowhere

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	quic "github.com/metacubex/quic-go"
)

type morphTestPacketConn struct {
	net.PacketConn
	read  func([]byte) (int, net.Addr, error)
	write func([]byte, net.Addr) (int, error)
}

func (c *morphTestPacketConn) ReadFrom(b []byte) (int, net.Addr, error) { return c.read(b) }
func (c *morphTestPacketConn) WriteTo(b []byte, a net.Addr) (int, error) {
	return c.write(b, a)
}

func TestMorphPacketBuffers(t *testing.T) {
	keys := newMorphKeys("secret")
	addr := targetAddr("127.0.0.1:53")
	for _, client := range []bool{false, true} {
		for _, size := range []int{1, 1200, 65523} {
			payload := bytes.Repeat([]byte{42}, size)
			var wire []byte
			sender := wrapMorphUDP(&morphTestPacketConn{write: func(b []byte, _ net.Addr) (int, error) {
				wire = append([]byte(nil), b...)
				return len(b), nil
			}}, keys, client)
			if n, err := sender.WriteTo(payload, addr); err != nil || n != size || len(wire) != size+12 {
				t.Fatalf("write size %d: n=%d err=%v", size, n, err)
			}
			if !bytes.Equal(payload, bytes.Repeat([]byte{42}, size)) {
				t.Fatal("Morph modified caller payload")
			}
			// Concurrent reads must own separate pooled buffers. The source is
			// immutable, so any sharing would race during copy or decryption.
			receiver := wrapMorphUDP(&morphTestPacketConn{read: func(b []byte) (int, net.Addr, error) {
				return copy(b, wire), addr, nil
			}}, keys, !client)
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					buf := make([]byte, size)
					n, from, err := receiver.ReadFrom(buf)
					if err != nil || n != size || from != addr || !bytes.Equal(buf, payload) {
						t.Errorf("read size %d: n=%d from=%v err=%v", size, n, from, err)
					}
				}()
			}
			wg.Wait()
		}
	}
	wire := &morphTestPacketConn{write: func(b []byte, _ net.Addr) (int, error) { return len(b) - 1, nil }}
	if _, err := wrapMorphUDP(wire, keys, true).WriteTo([]byte{42}, addr); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
}

func BenchmarkMorphPacket(b *testing.B) {
	addr := targetAddr("127.0.0.1:53")
	packet := make([]byte, 1212)
	c := wrapMorphUDP(&morphTestPacketConn{
		read:  func(buf []byte) (int, net.Addr, error) { return copy(buf, packet), addr, nil },
		write: func(buf []byte, _ net.Addr) (int, error) { return len(buf), nil },
	}, newMorphKeys("secret"), true)
	for _, receive := range []bool{true, false} {
		b.Run(map[bool]string{true: "read", false: "write"}[receive], func(b *testing.B) {
			buf := make([]byte, 1200)
			b.SetBytes(int64(len(buf)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var err error
				if receive {
					_, _, err = c.ReadFrom(buf)
				} else {
					_, err = c.WriteTo(buf, addr)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

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
