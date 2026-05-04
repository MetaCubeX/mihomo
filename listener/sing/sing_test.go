package sing

import (
	"net"
	"sync"
	"testing"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
)

type testDomainAddr string

func (a testDomainAddr) Network() string {
	return "udp"
}

func (a testDomainAddr) String() string {
	return string(a)
}

type testNetPacketWriter struct {
	addr net.Addr
	data []byte
}

func (w *testNetPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	w.addr = destination.UDPAddr()
	w.data = append(w.data[:0], buffer.Bytes()...)
	return nil
}

func (w *testNetPacketWriter) WriteTo(p []byte, addr net.Addr) (int, error) {
	w.addr = addr
	w.data = append(w.data[:0], p...)
	return len(p), nil
}

func TestSingPacketSupportsDomainWriteBack(t *testing.T) {
	writerImpl := &testNetPacketWriter{}
	writer := network.NetPacketWriter(writerImpl)
	packet := &packet{
		writer: &writer,
		mutex:  &sync.Mutex{},
	}

	if !packet.SupportDomainWriteBack() {
		t.Fatal("sing packet should allow domain UDP writeback")
	}

	addr := testDomainAddr("magic.example.ts.net:5353")
	if _, err := packet.WriteBack([]byte("response"), addr); err != nil {
		t.Fatal(err)
	}
	if writerImpl.addr != addr {
		t.Fatalf("expected domain addr to be forwarded unchanged, got %T(%s)", writerImpl.addr, writerImpl.addr)
	}
	if string(writerImpl.data) != "response" {
		t.Fatalf("unexpected payload: %q", writerImpl.data)
	}
}
