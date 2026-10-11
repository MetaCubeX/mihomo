package trojan

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/metacubex/mihomo/transport/socks5"
)

func TestReadPacketDomainPartialPayload(t *testing.T) {
	var wire bytes.Buffer
	target := "remote-only.invalid:1234"
	payload := bytes.Repeat([]byte("x"), 512)
	if _, err := WritePacket(&wire, socks5.ParseAddr(target), payload); err != nil {
		t.Fatal(err)
	}
	// Exercise PacketConn's cached domain address while draining the remainder.
	pc := NewPacketConn(&wireTestConn{Reader: &wire})
	buffer := make([]byte, 300)
	for _, want := range []int{300, 212} {
		n, addr, err := pc.ReadFrom(buffer)
		if err != nil || addr == nil || addr.String() != target || n != want || !bytes.Equal(buffer[:n], payload[:want]) {
			t.Fatalf("partial reply: %v, length %d, error %v", addr, n, err)
		}
	}
	if pc.remain != 0 || pc.rAddr != nil {
		t.Fatal("completed packet retained cached state")
	}
}

type wireTestConn struct {
	net.Conn
	io.Reader
}

func (c *wireTestConn) Read(b []byte) (int, error) { return c.Reader.Read(b) }
