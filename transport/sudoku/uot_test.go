package sudoku

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

func TestUoTPacketConnReadFrom_ShortBufferConsumesFrame(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	packetConn := NewUoTPacketConn(serverConn)
	go func() {
		_ = WriteDatagram(clientConn, "8.8.8.8:53", bytes.Repeat([]byte("a"), 16))
		_ = WriteDatagram(clientConn, "8.8.4.4:53", []byte("ok"))
		_ = clientConn.Close()
	}()

	buf := make([]byte, 4)
	if n, addr, err := packetConn.ReadFrom(buf); !errors.Is(err, io.ErrShortBuffer) || n != 0 || addr != nil {
		t.Fatalf("short buffer read = (%d, %v, %v), want (0, nil, %v)", n, addr, err, io.ErrShortBuffer)
	}

	n, addr, err := packetConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second read failed: %v", err)
	}
	if got := addr.String(); got != "8.8.4.4:53" {
		t.Fatalf("unexpected address: %s", got)
	}
	if got := string(buf[:n]); got != "ok" {
		t.Fatalf("unexpected payload: %q", got)
	}
}

func TestUoTPacketConnReadFrom_SkipsInvalidDomainDatagram(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	packetConn := NewUoTPacketConn(serverConn)
	go func() {
		_ = WriteDatagram(clientConn, "example.com:53", []byte("skip-me"))
		_ = WriteDatagram(clientConn, "1.1.1.1:53", []byte("ok"))
		_ = clientConn.Close()
	}()

	buf := make([]byte, 16)
	n, addr, err := packetConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if got := addr.String(); got != "1.1.1.1:53" {
		t.Fatalf("unexpected address: %s", got)
	}
	if got := string(buf[:n]); got != "ok" {
		t.Fatalf("unexpected payload: %q", got)
	}
}
