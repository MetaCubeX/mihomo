package xhttp

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type mockAddr struct {
	network string
	address string
}

func (m *mockAddr) Network() string { return m.network }
func (m *mockAddr) String() string  { return m.address }

func TestSplitConnReadWrite(t *testing.T) {
	readBuf := bytes.NewBuffer([]byte("test data from reader"))
	writeBuf := &bytes.Buffer{}

	conn := &splitConn{
		reader: io.NopCloser(readBuf),
		writer: nopWriteCloser{writeBuf},
		remote: &mockAddr{"tcp", "127.0.0.1:8080"},
		local:  &mockAddr{"tcp", "127.0.0.1:9090"},
	}

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(buf[:n]) != "test data from reader" {
		t.Errorf("Read() = %s, want 'test data from reader'", string(buf[:n]))
	}

	data := []byte("write test")
	n, err = conn.Write(data)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(data) {
		t.Errorf("Write() n = %d, want %d", n, len(data))
	}
	if writeBuf.String() != "write test" {
		t.Errorf("Write() result = %s, want 'write test'", writeBuf.String())
	}
}

func TestSplitConnClose(t *testing.T) {
	pr, pw := io.Pipe()
	closed := false

	conn := &splitConn{
		reader: pr,
		writer: pw,
		onClose: func() {
			closed = true
		},
	}

	err := conn.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if !closed {
		t.Error("onClose() hook not called")
	}
}

func TestSplitConnCloseWithNilClosers(t *testing.T) {
	conn := &splitConn{
		reader: io.NopCloser(&bytes.Buffer{}),
		writer: nopWriteCloser{&bytes.Buffer{}},
	}

	err := conn.Close()
	if err != nil {
		t.Errorf("Close() with nil closers should not error, got %v", err)
	}
}

func TestSplitConnAddr(t *testing.T) {
	remoteAddr := &mockAddr{"tcp", "192.168.1.1:8080"}
	localAddr := &mockAddr{"tcp", "10.0.0.1:9090"}

	conn := &splitConn{
		reader: io.NopCloser(&bytes.Buffer{}),
		writer: nopWriteCloser{&bytes.Buffer{}},
		remote: remoteAddr,
		local:  localAddr,
	}

	if conn.RemoteAddr() != remoteAddr {
		t.Errorf("RemoteAddr() = %v, want %v", conn.RemoteAddr(), remoteAddr)
	}

	if conn.LocalAddr() != localAddr {
		t.Errorf("LocalAddr() = %v, want %v", conn.LocalAddr(), localAddr)
	}
}

func TestSplitConnDeadline(t *testing.T) {
	conn := &splitConn{
		reader: io.NopCloser(&bytes.Buffer{}),
		writer: nopWriteCloser{&bytes.Buffer{}},
	}

	deadline := time.Now().Add(time.Hour)

	if err := conn.SetDeadline(deadline); err != nil {
		t.Errorf("SetDeadline() error = %v", err)
	}

	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Errorf("SetReadDeadline() error = %v", err)
	}

	if err := conn.SetWriteDeadline(deadline); err != nil {
		t.Errorf("SetWriteDeadline() error = %v", err)
	}
}

func TestSplitConnImplementsNetConn(t *testing.T) {
	var _ net.Conn = (*splitConn)(nil)
}

func TestSplitConnReadEOF(t *testing.T) {
	conn := &splitConn{
		reader: io.NopCloser(&bytes.Buffer{}),
		writer: nopWriteCloser{&bytes.Buffer{}},
	}

	buf := make([]byte, 100)
	_, err := conn.Read(buf)
	if err != io.EOF {
		t.Errorf("Read() on empty buffer should return EOF, got %v", err)
	}
}

func TestSplitConnWriteClosed(t *testing.T) {
	pr, pw := io.Pipe()
	pw.Close()

	conn := &splitConn{
		reader: pr,
		writer: pw,
	}

	_, err := conn.Write([]byte("data"))
	if err == nil {
		t.Error("Write() to closed pipe should error, got nil")
	}
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }
