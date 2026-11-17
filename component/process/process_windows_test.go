package process

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func localTCPConn(t testing.TB) (netip.AddrPort, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
		close(accepted)
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	server := <-accepted
	return conn.LocalAddr().(*net.TCPAddr).AddrPort(), func() {
		_ = conn.Close()
		if server != nil {
			_ = server.Close()
		}
		_ = ln.Close()
	}
}

func TestFindProcessNameTCP(t *testing.T) {
	addr, closeConn := localTCPConn(t)
	defer closeConn()

	_, path, err := FindProcessName(TCP, addr.Addr(), int(addr.Port()))
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Compare only the file names: the directory may be reported in 8.3 form by one of them.
	if !strings.EqualFold(filepath.Base(path), filepath.Base(self)) {
		t.Fatalf("got %q, want %q", path, self)
	}
}

func BenchmarkFindProcessNameTCP(b *testing.B) {
	addr, closeConn := localTCPConn(b)
	defer closeConn()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := FindProcessName(TCP, addr.Addr(), int(addr.Port())); err != nil {
			b.Fatal(err)
		}
	}
}
