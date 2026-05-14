//go:build linux

package process

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
)

func TestResolveSocketByNetlinkRejectsWrongSourceIP(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	serverConn := <-accepted
	defer serverConn.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr).AddrPort()
	wrongIP := netip.MustParseAddr("28.0.0.1")

	uid, inode, err := resolveSocketByNetlink(TCP, wrongIP, int(localAddr.Port()))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("resolveSocketByNetlink(%s:%d) = uid %d inode %d err %v, want ErrNotFound", wrongIP, localAddr.Port(), uid, inode, err)
	}
}

func TestResolveSocketByNetlinkMatchesSourceSocket(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	serverConn := <-accepted
	defer serverConn.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr).AddrPort()
	uid, inode, err := resolveSocketByNetlink(TCP, localAddr.Addr(), int(localAddr.Port()))
	if err != nil {
		t.Fatal(err)
	}
	if uid != uint32(os.Getuid()) {
		t.Fatalf("uid = %d, want current uid %d", uid, os.Getuid())
	}
	if inode == 0 {
		t.Fatal("inode = 0, want non-zero")
	}
}

func TestResolveSocketByNetlinkMatchesUDPWildcardSocket(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	uid, inode, err := resolveSocketByNetlink(UDP, netip.MustParseAddr("127.0.0.1"), int(localAddr.Port()))
	if err != nil {
		t.Fatal(err)
	}
	if uid != uint32(os.Getuid()) {
		t.Fatalf("uid = %d, want current uid %d", uid, os.Getuid())
	}
	if inode == 0 {
		t.Fatal("inode = 0, want non-zero")
	}
}
