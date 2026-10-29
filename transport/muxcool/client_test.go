package muxcool

import (
	"io"
	"net"
	"testing"
	"time"
)

// echoDisp —— Bridge 侧落地器:每个子流接一个把收到数据原样回吐的 echo。
type echoDisp struct{}

func (echoDisp) DialTarget(n TargetNetwork, a Address, p uint16) (net.Conn, error) {
	c1, c2 := net.Pipe()
	go func() {
		buf := make([]byte, 4096)
		for {
			k, e := c2.Read(buf)
			if k > 0 {
				c2.Write(buf[:k])
			}
			if e != nil {
				c2.Close()
				return
			}
		}
	}()
	return c1, nil
}

func readConnTimeout(t *testing.T, c net.Conn, want string) {
	t.Helper()
	ch := make(chan string, 1)
	go func() {
		buf := make([]byte, 256)
		k, err := c.Read(buf)
		if err != nil {
			ch <- "ERR:" + err.Error()
			return
		}
		ch <- string(buf[:k])
	}()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("read got %q want %q", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("read timeout")
	}
}

// ClientWorker(Portal)↔ ServerWorker(Bridge)loopback:开子流、数据双向、控制心跳。
// 证明两侧 codec 对称互通——mihomo 既能当 Portal 也能当 Bridge。
func TestClientServer_Loopback(t *testing.T) {
	linkA, linkB := net.Pipe()

	got := make(chan []byte, 16)
	server := NewServerWorker(linkB, echoDisp{}, func(p []byte) {
		cp := make([]byte, len(p))
		copy(cp, p)
		got <- cp
	})
	client := NewClientWorker(linkA)
	go server.Run()
	go client.Run()
	defer linkA.Close()
	defer linkB.Close()

	// 控制心跳(快节奏便于测)。
	if err := client.StartControl(50 * time.Millisecond); err != nil {
		t.Fatal(err)
	}

	// 开子流,写数据,期望 echo 回来。
	conn, err := client.OpenStream(NetworkTCP, AddrFromString("1.2.3.4"), 80)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("hello-reverse")); err != nil {
		t.Fatal(err)
	}
	readConnTimeout(t, conn, "hello-reverse")

	// 收到至少一条 ACTIVE 心跳(9a 06 …,非 08 01 开头)。
	select {
	case hb := <-got:
		if len(hb) < 3 || hb[0] != 0x9A || hb[1] != 0x06 {
			t.Fatalf("heartbeat not ACTIVE control proto: % x", hb)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no control heartbeat received")
	}

	conn.Close()
}

// UDP 全锥:一个 PacketConn WriteTo 多个 target,各自独立 echo 子流,ReadFrom 带回正确 source。
func TestClientServer_UDP(t *testing.T) {
	linkA, linkB := net.Pipe()
	server := NewServerWorker(linkB, echoDisp{}, nil)
	client := NewClientWorker(linkA)
	go server.Run()
	go client.Run()
	defer linkA.Close()
	defer linkB.Close()

	pc := client.NewPacketConn()
	defer pc.Close()

	t1 := &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}
	t2 := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 5353}
	if _, err := pc.WriteTo([]byte("q-to-8888"), t1); err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo([]byte("q-to-1111"), t2); err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i := 0; i < 2; i++ {
		buf := make([]byte, 256)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		got[addr.String()] = string(buf[:n])
	}
	if got["8.8.8.8:53"] != "q-to-8888" {
		t.Fatalf("target1 mismatch: %v", got)
	}
	if got["1.1.1.1:5353"] != "q-to-1111" {
		t.Fatalf("target2 mismatch: %v", got)
	}
}

// 多子流并发:各自独立 echo,互不串。
func TestClientServer_MultiStream(t *testing.T) {
	linkA, linkB := net.Pipe()
	server := NewServerWorker(linkB, echoDisp{}, nil)
	client := NewClientWorker(linkA)
	go server.Run()
	go client.Run()
	defer linkA.Close()
	defer linkB.Close()

	const N = 8
	type res struct {
		i   int
		err error
	}
	done := make(chan res, N)
	for i := 0; i < N; i++ {
		go func(i int) {
			conn, err := client.OpenStream(NetworkTCP, AddrFromString("10.0.0.1"), uint16(1000+i))
			if err != nil {
				done <- res{i, err}
				return
			}
			defer conn.Close()
			msg := []byte{byte('A' + i)}
			if _, err := conn.Write(msg); err != nil {
				done <- res{i, err}
				return
			}
			buf := make([]byte, 8)
			connCh := make(chan error, 1)
			go func() {
				k, e := conn.Read(buf)
				if e != nil {
					connCh <- e
					return
				}
				if k != 1 || buf[0] != byte('A'+i) {
					connCh <- io.ErrUnexpectedEOF
					return
				}
				connCh <- nil
			}()
			select {
			case e := <-connCh:
				done <- res{i, e}
			case <-time.After(3 * time.Second):
				done <- res{i, io.ErrUnexpectedEOF}
			}
		}(i)
	}
	for i := 0; i < N; i++ {
		r := <-done
		if r.err != nil {
			t.Fatalf("stream %d: %v", r.i, r.err)
		}
	}
}
