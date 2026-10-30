package miu

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"
	M "github.com/metacubex/sing/common/metadata"
)

// Exercise real authentication and Settings frames, not just scheme setters.
func TestDerivedServerNegotiation(t *testing.T) {
	const other = "another-test-user-psk-2026"
	for _, explicit := range []string{"", "stop=2\n0=40-40\n1=128-160"} {
		srv, err := NewServer(ServerConfig{Users: map[string]string{"a": testPSK, "b": other}, PaddingScheme: explicit,
			Handler: func(context.Context, net.Conn, string, M.Socksaddr) {}})
		if err != nil {
			t.Fatal(err)
		}
		for _, psk := range []string{testPSK, other} {
			token, err := pskToken(psk)
			if err != nil {
				t.Fatal(err)
			}
			expected := explicit
			if expected == "" {
				expected, err = derivedScheme(token)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, match := range []bool{false, true} {
				a, b := net.Pipe()
				a.SetDeadline(time.Now().Add(3 * time.Second))
				b.SetDeadline(time.Now().Add(3 * time.Second))
				done := make(chan error, 1)
				go func() { done <- srv.Serve(context.Background(), b) }()
				md5 := padding.NewPaddingFactory(padding.DefaultPaddingScheme).Md5
				if match {
					md5 = padding.NewPaddingFactory([]byte(expected)).Md5
				}
				hello := append(append([]byte{}, token[:]...), 0, 0)
				hello = appendFrame(hello, frSettings, []byte("v=2\nraw=0\npadding-md5="+md5))
				if _, err = a.Write(hello); err != nil {
					t.Fatal(err)
				}
				l := newLane(a, false, false)
				typ, _, err := l.next()
				if err != nil || typ != frServerSettings {
					t.Fatalf("settings: %d %v", typ, err)
				}
				if !match {
					typ, p, err := l.next()
					if err != nil || typ != frUpdatePadding || string(p) != expected {
						t.Fatalf("user-specific update: type=%d err=%v payload=%q", typ, err, p)
					}
				} else {
					// A mismatched extra update would arrive instead of this read timing out.
					a.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
					_, _, err = l.next()
					if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
						t.Fatalf("unexpected matching-scheme response: %v", err)
					}
				}
				a.Close()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestDerivedUpdatePersistsToNextHello(t *testing.T) {
	const updated = "stop=2\n0=40-40\n1=200-300"
	var peers []net.Conn
	c, err := NewClient(ClientConfig{PSK: testPSK, Dial: func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		a.SetDeadline(time.Now().Add(3 * time.Second))
		b.SetDeadline(time.Now().Add(3 * time.Second))
		peers = append(peers, b)
		go func() {
			var h [34]byte
			if _, e := io.ReadFull(b, h[:]); e != nil {
				return
			}
			if _, e := io.CopyN(io.Discard, b, int64(binary.BigEndian.Uint16(h[32:]))); e != nil {
				return
			}
			l := newLane(b, true, false)
			typ, p, e := l.next()
			if e != nil || typ != frSettings {
				return
			}
			// Echo the received md5 after the control frame, so the next hello is observable.
			l.writeFrame(frUpdatePadding, []byte(updated))
			l.writeFrame(frServerSettings, p)
		}()
		return a, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer func() {
		for _, p := range peers {
			p.Close()
		}
	}()
	for i := 0; i < 2; i++ {
		l, e := c.dial(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		typ, p, e := l.next()
		if e != nil || typ != frUpdatePadding {
			t.Fatalf("update: %d %v", typ, e)
		}
		if e = l.control(typ, p); e != nil {
			t.Fatal(e)
		}
		typ, p, e = l.next()
		if e != nil || typ != frServerSettings {
			t.Fatalf("echo: %d %v", typ, e)
		}
		if i == 1 && !strings.Contains(string(p), "padding-md5="+padding.NewPaddingFactory([]byte(updated)).Md5) {
			t.Fatalf("next hello: %q", p)
		}
		l.close()
	}
}
