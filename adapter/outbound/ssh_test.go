package outbound_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/ssh"
)

func TestSSHServerAlive(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	server := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) != "test-only" {
				return nil, ssh.ErrNoAuth
			}
			return nil, nil
		},
	}
	server.AddHostKey(signer)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepted atomic.Int32
	var frozen atomic.Bool
	probes := make(chan struct{}, 8)
	firstClosed := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			generation := accepted.Add(1)
			go func() {
				defer conn.Close()
				if generation == 1 {
					defer close(firstClosed)
				}
				peer, channels, requests, err := ssh.NewServerConn(conn, server)
				if err != nil {
					return
				}
				defer peer.Close()
				go func() {
					for req := range requests {
						if generation == 1 && frozen.Load() {
							continue
						}
						_ = req.Reply(false, nil)
						select {
						case probes <- struct{}{}:
						default:
						}
					}
				}()
				for ch := range channels {
					if generation == 1 && frozen.Load() {
						continue
					}
					stream, requests, err := ch.Accept()
					if err == nil {
						go ssh.DiscardRequests(requests)
						go func() {
							defer stream.Close()
							_, _ = io.Copy(stream, stream)
						}()
					}
				}
			}()
		}
	}()
	node, err := adapter.ParseProxy(map[string]any{
		"type": "ssh", "name": "test", "server": "127.0.0.1",
		"port": listener.Addr().(*net.TCPAddr).Port, "username": "test", "password": "test-only",
		"host-key":              []string{string(ssh.MarshalAuthorizedKey(signer.PublicKey()))},
		"server-alive-interval": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	target := &C.Metadata{NetWork: C.TCP, Host: "example.invalid", DstPort: 443}
	dial := func(timeout time.Duration) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return node.DialContext(ctx, target)
	}
	first, err := dial(3 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	probed := false
	select {
	case <-probes:
		probed = true
	case <-time.After(2 * time.Second):
	}
	healthy, err := dial(2 * time.Second)
	if err != nil {
		t.Fatalf("a negative keepalive reply broke a healthy session: %v", err)
	}
	_ = healthy.Close()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("healthy session was replaced: %d transports", got)
	}
	frozen.Store(true)
	if stalled, err := dial(150 * time.Millisecond); err == nil {
		_ = stalled.Close()
		t.Fatal("channel unexpectedly opened on the silent transport")
	}
	select {
	case <-firstClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("silent SSH session was not closed")
	}
	if !probed {
		t.Fatal("SSH server did not receive a keepalive request")
	}
	const dials = 6
	results := make(chan error, dials)
	for i := 0; i < dials; i++ {
		go func() {
			conn, err := dial(2 * time.Second)
			if err != nil {
				results <- err
				return
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("test")); err != nil {
				results <- err
				return
			}
			reply := make([]byte, 4)
			if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "test" {
				results <- fmt.Errorf("new channel did not carry traffic: %q, %v", reply, err)
				return
			}
			results <- nil
		}()
	}
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for i := 0; i < dials; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-timeout.C:
			t.Fatal("replacement SSH channels did not finish")
		}
	}
	if got := accepted.Load(); got != 2 {
		t.Fatalf("expected one replacement SSH transport, got %d total", got)
	}
}
