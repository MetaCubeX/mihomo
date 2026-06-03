package mkcp

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

// TestSimpleAuthenticatorRoundTrip verifies the no-seed authenticator seals and
// opens to the original plaintext.
func TestSimpleAuthenticatorRoundTrip(t *testing.T) {
	a := NewSimpleAuthenticator()
	for _, n := range []int{0, 1, 7, 18, 100, 1291} {
		plain := make([]byte, n)
		_, _ = rand.Read(plain)
		sealed := a.Seal(nil, nil, plain, nil)
		opened, err := a.Open(nil, nil, sealed, nil)
		if err != nil {
			t.Fatalf("open failed for len %d: %v", n, err)
		}
		if !bytes.Equal(opened, plain) {
			t.Fatalf("round trip mismatch for len %d", n)
		}
	}
}

// TestAEADSeedRoundTrip verifies the seed-based AES-128-GCM authenticator.
func TestAEADSeedRoundTrip(t *testing.T) {
	a := NewAEADAESGCMBasedOnSeed("a-shared-seed")
	nonce := make([]byte, a.NonceSize())
	_, _ = rand.Read(nonce)
	plain := []byte("the quick brown fox jumps over the lazy dog")
	sealed := a.Seal(nil, nonce, plain, nil)
	opened, err := a.Open(nil, nonce, sealed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plain) {
		t.Fatal("aead round trip mismatch")
	}
}

func dialPair(t *testing.T, cfg *Config) (*Connection, *Connection, func()) {
	t.Helper()
	pcA, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pcB, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	const conv = 0x4242
	connA, err := dialConv(pcA, pcB.LocalAddr(), cfg, conv)
	if err != nil {
		t.Fatal(err)
	}
	connB, err := dialConv(pcB, pcA.LocalAddr(), cfg, conv)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		connA.Close()
		connB.Close()
	}
	return connA, connB, cleanup
}

// TestMKCPEndToEnd runs two mKCP connections over real UDP loopback (sharing a
// conversation id, as a client and server would) and exchanges data in both
// directions, exercising the full segment/window/crypto/header path.
func TestMKCPEndToEnd(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
	}{
		{"none-noseed", &Config{}},
		{"wechat-seed", &Config{Header: "wechat-video", Seed: "test-seed"}},
		{"wireguard-seed", &Config{Header: "wireguard", Seed: "another-seed"}},
		{"utp-noseed", &Config{Header: "utp"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			connA, connB, cleanup := dialPair(t, tc.cfg)
			defer cleanup()

			payload := make([]byte, 64*1024)
			_, _ = rand.Read(payload)

			errc := make(chan error, 1)
			go func() {
				_, err := connA.Write(payload)
				errc <- err
			}()

			connB.SetReadDeadline(time.Now().Add(10 * time.Second))
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(connB, got); err != nil {
				t.Fatalf("read on B: %v", err)
			}
			if err := <-errc; err != nil {
				t.Fatalf("write on A: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("payload mismatch A->B")
			}

			// reverse direction
			reply := []byte("pong from B")
			go connB.Write(reply)
			connA.SetReadDeadline(time.Now().Add(10 * time.Second))
			rgot := make([]byte, len(reply))
			if _, err := io.ReadFull(connA, rgot); err != nil {
				t.Fatalf("read on A: %v", err)
			}
			if !bytes.Equal(rgot, reply) {
				t.Fatal("payload mismatch B->A")
			}
		})
	}
}
