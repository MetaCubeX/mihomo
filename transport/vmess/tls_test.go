package vmess

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"

	tlsC "github.com/metacubex/mihomo/component/tls"
)

func TestStreamTLSConnDefaultsEmptyRealityFingerprint(t *testing.T) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))

	result := make(chan error, 1)
	go func() {
		_, err := StreamTLSConn(context.Background(), client, &TLSConfig{
			Host: "example.com",
			Reality: &tlsC.RealityConfig{
				PublicKey: privateKey.PublicKey(),
			},
		})
		result <- err
	}()

	header := make([]byte, 1)
	readResult := make(chan error, 1)
	go func() {
		_, err := server.Read(header)
		readResult <- err
	}()
	select {
	case err := <-result:
		t.Fatalf("empty REALITY fingerprint failed before ClientHello: %v", err)
	case err := <-readResult:
		if err != nil {
			t.Fatalf("read ClientHello: %v", err)
		}
		if header[0] != 22 {
			t.Fatalf("first TLS record type = %d, want handshake (22)", header[0])
		}
	}
}

func TestStreamTLSConnRejectsExplicitNoneRealityFingerprint(t *testing.T) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_, err = StreamTLSConn(context.Background(), client, &TLSConfig{
		Host:              "example.com",
		ClientFingerprint: "none",
		Reality: &tlsC.RealityConfig{
			PublicKey: privateKey.PublicKey(),
		},
	})
	if err == nil || !strings.Contains(err.Error(), "client-fingerprint") {
		t.Fatalf("explicit none error = %v, want client-fingerprint error", err)
	}
}
