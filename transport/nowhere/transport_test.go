package nowhere

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/tls"
)

type echoHandler struct{}

func (echoHandler) HandleTCP(_ context.Context, c *ServerConn, target string) {
	defer c.Close()
	if target == "fail.test:80" {
		return
	}
	if c.HandshakeSuccess() != nil {
		return
	}
	_, _ = io.Copy(c, c)
	_ = c.CloseWrite()
}
func (echoHandler) HandleUDP(_ context.Context, p *ServerPacketConn, _ string, _ net.Addr) {
	defer p.Close()
	if p.HandshakeSuccess() != nil {
		return
	}
	b := make([]byte, 65535)
	for {
		_ = p.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := p.ReadFrom(b)
		if err != nil {
			return
		}
		if _, err = p.WriteTo(b[:n], addr); err != nil {
			return
		}
	}
}
func testCertificate(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}
func testServer(t *testing.T, morph bool) string {
	address, _ := testServerInstance(t, morph)
	return address
}
func testServerInstance(t *testing.T, morph bool) (string, *Server) {
	t.Helper()
	s, err := NewServer(ServerConfig{Password: "secret", Morph: morph, TLSConfig: testCertificate(t), Handler: echoHandler{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", l.Addr().String())
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	if err = s.ServeTCP(l); err != nil {
		t.Fatal(err)
	}
	if err = s.ServeUDP(pc); err != nil {
		t.Fatal(err)
	}
	return l.Addr().String(), s
}
func testClient(t *testing.T, address, up, down string, mux, morph bool) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{Password: "secret", Up: up, Down: down, Mux: mux, Morph: morph, TLSConfig: &tls.Config{InsecureSkipVerify: true}, DialTCP: func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", address) }, DialUDP: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		addr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return nil, nil, err
		}
		pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", "127.0.0.1:0")
		return pc, addr, err
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func exerciseTCP(t *testing.T, c *Client, target string, size int) {
	t.Helper()
	conn, err := c.DialContext(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	payload := bytes.Repeat([]byte("nowhere!"), size/8)
	written := make(chan error, 1)
	go func() { written <- writeFull(conn, payload) }()
	response := make([]byte, len(payload))
	_, err = io.ReadFull(conn, response)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-written; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, response) {
		t.Fatal("TCP corruption")
	}
}
func exerciseUDP(t *testing.T, c *Client, target string) {
	t.Helper()
	p, err := c.ListenPacket(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	_ = p.SetDeadline(time.Now().Add(10 * time.Second))
	for _, size := range []int{0, 1, 1200, 16000, 65000} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		if _, err = p.WriteTo(payload, targetAddr(target)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 65535)
		n, _, err := p.ReadFrom(b)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(payload, b[:n]) {
			t.Fatalf("UDP corruption at size %d", size)
		}
	}
}
func TestTransportMatrix(t *testing.T) {
	for _, morph := range []bool{false, true} {
		for _, mux := range []bool{false, true} {
			for _, up := range []string{"tcp", "udp"} {
				for _, down := range []string{"tcp", "udp"} {
					if mux && up == "udp" && down == "udp" {
						continue // Mux only affects TCP carriers.
					}
					t.Run(fmt.Sprintf("%s-%s/mux=%v/morph=%v", up, down, mux, morph), func(t *testing.T) {
						c := testClient(t, testServer(t, morph), up, down, mux, morph)
						exerciseTCP(t, c, "echo.test:80", 256<<10)
						exerciseUDP(t, c, "127.0.0.1:53")
					})
				}
			}
		}
	}
}
func TestMuxConcurrencyAndWindows(t *testing.T) {
	c := testClient(t, testServer(t, false), "tcp", "tcp", true, false)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); exerciseTCP(t, c, "echo.test:80", 10<<20) }()
	}
	wg.Wait()
}
func TestSetupFailureAndCancellation(t *testing.T) {
	c := testClient(t, testServer(t, false), "udp", "tcp", true, false)
	if _, err := c.DialContext(context.Background(), "fail.test:80"); err != SetupError(DialFailed) {
		t.Fatalf("expected DIAL_FAILED, got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := c.DialContext(ctx, "echo.test:80"); err == nil {
		conn.Close()
		t.Fatal("cancelled setup succeeded")
	}
}
