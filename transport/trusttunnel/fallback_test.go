package trusttunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/sing/common/logger"
	"github.com/metacubex/tls"
)

func newFallbackService(t *testing.T, backend *httptest.Server) *Service {
	t.Helper()
	s := NewService(ServiceOptions{
		Ctx:      context.Background(),
		Logger:   logger.NOP(),
		Fallback: strings.TrimPrefix(backend.URL, "http://"),
	})
	s.UpdateUsers(map[string]string{"user": "pass"})
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestFallbackServesUnauthenticated(t *testing.T) {
	var header http.Header
	var method, host string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header, method, host = r.Header.Clone(), r.Method, r.Host
		w.Header().Set("Server", "cover")
		_, _ = io.WriteString(w, "cover page")
	}))
	defer backend.Close()
	s := newFallbackService(t, backend)

	request := httptest.NewRequest("GET", "https://cover.example/", nil)
	request.Header.Set("Proxy-Authorization", "Basic dXNlcjp3cm9uZw==") // user:wrong
	request.Header.Set("Forwarded", "for=198.51.100.77")
	request.Header.Set("X-Forwarded-For", "198.51.100.77")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("X-Forwarded-Host", "attacker.example")
	recorder := httptest.NewRecorder()
	s.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || recorder.Body.String() != "cover page" || recorder.Header().Get("Server") != "cover" {
		t.Fatalf("got %d %q, want the backend's page", recorder.Code, recorder.Body.String())
	}
	if method != "GET" || host != "cover.example" {
		t.Errorf("backend saw %s %q, want GET cover.example", method, host)
	}
	for _, name := range []string{"Forwarded", "Proxy-Authorization"} {
		if value := header.Get(name); value != "" {
			t.Errorf("%s reached backend: %q", name, value)
		}
	}
	// httptest.NewRequest uses 192.0.2.1 as the client address and sets TLS for https.
	want := map[string]string{"X-Forwarded-For": "192.0.2.1", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "cover.example"}
	for name, value := range want {
		if got := header.Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
}

func TestFallbackForwardsConnect(t *testing.T) {
	var method, host string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, host = r.Method, r.Host
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = io.WriteString(w, "not here")
	}))
	defer backend.Close()
	s := newFallbackService(t, backend)

	recorder := httptest.NewRecorder()
	s.ServeHTTP(recorder, httptest.NewRequest("CONNECT", "example.com:443", nil))
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Body.String() != "not here" {
		t.Errorf("got %d %q, want the backend's own answer", recorder.Code, recorder.Body.String())
	}
	if method != "CONNECT" || host != "example.com:443" {
		t.Errorf("backend saw %s %q, want CONNECT example.com:443", method, host)
	}
}

func TestFallbackBackendDown(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	backend.Close()
	s := newFallbackService(t, backend)

	recorder := httptest.NewRecorder()
	s.ServeHTTP(recorder, httptest.NewRequest("GET", "https://cover.example/", nil))
	if recorder.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", recorder.Code)
	}
}

func TestNoFallbackKeeps407(t *testing.T) {
	s := NewService(ServiceOptions{Ctx: context.Background(), Logger: logger.NOP()})
	recorder := httptest.NewRecorder()
	s.ServeHTTP(recorder, httptest.NewRequest("GET", "https://cover.example/", nil))
	if recorder.Code != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want 407", recorder.Code)
	}
}

func TestFallbackNegotiatesALPN(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cover.example"},
		DNSNames:     []string{"cover.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()
	s := newFallbackService(t, backend)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Like listener/trusttunnel: a certificate and no NextProtos.
	err = s.Start(listener, nil, &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		offer []string
		want  string
	}{
		{[]string{"h2", "http/1.1"}, "h2"},
		{[]string{"http/1.1"}, "http/1.1"},
		{nil, ""},
	} {
		conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: test.offer})
		if err != nil {
			t.Fatalf("offer %v: %v", test.offer, err)
		}
		if got := conn.ConnectionState().NegotiatedProtocol; got != test.want {
			t.Errorf("offer %v: negotiated %q, want %q", test.offer, got, test.want)
		}
		_ = conn.Close()
	}
}
