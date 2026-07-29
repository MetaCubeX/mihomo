package jls

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	tls "github.com/metacubex/jls-tls"
	httpTLS "github.com/metacubex/tls"
)

func TestJLSForbiddenRandomSuffix(t *testing.T) {
	for _, suffix := range []string{jlsDowngradeCanaryTLS12, jlsDowngradeCanaryTLS11, jlsHelloRetryRequestRandomSuffix} {
		random := append(make([]byte, jlsHelloRandomLen-len(suffix)), suffix...)
		if !jlsHasForbiddenRandomSuffix(random) {
			t.Fatalf("JLS accepted forbidden random suffix %x", suffix)
		}
	}
	if jlsHasForbiddenRandomSuffix(make([]byte, jlsHelloRandomLen)) {
		t.Fatal("JLS rejected an ordinary random suffix")
	}
}

func TestJLSClientServer(t *testing.T) {
	for _, clientFingerprint := range []string{"", "chrome"} {
		name := "Go"
		if clientFingerprint != "" {
			name = "uTLS"
		}
		t.Run(name, func(t *testing.T) {
			testJLSClientServer(t, clientFingerprint)
		})
	}
}

func testJLSClientServer(t *testing.T, clientFingerprint string) {
	user := User{Username: "test-user", Password: "test-password"}
	serverConfig, err := NewServerConfig("camouflage.example", "camouflage.example:443", []User{user}, nil, 0, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("authenticated JLS connection dialed fallback")
	})
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := NewClientConfig("camouflage.example", user.Username, user.Password, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.ClientFingerprint = clientFingerprint

	serverSide, clientSide := newLocalTCPPair(t)
	serverDone := make(chan error, 1)
	go func() {
		conn, err := Server(context.Background(), serverSide, serverConfig)
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		state := conn.(*tls.Conn).ConnectionState()
		if state.JLS.Status != tls.JLSAuthenticated || state.JLS.User != user.Username {
			serverDone <- errors.New("server did not authenticate JLS user")
			return
		}
		outerTLS := tls.Server(N.NewBufferedConn(N.NewCachedConn(conn, nil)), &tls.Config{})
		if authenticatedUser, ok := UserFromConn(outerTLS); !ok || authenticatedUser != user.Username {
			serverDone <- errors.New("server did not expose JLS user")
			return
		}
		outerJLS := tls.Server(outerTLS, &tls.Config{JLSConfig: &tls.JLSConfig{Enable: true}})
		if _, ok := UserFromConn(outerJLS); ok {
			serverDone <- errors.New("server exposed an inner JLS user through an unauthenticated outer JLS connection")
			return
		}
		_, err = io.Copy(conn, conn)
		serverDone <- err
	}()

	client, err := NewClient(context.Background(), clientSide, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("JLS over TCP")
	if _, err = client.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatalf("response = %q, want %q", response, payload)
	}
	_ = client.Close()
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestJLSUTLSClientRejectsInvalidFallbackCertificate(t *testing.T) {
	tlsConfig := newTestTLSServerConfig(t, tls.VersionTLS13)
	serverSide, clientSide := newLocalTCPPair(t)
	serverDone := make(chan error, 1)
	go func() {
		server := tls.Server(serverSide, tlsConfig)
		serverDone <- server.Handshake()
		_ = serverSide.Close()
	}()

	config, err := NewClientConfig("camouflage.example", "user", "password", nil)
	if err != nil {
		t.Fatal(err)
	}
	config.ClientFingerprint = "chrome"
	if conn, clientErr := NewClient(context.Background(), clientSide, config); clientErr == nil || errors.Is(clientErr, ErrJLSAuthFailed) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("client error = %v, want fallback certificate verification error", clientErr)
	}
	<-serverDone
}

func TestJLSUTLSClientFallback(t *testing.T) {
	for _, test := range []struct {
		name     string
		protocol string
		hrr      bool
	}{
		{name: "HTTP/1.1", protocol: "http/1.1"},
		{name: "HTTP/2", protocol: "h2"},
		{name: "HelloRetryRequest", protocol: "http/1.1", hrr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			requestProtocol := make(chan string, 1)
			hrrObserved := make(chan bool, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requestProtocol <- request.Proto
				writer.WriteHeader(http.StatusNoContent)
			}))
			server.EnableHTTP2 = test.protocol == "h2"
			if test.hrr {
				server.TLS = &httpTLS.Config{
					CurvePreferences: []httpTLS.CurveID{httpTLS.CurveP256},
					VerifyConnection: func(state httpTLS.ConnectionState) error {
						hrrObserved <- state.HelloRetryRequest
						return nil
					},
				}
			}
			server.StartTLS()
			defer func() {
				server.CloseClientConnections()
				server.Close()
			}()
			ca.GetCertPool().AddCert(server.Certificate())

			clientSide, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			config, err := NewClientConfig("example.com", "user", "password", []string{test.protocol})
			if err != nil {
				t.Fatal(err)
			}
			config.ClientFingerprint = "chrome"
			if conn, clientErr := NewClient(context.Background(), clientSide, config); !errors.Is(clientErr, ErrJLSAuthFailed) {
				if conn != nil {
					_ = conn.Close()
				}
				t.Fatalf("client error = %v, want %v", clientErr, ErrJLSAuthFailed)
			}

			wantProtocol := "HTTP/1.1"
			if test.protocol == "h2" {
				wantProtocol = "HTTP/2.0"
			}
			select {
			case got := <-requestProtocol:
				if got != wantProtocol {
					t.Fatalf("fallback protocol = %q, want %q", got, wantProtocol)
				}
			default:
				t.Fatal("fallback HTTP request was not sent")
			}
			if test.hrr && !<-hrrObserved {
				t.Fatal("ordinary TLS fallback did not exercise HelloRetryRequest")
			}
		})
	}
}

func TestJLSServerFallsBackBeforeServerFlight(t *testing.T) {
	user := User{Username: "user", Password: "password"}
	for _, test := range []struct {
		name      string
		configure func(*ServerConfig, *ClientConfig)
	}{
		{
			name: "HelloRetryRequest",
			configure: func(serverConfig *ServerConfig, _ *ClientConfig) {
				serverConfig.TLSConfig.CurvePreferences = []tls.CurveID{tls.CurveP256}
			},
		},
		{
			name: "missing certificate",
			configure: func(serverConfig *ServerConfig, _ *ClientConfig) {
				serverConfig.TLSConfig.Certificates = nil
			},
		},
		{
			name: "ALPN mismatch",
			configure: func(serverConfig *ServerConfig, clientConfig *ClientConfig) {
				serverConfig.TLSConfig.NextProtos = []string{"h3"}
				clientConfig.ALPN = []string{"http/1.1"}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			testJLSServerFallsBackBeforeServerFlight(t, user, test.configure)
		})
	}
}

func testJLSServerFallsBackBeforeServerFlight(t *testing.T, user User, configure func(*ServerConfig, *ClientConfig)) {
	t.Helper()
	fallbackRequest := make(chan struct{}, 1)
	fallback := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fallbackRequest <- struct{}{}
		writer.WriteHeader(http.StatusNoContent)
	}))
	fallback.StartTLS()
	defer func() {
		fallback.CloseClientConnections()
		fallback.Close()
	}()
	ca.GetCertPool().AddCert(fallback.Certificate())

	fallbackDialed := make(chan struct{}, 1)
	serverConfig, err := NewServerConfig("example.com", fallback.Listener.Addr().String(), []User{user}, nil, 0, func(ctx context.Context, network, _ string) (net.Conn, error) {
		fallbackDialed <- struct{}{}
		return (&net.Dialer{}).DialContext(ctx, network, fallback.Listener.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := NewClientConfig("example.com", user.Username, user.Password, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.ClientFingerprint = "chrome"
	configure(serverConfig, clientConfig)

	serverSide, clientSide := newLocalTCPPair(t)
	serverDone := make(chan error, 1)
	go func() {
		defer serverSide.Close()
		_, serverErr := Server(context.Background(), serverSide, serverConfig)
		serverDone <- serverErr
	}()

	if conn, clientErr := NewClient(context.Background(), clientSide, clientConfig); !errors.Is(clientErr, ErrJLSAuthFailed) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("client error = %v, want %v", clientErr, ErrJLSAuthFailed)
	}
	_ = clientSide.Close()
	if err = <-serverDone; !errors.Is(err, ErrFallbackCompleted) {
		t.Fatalf("server error = %v, want %v", err, ErrFallbackCompleted)
	}
	select {
	case <-fallbackDialed:
	default:
		t.Fatal("JLS server did not dial fallback")
	}
	select {
	case <-fallbackRequest:
	default:
		t.Fatal("fallback HTTP request was not sent")
	}
}

func TestNewServerConfigRequiresDialContext(t *testing.T) {
	_, err := NewServerConfig(
		"camouflage.example",
		"camouflage.example:443",
		[]User{{Username: "user", Password: "password"}},
		nil,
		0,
		nil,
	)
	if err == nil || err.Error() != "jls: dial context is required" {
		t.Fatalf("error = %v, want dial context required error", err)
	}
}

func TestJLSServerFallback(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			testJLSServerFallback(t, version)
		})
	}
}

func testJLSServerFallback(t *testing.T, version uint16) {
	upstreamConfig := newTestTLSServerConfig(t, version)
	upstreamClient, upstreamServer := net.Pipe()
	upstreamDone := make(chan error, 1)
	go func() {
		conn := tls.Server(upstreamServer, upstreamConfig)
		if err := conn.Handshake(); err != nil {
			upstreamDone <- err
			return
		}
		_, err := io.Copy(conn, conn)
		upstreamDone <- err
	}()

	serverConfig, err := NewServerConfig("camouflage.example", "camouflage.example:443", []User{{Username: "user", Password: "password"}}, nil, 0, func(context.Context, string, string) (net.Conn, error) {
		return upstreamClient, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	serverSide, clientSide := net.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		_, err := Server(context.Background(), serverSide, serverConfig)
		serverDone <- err
	}()

	client := tls.Client(clientSide, &tls.Config{
		ServerName:         "camouflage.example",
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	})
	if err = client.Handshake(); err != nil {
		t.Fatal(err)
	}
	payload := []byte("ordinary TLS fallback")
	if _, err = client.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatalf("response = %q, want %q", response, payload)
	}
	_ = client.Close()
	if err = <-serverDone; !errors.Is(err, ErrFallbackCompleted) {
		t.Fatalf("server error = %v, want %v", err, ErrFallbackCompleted)
	}
	if err = <-upstreamDone; err != nil {
		t.Fatal(err)
	}
}

func TestJLSServerDoesNotFallbackAfterServerFlight(t *testing.T) {
	user := User{Username: "user", Password: "password"}
	fallbackDialed := false
	serverConfig, err := NewServerConfig("camouflage.example", "camouflage.example:443", []User{user}, nil, 0, func(context.Context, string, string) (net.Conn, error) {
		fallbackDialed = true
		return nil, errors.New("fallback dialed")
	})
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := NewClientConfig("camouflage.example", user.Username, user.Password, nil)
	if err != nil {
		t.Fatal(err)
	}
	serverSide, clientSide := net.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		_, err := Server(context.Background(), serverSide, serverConfig)
		serverDone <- err
	}()

	client, clientErr := NewClient(context.Background(), &failWritesAfterReadConn{Conn: clientSide}, clientConfig)
	if client != nil {
		_ = client.Close()
	}
	_ = clientSide.Close()
	if clientErr == nil {
		t.Fatal("client handshake unexpectedly succeeded")
	}
	if serverErr := <-serverDone; serverErr == nil {
		t.Fatal("server handshake unexpectedly succeeded")
	}
	if fallbackDialed {
		t.Fatal("post-flight handshake failure dialed fallback")
	}
}

type failWritesAfterReadConn struct {
	net.Conn
	read atomic.Bool
}

func (c *failWritesAfterReadConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.read.Store(true)
	}
	return n, err
}

func (c *failWritesAfterReadConn) Write(p []byte) (int, error) {
	if c.read.Load() {
		return 0, errors.New("test client write failed after reading server flight")
	}
	return c.Conn.Write(p)
}

func TestJLSServerFallbackReplaysRejectedTLS(t *testing.T) {
	request := []byte{23, 3, 3, 0, 1, 0} // Application data before ClientHello.
	response := []byte("camouflage response")

	upstreamClient, upstreamServer := net.Pipe()
	upstreamDone := make(chan error, 1)
	go func() {
		defer upstreamServer.Close()
		got := make([]byte, len(request))
		if _, err := io.ReadFull(upstreamServer, got); err != nil {
			upstreamDone <- err
			return
		}
		if !bytes.Equal(got, request) {
			upstreamDone <- errors.New("fallback received modified handshake bytes")
			return
		}
		_, err := upstreamServer.Write(response)
		upstreamDone <- err
	}()

	serverConfig, err := NewServerConfig("camouflage.example", "camouflage.example:443", []User{{Username: "user", Password: "password"}}, nil, 0, func(context.Context, string, string) (net.Conn, error) {
		return upstreamClient, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	serverSide, clientSide := net.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		_, err := Server(context.Background(), serverSide, serverConfig)
		serverDone <- err
	}()

	if _, err = clientSide.Write(request); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(response))
	if _, err = io.ReadFull(clientSide, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("fallback response = %q, want %q", got, response)
	}
	_ = clientSide.Close()
	if err = <-serverDone; !errors.Is(err, ErrFallbackCompleted) {
		t.Fatalf("server error = %v, want %v", err, ErrFallbackCompleted)
	}
	if err = <-upstreamDone; err != nil {
		t.Fatal(err)
	}
}

func TestBitRateLimiterReservations(t *testing.T) {
	limiter := &bitRateLimiter{rateBps: 800}
	now := time.Unix(0, 0)
	if delay := limiter.reserveN(now, 1); delay != 0 {
		t.Fatalf("initial reservation delay = %s, want 0", delay)
	}
	if delay := limiter.reserveN(now, 1); delay != 10*time.Millisecond {
		t.Fatalf("second reservation delay = %s, want 10ms", delay)
	}
}

func newTestTLSServerConfig(t *testing.T, version uint16) *tls.Config {
	t.Helper()
	certificatePEM, privateKeyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair([]byte(certificatePEM), []byte(privateKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   version,
		MaxVersion:   version,
	}
}

// newLocalTCPPair mirrors crypto/tls's test helper. A real TCP connection has
// enough buffering to avoid net.Pipe deadlocks when TLS handshake writes cross,
// such as a server ticket flight and the client's Finished message.
func newLocalTCPPair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		accepted <- struct {
			conn net.Conn
			err  error
		}{conn: conn, err: acceptErr}
	}()
	client, err = net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	result := <-accepted
	if result.err != nil {
		_ = client.Close()
		t.Fatal(result.err)
	}
	return result.conn, client
}
