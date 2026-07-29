package shadowtls

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/tls"
)

const (
	testServerName = "shadowtls.example"
	testPassword   = "shadowtls-test-password"
)

func TestServer(t *testing.T) {
	testCases := []struct {
		name        string
		version     int
		fingerprint string
		alpn        []string
	}{
		{name: "v1", version: 1},
		{name: "v2", version: 2},
		{name: "v2-utls-websocket", version: 2, fingerprint: "chrome", alpn: WsALPN},
		{name: "v3", version: 3},
		{name: "v3-utls", version: 3, fingerprint: "chrome"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			camouflageAddr := startCamouflageServer(t, testCase.version == 1)
			serverConfig := newTestServerConfig(t, testCase.version, camouflageAddr)
			frontendAddr, result := startServer(t, serverConfig)

			rawClient, err := net.Dial("tcp", frontendAddr)
			if err != nil {
				t.Fatal(err)
			}
			defer rawClient.Close()
			setTestDeadline(t, rawClient)
			client, err := NewShadowTLS(context.Background(), rawClient, &ShadowTLSOption{
				Password:          testPassword,
				Host:              testServerName,
				ClientFingerprint: testCase.fingerprint,
				SkipCertVerify:    true,
				Version:           testCase.version,
				ALPN:              testCase.alpn,
			})
			if err != nil {
				t.Fatalf("client handshake: %v", err)
			}

			clientPayload := bytes.Repeat([]byte("client-payload-"), 3000)
			if _, err = client.Write(clientPayload); err != nil {
				t.Fatalf("client write: %v", err)
			}
			serverResult := receiveServerResult(t, result)
			if serverResult.err != nil {
				t.Fatalf("server handshake: %v", serverResult.err)
			}
			defer serverResult.conn.Close()
			setTestDeadline(t, serverResult.conn)
			if testCase.version == 3 && serverResult.user != "test-user" {
				t.Fatalf("authenticated user = %q, want test-user", serverResult.user)
			}
			if testCase.version != 3 && serverResult.user != "" {
				t.Fatalf("unexpected authenticated user %q", serverResult.user)
			}
			gotClientPayload := make([]byte, len(clientPayload))
			if _, err = io.ReadFull(serverResult.conn, gotClientPayload); err != nil {
				t.Fatalf("server read: %v", err)
			}
			if !bytes.Equal(gotClientPayload, clientPayload) {
				t.Fatal("server received corrupted client payload")
			}

			serverPayload := bytes.Repeat([]byte("server-payload-"), 3000)
			if _, err = serverResult.conn.Write(serverPayload); err != nil {
				t.Fatalf("server write: %v", err)
			}
			gotServerPayload := make([]byte, len(serverPayload))
			if _, err = io.ReadFull(client, gotServerPayload); err != nil {
				t.Fatalf("client read: %v", err)
			}
			if !bytes.Equal(gotServerPayload, serverPayload) {
				t.Fatal("client received corrupted server payload")
			}
		})
	}
}

func TestUserFromConnThroughWrappers(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})
	authenticated := &authenticatedConn{Conn: left, user: "test-user"}
	conn := N.NewBufferedConn(N.NewCachedConn(authenticated, nil))

	user, ok := UserFromConn(conn)
	if !ok || user != authenticated.user {
		t.Fatalf("UserFromConn() = (%q, %v), want (%q, true)", user, ok, authenticated.user)
	}
}

func TestV3UnauthenticatedConnectionFallsBack(t *testing.T) {
	camouflageAddr := startCamouflageServer(t, false)
	serverConfig := newTestServerConfig(t, 3, camouflageAddr)
	frontendAddr, result := startServer(t, serverConfig)

	rawClient, err := net.Dial("tcp", frontendAddr)
	if err != nil {
		t.Fatal(err)
	}
	setTestDeadline(t, rawClient)
	client := tls.Client(rawClient, &tls.Config{
		ServerName:         testServerName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err = client.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("fallback TLS handshake: %v", err)
	}
	payload := []byte("ordinary TLS connection")
	if _, err = client.Write(payload); err != nil {
		t.Fatalf("fallback write: %v", err)
	}
	response := make([]byte, len(payload))
	if _, err = io.ReadFull(client, response); err != nil {
		t.Fatalf("fallback read: %v", err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatalf("fallback response = %q, want %q", response, payload)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	serverResult := receiveServerResult(t, result)
	if !errors.Is(serverResult.err, ErrFallbackCompleted) {
		t.Fatalf("server error = %v, want %v", serverResult.err, ErrFallbackCompleted)
	}
}

func TestV2InterruptedHeaderRead(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	serverRaw := &readStartedConn{Conn: serverSide, started: make(chan struct{}, 1)}
	server := newConn(serverRaw)
	payload := []byte("payload after interrupted v2 header")
	frame := make([]byte, tlsHeaderSize+len(payload))
	frame[0] = applicationData
	frame[1] = 3
	frame[2] = 3
	binary.BigEndian.PutUint16(frame[3:tlsHeaderSize], uint16(len(payload)))
	copy(frame[tlsHeaderSize:], payload)

	buffer := make([]byte, len(payload))
	serverRead := make(chan error, 1)
	go func() {
		_, err := server.Read(buffer)
		serverRead <- err
	}()
	<-serverRaw.started
	if _, err := clientSide.Write(frame[:2]); err != nil {
		t.Fatalf("write partial header: %v", err)
	}
	<-serverRaw.started
	if err := server.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("interrupt server read: %v", err)
	}
	if err := <-serverRead; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("server read error = %v, want deadline exceeded", err)
	}
	if err := server.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear server read deadline: %v", err)
	}

	clientWrite := make(chan error, 1)
	go func() {
		_, err := clientSide.Write(frame[2:])
		clientWrite <- err
	}()
	if _, err := io.ReadFull(server, buffer); err != nil {
		t.Fatalf("server read completed frame: %v", err)
	}
	if !bytes.Equal(buffer, payload) {
		t.Fatalf("server payload = %q, want %q", buffer, payload)
	}
	if err := <-clientWrite; err != nil {
		t.Fatalf("client write remaining frame: %v", err)
	}
}

func TestV3InterruptedReadDoesNotSendAlert(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	serverRaw := &readStartedConn{Conn: serverSide, started: make(chan struct{}, 1)}
	serverRandom := bytes.Repeat([]byte{1}, tlsRandomSize)
	clientAdd := hmac.New(sha1.New, []byte(testPassword))
	hmacReset(clientAdd, serverRandom, 'C')
	clientVerify := hmac.New(sha1.New, []byte(testPassword))
	hmacReset(clientVerify, serverRandom, 'S')
	serverAdd := hmac.New(sha1.New, []byte(testPassword))
	hmacReset(serverAdd, serverRandom, 'S')
	serverVerify := hmac.New(sha1.New, []byte(testPassword))
	hmacReset(serverVerify, serverRandom, 'C')
	client := newVerifiedConn(clientSide, clientAdd, clientVerify, nil)
	server := newVerifiedConn(serverRaw, serverAdd, serverVerify, nil)

	type readResult struct {
		data []byte
		err  error
	}
	clientRead := make(chan readResult, 1)
	response := []byte("response after interrupted idle read")
	go func() {
		buffer := make([]byte, len(response))
		_, err := io.ReadFull(client, buffer)
		clientRead <- readResult{data: buffer, err: err}
	}()

	serverRead := make(chan error, 1)
	go func() {
		var buffer [1]byte
		_, err := server.Read(buffer[:])
		serverRead <- err
	}()
	<-serverRaw.started
	if err := server.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("interrupt server read: %v", err)
	}
	if err := <-serverRead; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("server read error = %v, want deadline exceeded", err)
	}
	if err := server.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear server read deadline: %v", err)
	}
	select {
	case result := <-clientRead:
		t.Fatalf("client received data before response: data=%x err=%v", result.data, result.err)
	default:
	}

	request := []byte("request after interrupted partial read")
	frame := makeV3ClientFrame(client, request)
	buffer := make([]byte, len(request))
	serverRead = make(chan error, 1)
	go func() {
		_, err := server.Read(buffer)
		serverRead <- err
	}()
	<-serverRaw.started
	if _, err := clientSide.Write(frame[:tlsHeaderSize]); err != nil {
		t.Fatalf("write partial request: %v", err)
	}
	<-serverRaw.started
	if err := server.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("interrupt partial server read: %v", err)
	}
	if err := <-serverRead; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("partial server read error = %v, want deadline exceeded", err)
	}
	if err := server.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear partial server read deadline: %v", err)
	}
	select {
	case result := <-clientRead:
		t.Fatalf("client received data after interrupted partial read: data=%x err=%v", result.data, result.err)
	default:
	}

	clientWrite := make(chan error, 1)
	go func() {
		_, err := clientSide.Write(frame[tlsHeaderSize:])
		clientWrite <- err
	}()
	if _, err := io.ReadFull(server, buffer); err != nil {
		t.Fatalf("server read request: %v", err)
	}
	if !bytes.Equal(buffer, request) {
		t.Fatalf("server request = %q, want %q", buffer, request)
	}
	if err := <-clientWrite; err != nil {
		t.Fatalf("client write request: %v", err)
	}

	serverWrite := make(chan error, 1)
	go func() {
		_, err := server.Write(response)
		serverWrite <- err
	}()
	result := <-clientRead
	if result.err != nil {
		t.Fatalf("client read response: %v", result.err)
	}
	if !bytes.Equal(result.data, response) {
		t.Fatalf("client response = %q, want %q", result.data, response)
	}
	if err := <-serverWrite; err != nil {
		t.Fatalf("server write response: %v", err)
	}
}

type readStartedConn struct {
	net.Conn
	started chan struct{}
}

func (c *readStartedConn) Read(p []byte) (int, error) {
	select {
	case c.started <- struct{}{}:
	default:
	}
	return c.Conn.Read(p)
}

func makeV3ClientFrame(client *verifiedConn, payload []byte) []byte {
	frame := make([]byte, tlsHMACHeaderSize+len(payload))
	frame[0] = applicationData
	frame[1] = 3
	frame[2] = 3
	binary.BigEndian.PutUint16(frame[3:tlsHeaderSize], uint16(hmacSize+len(payload)))
	_, _ = client.hmacAdd.Write(payload)
	hmacHash := client.hmacAdd.Sum(nil)[:hmacSize]
	_, _ = client.hmacAdd.Write(hmacHash)
	copy(frame[tlsHeaderSize:tlsHMACHeaderSize], hmacHash)
	copy(frame[tlsHMACHeaderSize:], payload)
	return frame
}

func TestHandshakeSelectionByServerName(t *testing.T) {
	frame := captureClientHello(t, "mapped.example")
	if serverName, err := extractServerName(frame); err != nil || serverName != "mapped.example" {
		t.Fatalf("extractServerName() = %q, %v", serverName, err)
	}
	dial := (&net.Dialer{}).DialContext
	serverConfig, err := NewServerConfig(
		2,
		"",
		nil,
		HandshakeConfig{Server: "default.example:443", DialContext: dial},
		map[string]HandshakeConfig{
			"mapped.example": {Server: "mapped.example:8443", DialContext: dial},
		},
		false,
		WildcardSNIOff,
	)
	if err != nil {
		t.Fatal(err)
	}
	if selected := serverConfig.selectHandshake(frame); selected.Server != "mapped.example:8443" {
		t.Fatalf("selected server = %q, want mapped.example:8443", selected.Server)
	}
}

func TestV3WildcardSNISelection(t *testing.T) {
	defaultHandshake := HandshakeConfig{Server: "default.example:443"}
	customHandshake := HandshakeConfig{Server: "custom-upstream.example:443"}
	testCases := []struct {
		name          string
		mode          WildcardSNI
		serverName    string
		authenticated bool
		want          string
	}{
		{name: "off-authenticated", mode: WildcardSNIOff, serverName: "other.example", authenticated: true, want: defaultHandshake.Server},
		{name: "authed-authenticated", mode: WildcardSNIAuthed, serverName: "other.example", authenticated: true, want: "other.example:443"},
		{name: "authed-fallback", mode: WildcardSNIAuthed, serverName: "other.example", authenticated: false, want: defaultHandshake.Server},
		{name: "all-fallback", mode: WildcardSNIAll, serverName: "other.example", authenticated: false, want: "other.example:443"},
		{name: "custom-fallback", mode: WildcardSNIOff, serverName: "custom.example", authenticated: false, want: customHandshake.Server},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			serverConfig := &ServerConfig{
				handshake:              defaultHandshake,
				handshakeForServerName: map[string]HandshakeConfig{"custom.example": customHandshake},
				wildcardSNI:            testCase.mode,
			}
			if got := serverConfig.selectV3Handshake(testCase.serverName, testCase.authenticated).Server; got != testCase.want {
				t.Fatalf("selected server = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestVerifiedConnZeroLengthWrite(t *testing.T) {
	underlying := new(writeSpyConn)
	hmacAdd := hmac.New(sha1.New, []byte(testPassword))
	conn := newVerifiedConn(underlying, hmacAdd, nil, nil)
	before := append([]byte(nil), hmacAdd.Sum(nil)...)

	n, err := conn.Write(nil)
	if err != nil || n != 0 {
		t.Fatalf("Write(nil) = %d, %v; want 0, nil", n, err)
	}
	if underlying.writes != 0 {
		t.Fatalf("underlying writes = %d, want 0", underlying.writes)
	}
	if !bytes.Equal(hmacAdd.Sum(nil), before) {
		t.Fatal("Write(nil) advanced the HMAC state")
	}
}

type writeSpyConn struct {
	net.Conn
	writes int
}

func (c *writeSpyConn) Write(p []byte) (int, error) {
	c.writes++
	return len(p), nil
}

type serverResult struct {
	conn net.Conn
	user string
	err  error
}

func newTestServerConfig(t *testing.T, version int, camouflageAddr string) *ServerConfig {
	t.Helper()
	var users []User
	if version == 3 {
		users = []User{{Name: "test-user", Password: testPassword}}
	}
	serverConfig, err := NewServerConfig(
		version,
		testPassword,
		users,
		HandshakeConfig{Server: camouflageAddr, DialContext: (&net.Dialer{}).DialContext},
		nil,
		version == 3,
		WildcardSNIOff,
	)
	if err != nil {
		t.Fatal(err)
	}
	return serverConfig
}

func startServer(t *testing.T, serverConfig *ServerConfig) (string, <-chan serverResult) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	result := make(chan serverResult, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			result <- serverResult{err: acceptErr}
			return
		}
		setTestDeadline(t, conn)
		shadowConn, serverErr := Server(context.Background(), conn, serverConfig)
		user, _ := UserFromConn(shadowConn)
		result <- serverResult{conn: shadowConn, user: user, err: serverErr}
	}()
	return listener.Addr().String(), result
}

func startCamouflageServer(t *testing.T, tls12Only bool) string {
	t.Helper()
	certificatePEM, privateKeyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair([]byte(certificatePEM), []byte(privateKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   append([]string(nil), DefaultALPN...),
		MinVersion:   tls.VersionTLS12,
	}
	if tls12Only {
		config.MaxVersion = tls.VersionTLS12
	}
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(rawListener, config)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				setTestDeadline(t, conn)
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		client := tls.Client(clientSide, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		_ = client.Handshake()
	}()
	frame, err := readFrame(serverSide)
	if err != nil {
		t.Fatal(err)
	}
	_ = serverSide.Close()
	<-done
	return frame
}

func receiveServerResult(t *testing.T, result <-chan serverResult) serverResult {
	t.Helper()
	select {
	case serverResult := <-result:
		return serverResult
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for ShadowTLS server")
		return serverResult{}
	}
}

func setTestDeadline(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Errorf("set deadline: %v", err)
	}
}
