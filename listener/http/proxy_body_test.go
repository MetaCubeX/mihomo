package http

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// echoTunnel answers every request it gets with "<method> <body>".
type echoTunnel struct{ fail bool }

func (t echoTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()
	if t.fail {
		return
	}
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body, _ := io.ReadAll(req.Body)
		reply := req.Method + " " + string(body)
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(reply), reply)
	}
}

func (echoTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {}

func (echoTunnel) NatTable() C.NatTable { return nil }

func startProxy(t *testing.T, tunnel C.Tunnel, store auth.AuthStore) (net.Conn, *bufio.Reader) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		c, err := l.Accept()
		if err == nil {
			HandleConn(c, tunnel, store)
		}
	}()
	conn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))
	return conn, bufio.NewReader(conn)
}

func readResponse(t *testing.T, br *bufio.Reader) (*http.Response, string) {
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, string(body)
}

func testAuthStore() auth.AuthStore {
	return authStore.NewAuthStore(auth.NewAuthenticator([]auth.AuthUser{{User: "user", Pass: "pass"}}))
}

func proxyAuth(user, pass string) string {
	return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) + "\r\n"
}

const postHead = "POST http://example.com/echo HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n"

func TestHandleConnRejectedBodyKeepAlive(t *testing.T) {
	for _, tt := range []struct {
		name   string
		store  auth.AuthStore
		first  string
		status int
	}{
		{"407", testAuthStore(), postHead + "Content-Length: 5\r\n\r\nhello", http.StatusProxyAuthRequired},
		{"407 chunked", testAuthStore(), postHead + "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", http.StatusProxyAuthRequired},
		{"403", testAuthStore(), postHead + proxyAuth("user", "wrong") + "Content-Length: 5\r\n\r\nhello", http.StatusForbidden},
		{"400", authStore.Nil, "POST /echo HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nContent-Length: 5\r\n\r\nhello", http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn, br := startProxy(t, echoTunnel{}, tt.store)

			_, err := io.WriteString(conn, tt.first)
			require.NoError(t, err)
			resp, _ := readResponse(t, br)
			assert.Equal(t, tt.status, resp.StatusCode)
			assert.False(t, resp.Close)

			// retry on the same connection
			_, err = io.WriteString(conn, postHead+proxyAuth("user", "pass")+"Content-Length: 5\r\n\r\nworld")
			require.NoError(t, err)
			resp, body := readResponse(t, br)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "POST world", body)
		})
	}
}

func TestHandleConnRejectedBodyClose(t *testing.T) {
	large := strings.Repeat("x", maxDiscardBodyBytes+1)
	for _, tt := range []struct {
		name   string
		tunnel echoTunnel
		store  auth.AuthStore
		req    string
		status int
	}{
		{"large body", echoTunnel{}, testAuthStore(), postHead + fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(large), large), http.StatusProxyAuthRequired},
		// the client waits for "100 Continue", so the body never arrives
		{"expect continue", echoTunnel{}, testAuthStore(), postHead + "Expect: 100-continue\r\nContent-Length: 5\r\n\r\n", http.StatusProxyAuthRequired},
		{"bad gateway", echoTunnel{fail: true}, authStore.Nil, postHead + "Content-Length: 5\r\n\r\nhello", http.StatusBadGateway},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn, br := startProxy(t, tt.tunnel, tt.store)

			go func() { _, _ = io.WriteString(conn, tt.req) }()
			resp, _ := readResponse(t, br)
			assert.Equal(t, tt.status, resp.StatusCode)
			assert.True(t, resp.Close)

			_, err := br.ReadByte()
			assert.Equal(t, io.EOF, err) // closed by the server, nothing parsed from the leftover body
		})
	}
}
