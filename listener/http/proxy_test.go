package http

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"

	"github.com/metacubex/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testTunnel struct {
	handler func(conn net.Conn, req *http.Request)
}

func (tt *testTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		tt.handler(conn, req)
	}
}

func (tt *testTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {}

func (tt *testTunnel) NatTable() C.NatTable { return nil }

func serveProxyConn(t *testing.T, tunnel C.Tunnel) (net.Conn, *bufio.Reader) {
	cli, srv := net.Pipe()
	done := make(chan struct{})
	go func() {
		HandleConn(srv, tunnel, authStore.Nil)
		close(done)
	}()
	t.Cleanup(func() {
		_ = cli.Close()
		<-done
	})
	require.NoError(t, cli.SetDeadline(time.Now().Add(10*time.Second)))
	return cli, bufio.NewReader(cli)
}

func readProxyResponse(t *testing.T, br *bufio.Reader) (*http.Response, string) {
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, string(body)
}

func TestHandleConnKeepAlive(t *testing.T) {
	tunnel := &testTunnel{handler: func(conn net.Conn, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	}}
	cli, br := serveProxyConn(t, tunnel)

	for _, body := range []string{"hello", "world"} {
		_, err := fmt.Fprintf(cli, "POST http://example.com/echo HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		require.NoError(t, err)

		resp, respBody := readProxyResponse(t, br)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, body, respBody)
		assert.False(t, resp.Close)
	}
}

// The upstream answers before it has read the request body, so http.Transport is
// still copying the body from the client connection after the response is relayed.
func TestHandleConnKeepAliveEarlyResponse(t *testing.T) {
	tunnel := &testTunnel{handler: func(conn net.Conn, req *http.Request) {
		if req.Method == http.MethodPost {
			_, _ = io.WriteString(conn, "HTTP/1.1 413 Request Entity Too Large\r\nContent-Length: 2\r\n\r\nno")
			time.Sleep(100 * time.Millisecond) // let HandleConn get back to reading the next request
			_, _ = io.Copy(io.Discard, req.Body)
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	}}
	cli, br := serveProxyConn(t, tunnel)

	body := strings.Repeat("x", 4<<20)
	go func() {
		_, _ = fmt.Fprintf(cli, "POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nContent-Length: %d\r\n\r\n", len(body))
		_, _ = io.WriteString(cli, body)
		_, _ = io.WriteString(cli, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n")
	}()

	resp, respBody := readProxyResponse(t, br)
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	assert.Equal(t, "no", respBody)

	resp, respBody = readProxyResponse(t, br)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "ok", respBody)
}
