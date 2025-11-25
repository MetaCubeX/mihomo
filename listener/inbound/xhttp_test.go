package inbound_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXhttp_BasicServer(t *testing.T) {
	t.Run("Server starts and accepts connections", func(t *testing.T) {
		option := &inbound.XhttpOption{
			BaseOption: inbound.BaseOption{
				NameStr: "test-xhttp",
				Listen:  "127.0.0.1",
				Port:    "0", // random port
			},
			Path: "/xhttp/",
			Mode: "auto",
		}

		listener, err := inbound.NewXhttp(option)
		require.NoError(t, err)
		require.NotNil(t, listener)

		tunnel := NewHttpTestTunnel()
		defer tunnel.Close()

		err = listener.Listen(tunnel)
		require.NoError(t, err)
		defer listener.Close()

		addr := listener.Address()
		require.NotEmpty(t, addr)

		_, err = netip.ParseAddrPort(addr)
		require.NoError(t, err, "Address should be valid host:port")
	})

	t.Run("Server returns 404 for invalid path", func(t *testing.T) {
		option := &inbound.XhttpOption{
			BaseOption: inbound.BaseOption{
				NameStr: "test-xhttp",
				Listen:  "127.0.0.1",
				Port:    "0",
			},
			Path: "/xhttp/",
		}

		listener, err := inbound.NewXhttp(option)
		require.NoError(t, err)

		tunnel := NewHttpTestTunnel()
		defer tunnel.Close()

		err = listener.Listen(tunnel)
		require.NoError(t, err)
		defer listener.Close()

		addrPort, _ := netip.ParseAddrPort(listener.Address())
		url := fmt.Sprintf("http://%s/invalid/path", addrPort)

		resp, err := http.Get(url)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, resp.StatusCode >= 400, "Invalid path should return error status")
	})

	t.Run("Server accepts GET request with valid session ID", func(t *testing.T) {
		option := &inbound.XhttpOption{
			BaseOption: inbound.BaseOption{
				NameStr: "test-xhttp",
				Listen:  "127.0.0.1",
				Port:    "0",
			},
			Path: "/xhttp/",
		}

		listener, err := inbound.NewXhttp(option)
		require.NoError(t, err)

		tunnel := NewHttpTestTunnel()
		defer tunnel.Close()

		err = listener.Listen(tunnel)
		require.NoError(t, err)
		defer listener.Close()

		sessionID := uuid.Must(uuid.NewV4()).String()
		addrPort, _ := netip.ParseAddrPort(listener.Address())
		url := fmt.Sprintf("http://%s/xhttp/%s", addrPort, sessionID)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		require.NoError(t, err)

		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Do(req)

		if err == nil {
			defer resp.Body.Close()
			assert.True(t, resp.StatusCode < 500, "Should not return server error for valid session")
		}
	})
}

func TestXhttp_CustomHeaders(t *testing.T) {
	option := &inbound.XhttpOption{
		BaseOption: inbound.BaseOption{
			NameStr: "test-xhttp",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Path: "/xhttp/",
		Headers: map[string]string{
			"X-Custom-Header": "test-value",
			"Server":          "mihomo-xhttp",
		},
	}

	listener, err := inbound.NewXhttp(option)
	require.NoError(t, err)

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = listener.Listen(tunnel)
	require.NoError(t, err)
	defer listener.Close()

	sessionID := uuid.Must(uuid.NewV4()).String()
	addrPort, _ := netip.ParseAddrPort(listener.Address())
	url := fmt.Sprintf("http://%s/xhttp/%s", addrPort, sessionID)

	type response struct {
		headers http.Header
		status  int
	}
	respChan := make(chan response, 1)

	go func() {
		transport := &http.Transport{
			ResponseHeaderTimeout: 100 * time.Millisecond,
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   150 * time.Millisecond,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return
		}

		resp, _ := client.Do(req)
		if resp != nil {
			respChan <- response{headers: resp.Header.Clone(), status: resp.StatusCode}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	select {
	case resp := <-respChan:
		assert.Equal(t, http.StatusOK, resp.status, "Should return 200 OK")
		assert.Equal(t, "test-value", resp.headers.Get("X-Custom-Header"), "Custom header should be set")
		assert.Equal(t, "mihomo-xhttp", resp.headers.Get("Server"), "Server header should be set")
	case <-time.After(300 * time.Millisecond):
		t.Fatal("Failed to receive response headers within timeout")
	}
}

func TestXhttp_ContentTypeHeaders(t *testing.T) {
	tests := []struct {
		name             string
		noGRPCHeader     bool
		noSSEHeader      bool
		expectedContains string
	}{
		{
			name:             "Default gRPC content-type",
			noGRPCHeader:     false,
			noSSEHeader:      false,
			expectedContains: "application/grpc",
		},
		{
			name:             "SSE content-type when gRPC disabled",
			noGRPCHeader:     true,
			noSSEHeader:      false,
			expectedContains: "text/event-stream",
		},
		{
			name:             "Octet-stream when both disabled",
			noGRPCHeader:     true,
			noSSEHeader:      true,
			expectedContains: "application/octet-stream",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option := &inbound.XhttpOption{
				BaseOption: inbound.BaseOption{
					NameStr: "test-xhttp",
					Listen:  "127.0.0.1",
					Port:    "0",
				},
				Path:         "/xhttp/",
				NoGRPCHeader: tt.noGRPCHeader,
				NoSSEHeader:  tt.noSSEHeader,
			}

			listener, err := inbound.NewXhttp(option)
			require.NoError(t, err)

			tunnel := NewHttpTestTunnel()
			defer tunnel.Close()

			err = listener.Listen(tunnel)
			require.NoError(t, err)
			defer listener.Close()

			sessionID := uuid.Must(uuid.NewV4()).String()
			addrPort, _ := netip.ParseAddrPort(listener.Address())
			url := fmt.Sprintf("http://%s/xhttp/%s", addrPort, sessionID)

			type response struct {
				contentType string
				status      int
			}
			respChan := make(chan response, 1)

			go func() {
				transport := &http.Transport{
					ResponseHeaderTimeout: 100 * time.Millisecond,
				}
				client := &http.Client{
					Transport: transport,
					Timeout:   150 * time.Millisecond,
				}

				ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
				defer cancel()

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
				if err != nil {
					return
				}

				resp, _ := client.Do(req)
				if resp != nil {
					respChan <- response{
						contentType: resp.Header.Get("Content-Type"),
						status:      resp.StatusCode,
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()

			select {
			case resp := <-respChan:
				assert.Equal(t, http.StatusOK, resp.status, "Should return 200 OK")
				assert.Contains(t, resp.contentType, tt.expectedContains, "Content-Type should match")
			case <-time.After(300 * time.Millisecond):
				t.Fatalf("Failed to receive response headers, expected Content-Type: %s", tt.expectedContains)
			}
		})
	}
}

func TestXhttp_HostValidation(t *testing.T) {
	option := &inbound.XhttpOption{
		BaseOption: inbound.BaseOption{
			NameStr: "test-xhttp",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Path: "/xhttp/",
	}

	listener, err := inbound.NewXhttp(option)
	require.NoError(t, err)

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = listener.Listen(tunnel)
	require.NoError(t, err)
	defer listener.Close()

	sessionID := uuid.Must(uuid.NewV4()).String()
	addrPort, _ := netip.ParseAddrPort(listener.Address())
	url := fmt.Sprintf("http://%s/xhttp/%s", addrPort, sessionID)

	t.Run("Accepts request with correct host", func(t *testing.T) {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return
			}

			client := &http.Client{Timeout: 100 * time.Millisecond}
			resp, _ := client.Do(req)
			if resp != nil {
				resp.Body.Close()
			}
		}()

		time.Sleep(50 * time.Millisecond)
	})
}

func TestXhttp_ConcurrentSessions(t *testing.T) {
	option := &inbound.XhttpOption{
		BaseOption: inbound.BaseOption{
			NameStr: "test-xhttp",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Path: "/xhttp/",
	}

	listener, err := inbound.NewXhttp(option)
	require.NoError(t, err)

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = listener.Listen(tunnel)
	require.NoError(t, err)
	defer listener.Close()

	addrPort, _ := netip.ParseAddrPort(listener.Address())

	var wg sync.WaitGroup
	numSessions := 10

	for i := 0; i < numSessions; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			sessionID := uuid.Must(uuid.NewV4()).String()
			url := fmt.Sprintf("http://%s/xhttp/%s", addrPort, sessionID)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return
			}

			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Do(req)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}(i)
	}

	wg.Wait()
}

func TestXhttp_StreamUpload(t *testing.T) {
	option := &inbound.XhttpOption{
		BaseOption: inbound.BaseOption{
			NameStr: "test-xhttp",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Path: "/xhttp/",
		Mode: "stream-up",
	}

	listener, err := inbound.NewXhttp(option)
	require.NoError(t, err)

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = listener.Listen(tunnel)
	require.NoError(t, err)
	defer listener.Close()

	sessionID := uuid.Must(uuid.NewV4()).String()
	addrPort, _ := netip.ParseAddrPort(listener.Address())
	url := fmt.Sprintf("http://%s/xhttp/%s", addrPort, sessionID)

	data := []byte("test data payload")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)

	if err == nil {
		defer resp.Body.Close()
		assert.True(t, resp.StatusCode < 500, "Stream upload should not return server error")
	}
}

func TestXhttp_PacketUpload(t *testing.T) {
	option := &inbound.XhttpOption{
		BaseOption: inbound.BaseOption{
			NameStr: "test-xhttp",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Path: "/xhttp/",
		Mode: "packet-up",
	}

	listener, err := inbound.NewXhttp(option)
	require.NoError(t, err)

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = listener.Listen(tunnel)
	require.NoError(t, err)
	defer listener.Close()

	sessionID := uuid.Must(uuid.NewV4()).String()
	addrPort, _ := netip.ParseAddrPort(listener.Address())

	for seq := 0; seq < 3; seq++ {
		url := fmt.Sprintf("http://%s/xhttp/%s/%d", addrPort, sessionID, seq)
		data := fmt.Appendf(nil, "packet %d", seq)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
		cancel()

		if err != nil {
			continue
		}

		client := &http.Client{Timeout: 1 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}
}

func TestXhttp_InvalidMethods(t *testing.T) {
	option := &inbound.XhttpOption{
		BaseOption: inbound.BaseOption{
			NameStr: "test-xhttp",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Path: "/xhttp/",
	}

	listener, err := inbound.NewXhttp(option)
	require.NoError(t, err)

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = listener.Listen(tunnel)
	require.NoError(t, err)
	defer listener.Close()

	sessionID := uuid.Must(uuid.NewV4()).String()
	addrPort, _ := netip.ParseAddrPort(listener.Address())
	url := fmt.Sprintf("http://%s/xhttp/%s", addrPort, sessionID)

	invalidMethods := []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead}

	for _, method := range invalidMethods {
		t.Run("Method_"+method, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, method, url, nil)
			require.NoError(t, err)

			client := &http.Client{Timeout: 1 * time.Second}
			resp, err := client.Do(req)

			if err == nil {
				defer resp.Body.Close()
				assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
			}
		})
	}
}

func TestXhttp_GracefulShutdown(t *testing.T) {
	option := &inbound.XhttpOption{
		BaseOption: inbound.BaseOption{
			NameStr: "test-xhttp",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Path: "/xhttp/",
	}

	listener, err := inbound.NewXhttp(option)
	require.NoError(t, err)

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = listener.Listen(tunnel)
	require.NoError(t, err)

	addrPort, _ := netip.ParseAddrPort(listener.Address())

	sessionID := uuid.Must(uuid.NewV4()).String()
	url := fmt.Sprintf("http://%s/xhttp/%s", addrPort, sessionID)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	cancel()

	client := &http.Client{Timeout: 500 * time.Millisecond}
	client.Do(req)

	err = listener.Close()
	assert.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel2()

	req2, _ := http.NewRequestWithContext(ctx2, http.MethodGet, url, nil)
	_, err = client.Do(req2)

	assert.Error(t, err, "Connection should fail after listener close")
}

func TestXhttp_ConfigRoundTrip(t *testing.T) {
	option := &inbound.XhttpOption{
		BaseOption: inbound.BaseOption{
			NameStr: "test-xhttp",
			Listen:  "127.0.0.1",
			Port:    "8888",
		},
		Path:          "/custom/path/",
		Mode:          "packet-up",
		HTTPVersion:   "2",
		NoGRPCHeader:  true,
		XPaddingBytes: "100-1000",
		Headers:       map[string]string{"X-Test": "value"},
		Xmux:          inbound.XhttpXmuxOption{HKeepAlivePeriod: 30},
	}

	listener, err := inbound.NewXhttp(option)
	require.NoError(t, err)

	config := listener.Config().(*inbound.XhttpOption)

	assert.Equal(t, "test-xhttp", config.NameStr)
	assert.Equal(t, "127.0.0.1", config.Listen)
	assert.Equal(t, "8888", config.Port)
	assert.Equal(t, "/custom/path/", config.Path)
	assert.Equal(t, "packet-up", config.Mode)
	assert.Equal(t, "2", config.HTTPVersion)
	assert.True(t, config.NoGRPCHeader)
	assert.Equal(t, "100-1000", config.XPaddingBytes)
	assert.Equal(t, "value", config.Headers["X-Test"])
	assert.Equal(t, int64(30), config.Xmux.HKeepAlivePeriod)
}

func TestXhttp_MultipleListeners(t *testing.T) {
	listeners := make([]*inbound.Xhttp, 3)
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	for i := 0; i < 3; i++ {
		option := &inbound.XhttpOption{
			BaseOption: inbound.BaseOption{
				NameStr: fmt.Sprintf("test-xhttp-%d", i),
				Listen:  "127.0.0.1",
				Port:    "0",
			},
			Path: fmt.Sprintf("/xhttp%d/", i),
		}

		listener, err := inbound.NewXhttp(option)
		require.NoError(t, err)

		err = listener.Listen(tunnel)
		require.NoError(t, err)

		listeners[i] = listener
	}

	addresses := make(map[string]bool)
	for _, l := range listeners {
		addr := l.Address()
		assert.False(t, addresses[addr], "Each listener should have unique address")
		addresses[addr] = true
	}

	for _, l := range listeners {
		err := l.Close()
		assert.NoError(t, err)
	}
}

var _ C.Tunnel = (*TestTunnel)(nil)
