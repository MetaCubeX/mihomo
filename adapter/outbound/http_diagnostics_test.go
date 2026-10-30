package outbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/tls"
)

func diagnosticHTTP(t *testing.T) *Http {
	t.Helper()
	h, err := NewHttp(HttpOption{Name: "local", Server: "127.0.0.1", Port: 3128, UserName: "test-user", Password: "test-secret"})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHTTPDiagnosticsConnectDeadline(t *testing.T) {
	h := diagnosticHTTP(t)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		reader := bufio.NewReader(server)
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				return
			}
		}
	}()
	_, err := h.StreamConnContext(ctx, client, &C.Metadata{Host: "example.invalid", DstPort: 443})
	<-readDone
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost context deadline: %v", err)
	}
	for _, field := range []string{"stage=http-connect", "proxy=127.0.0.1:3128", "peer=pipe", "stage_elapsed=", "remaining_at_start="} {
		if !strings.Contains(err.Error(), field) {
			t.Fatalf("missing %s: %v", field, err)
		}
	}
}

func TestHTTPDiagnosticsProxyDialCanceled(t *testing.T) {
	h := diagnosticHTTP(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := h.DialContext(ctx, &C.Metadata{Host: "example.invalid", DstPort: 443})
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "stage=proxy-dial") {
		t.Fatalf("expected proxy dial cancellation: %v", err)
	}
}

func TestHTTPDiagnosticsTLSCanceled(t *testing.T) {
	h := diagnosticHTTP(t)
	h.tlsConfig = &tls.Config{ServerName: "example.invalid"}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := h.StreamConnContext(ctx, client, &C.Metadata{Host: "example.invalid", DstPort: 443})
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "stage=proxy-tls") {
		t.Fatalf("expected TLS cancellation: %v", err)
	}
}

func TestHTTPDiagnosticsStatusPrivacy(t *testing.T) {
	for _, status := range []int{407, 405, 503, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			h := diagnosticHTTP(t)
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				reader := bufio.NewReader(server)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				_, _ = fmt.Fprintf(server, "HTTP/1.1 %d test-secret-remote-reason\r\nContent-Length: 0\r\n\r\n", status)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := h.StreamConnContext(ctx, client, &C.Metadata{Host: "example.invalid", DstPort: 443})
			<-done
			if err == nil || !strings.Contains(err.Error(), fmt.Sprint(status)) || !strings.Contains(err.Error(), "stage=http-connect") {
				t.Fatalf("missing rejection status: %v", err)
			}
			for _, secret := range []string{"test-secret", "test-user", "Proxy-Authorization", "remote-reason"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("leaked sensitive data: %v", err)
				}
			}
		})
	}
}

func TestHTTPDiagnosticsRemaining(t *testing.T) {
	if got := httpProxyRemaining(context.Background()); got != "none" {
		t.Fatalf("no deadline: %s", got)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if got := httpProxyRemaining(ctx); got != "0s" {
		t.Fatalf("expired deadline: %s", got)
	}
}

func TestHTTPDiagnosticsMalformedResponse(t *testing.T) {
	h := diagnosticHTTP(t)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader := bufio.NewReader(server)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = fmt.Fprint(server, "PRIVATE_REMOTE_STATUS_LINE\r\n\r\n")
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := h.StreamConnContext(ctx, client, &C.Metadata{Host: "example.invalid", DstPort: 443})
	<-done
	var responseErr *httpProxyResponseError
	if !errors.As(err, &responseErr) || errors.Unwrap(responseErr) == nil {
		t.Fatalf("missing wrapped parser cause: %v", err)
	}
	if strings.Contains(err.Error(), "PRIVATE_REMOTE_STATUS_LINE") || !strings.Contains(err.Error(), "stage=http-connect") {
		t.Fatalf("unsafe or missing stage diagnostic: %v", err)
	}
	cause := errors.New("synthetic cause")
	if !errors.Is(&httpProxyResponseError{cause: cause}, cause) {
		t.Fatal("lost error identity")
	}
}
