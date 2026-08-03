package xhttp

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
	"github.com/stretchr/testify/require"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestPacketUpWriteReturnsAfterRequest(t *testing.T) {
	releaseResponse := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseResponse) })
	}
	t.Cleanup(release)

	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		httptrace.ContextClientTrace(req.Context()).WroteRequest(httptrace.WroteRequestInfo{})
		<-releaseResponse
		return &http.Response{
			Status:     "503 Service Unavailable",
			StatusCode: http.StatusServiceUnavailable,
			Body:       http.NoBody,
		}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := PacketUpWriter{
		ctx:       ctx,
		cancel:    cancel,
		cfg:       &Config{Host: "example.com"},
		transport: transport,
	}
	writer.writeCond.L = &writer.writeMu

	writeDone := make(chan error, 1)
	go func() {
		_, err := writer.write([]byte("payload"))
		writeDone <- err
	}()

	select {
	case err := <-writeDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("packet upload waited for the response")
	}

	release()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("response error was not reported")
	}
	writer.writeMu.Lock()
	err := writer.flushErr
	writer.writeMu.Unlock()
	require.ErrorContains(t, err, "503")
}
