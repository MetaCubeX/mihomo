package xhttp

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const packetUpTestTimeout = 5 * time.Second

func TestPacketUpWriterDoesNotWaitForResponse(t *testing.T) {
	received := make(chan string, 2)
	releaseFirstResponse := make(chan struct{})
	defer func() {
		select {
		case <-releaseFirstResponse:
		default:
			close(releaseFirstResponse)
		}
	}()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seq := r.URL.Path[len(r.URL.Path)-1:]
		received <- seq
		if seq == "0" {
			<-releaseFirstResponse
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	config := Config{
		Host:             serverURL.Host,
		Path:             "/xhttp",
		UplinkHTTPMethod: http.MethodPost,
		XPaddingBytes:    "0",
	}
	writer := PacketUpWriter{
		ctx:       context.Background(),
		cfg:       &config,
		sessionID: "session",
		transport: server.Client().Transport,
	}

	firstWrite := make(chan error, 1)
	go func() {
		_, err := writer.write([]byte("first"))
		firstWrite <- err
	}()

	select {
	case err := <-firstWrite:
		require.NoError(t, err)
	case <-time.After(packetUpTestTimeout):
		t.Fatal("first packet upload waited for the response")
	}

	secondWrite := make(chan error, 1)
	go func() {
		_, err := writer.write([]byte("second"))
		secondWrite <- err
	}()

	select {
	case err := <-secondWrite:
		require.NoError(t, err)
	case <-time.After(packetUpTestTimeout):
		t.Fatal("second packet upload was blocked by the first response")
	}

	assert.Equal(t, "0", <-received)
	assert.Equal(t, "1", <-received)
	close(releaseFirstResponse)
}

func TestPacketUpWriterReportsAsynchronousResponseError(t *testing.T) {
	requestReceived := make(chan struct{})
	releaseResponse := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestReceived)
		<-releaseResponse
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	asyncError := make(chan error, 1)
	config := Config{
		Host:             serverURL.Host,
		Path:             "/xhttp",
		UplinkHTTPMethod: http.MethodPost,
		XPaddingBytes:    "0",
	}
	writer := PacketUpWriter{
		ctx:       ctx,
		cancel:    cancel,
		cfg:       &config,
		sessionID: "session",
		transport: server.Client().Transport,
		onError: func(err error) {
			asyncError <- err
		},
	}

	writeComplete := make(chan error, 1)
	go func() {
		_, err := writer.write([]byte("payload"))
		writeComplete <- err
	}()

	select {
	case <-requestReceived:
	case <-time.After(packetUpTestTimeout):
		t.Fatal("packet upload was not sent")
	}
	select {
	case err := <-writeComplete:
		require.NoError(t, err)
	case <-time.After(packetUpTestTimeout):
		t.Fatal("packet upload waited for the response")
	}

	close(releaseResponse)
	select {
	case err := <-asyncError:
		assert.ErrorContains(t, err, http.StatusText(http.StatusServiceUnavailable))
	case <-time.After(packetUpTestTimeout):
		t.Fatal("asynchronous response error was not reported")
	}
}
