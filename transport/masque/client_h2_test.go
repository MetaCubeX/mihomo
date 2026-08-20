package masque

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/metacubex/quic-go/http3"
	"github.com/stretchr/testify/require"
)

func TestH2CapsuleStreamDrainsFinalDatagram(t *testing.T) {
	requestReader, requestWriter := io.Pipe()
	defer requestReader.Close()
	payload := []byte{0, 0x45, 0, 0, 0}
	response := io.NopCloser(bytes.NewReader(appendCapsule(nil, h2DatagramCapsuleType, payload)))
	stream := newH2CapsuleStream(requestWriter, response, func() {})

	select {
	case <-stream.done:
	case <-time.After(time.Second):
		t.Fatal("capsule reader did not reach EOF")
	}
	got, err := stream.ReceiveDatagram(context.Background())
	require.NoError(t, err)
	require.Equal(t, payload, got)
	_, err = stream.ReceiveDatagram(context.Background())
	require.Error(t, err)
}

func TestH2CapsuleStreamDemultiplexesControlCapsules(t *testing.T) {
	requestReader, requestWriter := io.Pipe()
	defer requestReader.Close()
	responseReader, responseWriter := io.Pipe()
	stream := newH2CapsuleStream(requestWriter, responseReader, func() {})
	defer stream.Close()

	datagram := []byte{0, 0x45, 1, 2, 3}
	controlPayload := []byte{0, 4, 192, 0, 2, 1, 32}
	go func() {
		_, _ = responseWriter.Write(appendCapsule(nil, h2DatagramCapsuleType, datagram))
		_, _ = responseWriter.Write(appendCapsule(nil, http3.CapsuleType(1), controlPayload))
		_ = responseWriter.Close()
	}()

	gotDatagram, err := stream.ReceiveDatagram(context.Background())
	require.NoError(t, err)
	require.Equal(t, datagram, gotDatagram)

	capsuleType, capsuleReader, err := http3.NewCapsuleParser(stream).Next()
	require.NoError(t, err)
	require.Equal(t, http3.CapsuleType(1), capsuleType)
	gotControl, err := io.ReadAll(capsuleReader)
	require.NoError(t, err)
	require.Equal(t, controlPayload, gotControl)
}

func TestH2CapsuleStreamEncodesDatagramCapsule(t *testing.T) {
	requestReader, requestWriter := io.Pipe()
	responseReader, responseWriter := io.Pipe()
	stream := newH2CapsuleStream(requestWriter, responseReader, func() {})
	defer func() {
		_ = stream.Close()
		_ = requestReader.Close()
		_ = responseWriter.Close()
	}()

	payload := []byte{0, 0x60, 1, 2, 3}
	errCh := make(chan error, 1)
	go func() { errCh <- stream.SendDatagram(payload) }()

	capsuleType, capsuleReader, err := http3.NewCapsuleParser(requestReader).Next()
	require.NoError(t, err)
	require.Equal(t, h2DatagramCapsuleType, capsuleType)
	got, err := io.ReadAll(capsuleReader)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	require.NoError(t, <-errCh)
}
