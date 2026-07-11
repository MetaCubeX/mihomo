package multiplex

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSessionKeepaliveUsesV047CompatibleFrame(t *testing.T) {
	sessionConn, peerConn := net.Pipe()
	session := &Session{
		conn:    sessionConn,
		streams: make(map[uint32]*stream),
		closed:  make(chan struct{}),
	}
	session.lastWrite.Store(time.Now().UnixNano())
	t.Cleanup(func() {
		session.closeWithError(net.ErrClosed)
		_ = peerConn.Close()
	})

	session.startKeepalive(10 * time.Millisecond)
	_ = peerConn.SetReadDeadline(time.Now().Add(time.Second))

	var header [headerSize]byte
	if _, err := io.ReadFull(peerConn, header[:]); err != nil {
		t.Fatalf("read keepalive: %v", err)
	}
	if header[0] != frameData {
		t.Fatalf("keepalive frame type = %d, want DATA", header[0])
	}
	if streamID := binary.BigEndian.Uint32(header[1:5]); streamID != 0 {
		t.Fatalf("keepalive stream id = %d, want 0", streamID)
	}
	if payloadLen := binary.BigEndian.Uint32(header[5:9]); payloadLen != 0 {
		t.Fatalf("keepalive payload length = %d, want 0", payloadLen)
	}
}

func TestSessionSlowStreamDoesNotBlockOtherStreams(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	clientSession, err := NewClientSession(clientConn)
	if err != nil {
		t.Fatalf("new client session: %v", err)
	}
	serverSession, err := NewServerSession(serverConn)
	if err != nil {
		t.Fatalf("new server session: %v", err)
	}
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	})

	slowConn, err := clientSession.OpenStream(nil)
	if err != nil {
		t.Fatalf("open slow stream: %v", err)
	}
	slowClient := slowConn.(*stream)
	if _, _, err := serverSession.AcceptStream(); err != nil {
		t.Fatalf("accept slow stream: %v", err)
	}

	payload := make([]byte, maxDataPayload)
	floodDone := make(chan struct{})
	go func() {
		defer close(floodDone)
		for queued := 0; queued <= maxQueuedBytesPerStream; queued += len(payload) {
			if _, err := slowClient.Write(payload); err != nil {
				return
			}
		}
	}()

	select {
	case <-floodDone:
	case <-time.After(time.Second):
		t.Fatal("failed to fill slow stream queue")
	}

	fastConn, err := clientSession.OpenStream(nil)
	if err != nil {
		t.Fatalf("open fast stream: %v", err)
	}
	fastDone := make(chan error, 1)
	go func() {
		_, err := fastConn.Write([]byte("still responsive"))
		fastDone <- err
	}()

	fastServer, _, err := serverSession.AcceptStream()
	if err != nil {
		t.Fatalf("slow stream blocked the entire mux session: %v", err)
	}
	buf := make([]byte, len("still responsive"))
	if _, err := io.ReadFull(fastServer, buf); err != nil {
		t.Fatalf("read fast stream: %v", err)
	}
	if string(buf) != "still responsive" {
		t.Fatalf("fast stream payload mismatch: %q", buf)
	}
	if err := <-fastDone; err != nil {
		t.Fatalf("write fast stream: %v", err)
	}
}

func TestStreamCloseWritePreservesResponse(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	clientSession, err := NewClientSession(clientConn)
	if err != nil {
		t.Fatalf("new client session: %v", err)
	}
	serverSession, err := NewServerSession(serverConn)
	if err != nil {
		t.Fatalf("new server session: %v", err)
	}
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	})

	serverDone := make(chan error, 1)
	go func() {
		conn, _, err := serverSession.AcceptStream()
		if err != nil {
			serverDone <- err
			return
		}
		request, err := io.ReadAll(conn)
		if err != nil {
			serverDone <- err
			return
		}
		if string(request) != "request" {
			serverDone <- errors.New("request payload mismatch")
			return
		}
		if _, err := conn.Write([]byte("response")); err != nil {
			serverDone <- err
			return
		}
		serverDone <- conn.(interface{ CloseWrite() error }).CloseWrite()
	}()

	clientStream, err := clientSession.OpenStream(nil)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := clientStream.Write([]byte("request")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := clientStream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatalf("close request side: %v", err)
	}

	response, err := io.ReadAll(clientStream)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(response) != "response" {
		t.Fatalf("response payload mismatch: %q", response)
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server stream: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not finish half-closed exchange")
	}
}

func TestStreamConcurrentWritesRemainContiguous(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	clientSession, err := NewClientSession(clientConn)
	if err != nil {
		t.Fatalf("new client session: %v", err)
	}
	serverSession, err := NewServerSession(serverConn)
	if err != nil {
		t.Fatalf("new server session: %v", err)
	}
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	})

	clientStream, err := clientSession.OpenStream(nil)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	serverStream, _, err := serverSession.AcceptStream()
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}

	const writers = 8
	payloadSize := maxDataPayload*2 + 17
	readDone := make(chan struct {
		payload []byte
		err     error
	}, 1)
	go func() {
		payload, err := io.ReadAll(serverStream)
		readDone <- struct {
			payload []byte
			err     error
		}{payload: payload, err: err}
	}()

	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(marker byte) {
			defer wg.Done()
			<-start
			payload := bytes.Repeat([]byte{marker}, payloadSize)
			n, err := clientStream.Write(payload)
			if err == nil && n != len(payload) {
				err = io.ErrShortWrite
			}
			errs <- err
		}(byte(i + 1))
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent write: %v", err)
		}
	}
	if err := clientStream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}

	result := <-readDone
	if result.err != nil {
		t.Fatalf("read stream: %v", result.err)
	}
	if len(result.payload) != writers*payloadSize {
		t.Fatalf("payload size = %d, want %d", len(result.payload), writers*payloadSize)
	}

	seen := make(map[byte]bool, writers)
	for offset := 0; offset < len(result.payload); offset += payloadSize {
		block := result.payload[offset : offset+payloadSize]
		marker := block[0]
		if marker == 0 || marker > writers {
			t.Fatalf("unexpected block marker %d at offset %d", marker, offset)
		}
		if seen[marker] {
			t.Fatalf("marker %d was split or duplicated", marker)
		}
		seen[marker] = true
		if !bytes.Equal(block, bytes.Repeat([]byte{marker}, payloadSize)) {
			t.Fatalf("write with marker %d was interleaved", marker)
		}
	}
}
