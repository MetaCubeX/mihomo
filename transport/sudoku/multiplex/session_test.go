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

func TestSessionMixedFrameSizesKeepStreamOrder(t *testing.T) {
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

	// Small writes are batched, large ones are written directly behind the batch; each
	// stream must still see its own bytes in order.
	const streams = 6
	sizes := []int{1, 700, coalesceMaxPayload + 1, 40, maxDataPayload + 5, 3, coalesceMaxPayload, 9000}
	expected := func(marker byte) []byte {
		var out []byte
		for i := 0; i < 20; i++ {
			out = append(out, bytes.Repeat([]byte{marker + byte(i)}, sizes[i%len(sizes)])...)
		}
		return out
	}

	type result struct {
		marker byte
		data   []byte
		err    error
	}
	results := make(chan result, streams)
	go func() {
		for i := 0; i < streams; i++ {
			st, _, err := serverSession.AcceptStream()
			if err != nil {
				results <- result{err: err}
				continue
			}
			go func() {
				data, err := io.ReadAll(st)
				r := result{data: data, err: err}
				if len(data) > 0 {
					r.marker = data[0]
				}
				results <- r
			}()
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		st, err := clientSession.OpenStream(nil)
		if err != nil {
			t.Fatalf("open stream: %v", err)
		}
		wg.Add(1)
		go func(st net.Conn, marker byte) {
			defer wg.Done()
			offset := 0
			data := expected(marker)
			for i := 0; offset < len(data); i++ {
				n := sizes[i%len(sizes)]
				if _, err := st.Write(data[offset : offset+n]); err != nil {
					t.Errorf("write: %v", err)
					return
				}
				offset += n
			}
			_ = st.(interface{ CloseWrite() error }).CloseWrite()
		}(st, byte(i*40))
	}
	wg.Wait()

	for i := 0; i < streams; i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("read stream: %v", r.err)
		}
		if !bytes.Equal(r.data, expected(r.marker)) {
			t.Fatalf("stream with marker %d received reordered or corrupted data", r.marker)
		}
	}
}

func TestSessionAnswersPingWithPong(t *testing.T) {
	sessionConn, peerConn := net.Pipe()
	session, err := NewServerSession(sessionConn)
	if err != nil {
		t.Fatalf("new server session: %v", err)
	}
	t.Cleanup(func() {
		_ = session.Close()
		_ = peerConn.Close()
	})
	_ = peerConn.SetDeadline(time.Now().Add(2 * time.Second))

	var ping [headerSize]byte
	ping[0] = framePing
	if _, err := peerConn.Write(ping[:]); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	var pong [headerSize]byte
	if _, err := io.ReadFull(peerConn, pong[:]); err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if pong[0] != framePong || binary.BigEndian.Uint32(pong[1:5]) != 0 || binary.BigEndian.Uint32(pong[5:9]) != 0 {
		t.Fatalf("reply = %v, want an empty PONG on stream 0", pong)
	}
	if session.IsClosed() {
		t.Fatal("session closed by ping")
	}
}
