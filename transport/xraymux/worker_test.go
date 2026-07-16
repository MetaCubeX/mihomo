package xraymux

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testCarrier struct {
	reader       *io.PipeReader
	serverWriter *io.PipeWriter
	writesMu     sync.Mutex
	writes       bytes.Buffer
	activeWrites atomic.Int32
	interleaved  atomic.Bool
	writeErrMu   sync.Mutex
	writeErr     error
	closeOnce    sync.Once
	closed       atomic.Bool
}

func newTestCarrier() *testCarrier {
	r, w := io.Pipe()
	return &testCarrier{reader: r, serverWriter: w}
}

func (c *testCarrier) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *testCarrier) Write(p []byte) (int, error) {
	if c.activeWrites.Add(1) != 1 {
		c.interleaved.Store(true)
	}
	defer c.activeWrites.Add(-1)
	time.Sleep(time.Millisecond)
	c.writeErrMu.Lock()
	err := c.writeErr
	c.writeErrMu.Unlock()
	if err != nil {
		return 0, err
	}
	c.writesMu.Lock()
	defer c.writesMu.Unlock()
	return c.writes.Write(p)
}

func (c *testCarrier) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		_ = c.reader.Close()
		_ = c.serverWriter.Close()
	})
	return nil
}

func (c *testCarrier) LocalAddr() net.Addr              { return muxAddr("carrier-local") }
func (c *testCarrier) RemoteAddr() net.Addr             { return muxAddr("carrier-remote") }
func (c *testCarrier) SetDeadline(time.Time) error      { return nil }
func (c *testCarrier) SetReadDeadline(time.Time) error  { return nil }
func (c *testCarrier) SetWriteDeadline(time.Time) error { return nil }

func (c *testCarrier) setWriteError(err error) {
	c.writeErrMu.Lock()
	c.writeErr = err
	c.writeErrMu.Unlock()
}

func (c *testCarrier) bytes() []byte {
	c.writesMu.Lock()
	defer c.writesMu.Unlock()
	return append([]byte(nil), c.writes.Bytes()...)
}

func (c *testCarrier) isClosed() bool {
	return c.closed.Load()
}

func (c *testCarrier) inject(t *testing.T, frame Frame) {
	t.Helper()
	raw, err := EncodeFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.serverWriter.Write(raw); err != nil {
		t.Fatal(err)
	}
}

func TestCarrierWorkerSerializesConcurrentWriters(t *testing.T) {
	carrier := newTestCarrier()
	worker := newCarrierWorker(carrier, 64, 128, nil)
	t.Cleanup(func() { worker.close(nil) })

	var wg sync.WaitGroup
	for id := uint16(1); id <= 32; id++ {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()
			if err := worker.writeFrame(Frame{SessionID: id, Status: StatusEnd}); err != nil {
				t.Errorf("write frame %d: %v", id, err)
			}
		}(id)
	}
	wg.Wait()
	if carrier.interleaved.Load() {
		t.Fatal("carrier observed overlapping writes")
	}

	reader := bytes.NewReader(carrier.bytes())
	for i := 0; i < 32; i++ {
		if _, err := DecodeFrame(reader); err != nil {
			t.Fatalf("decode serialized frames: %v", err)
		}
	}
}

func TestCarrierWorkerDemultiplexesResponses(t *testing.T) {
	carrier := newTestCarrier()
	worker := newCarrierWorker(carrier, 8, 128, nil)
	t.Cleanup(func() { worker.close(nil) })
	conn, err := worker.openSession(context.Background(), "echo.example", 443, time.Hour)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	carrier.inject(t, Frame{SessionID: 1, Status: StatusKeep, Option: OptionData, Payload: []byte("response")})
	got := make([]byte, len("response"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(got) != "response" {
		t.Fatalf("response = %q", got)
	}
}

func TestCarrierWorkerDemultiplexesStreamsAndPacketsOnOneCarrier(t *testing.T) {
	carrier := newTestCarrier()
	worker := newCarrierWorker(carrier, 8, 128, nil)
	t.Cleanup(func() { worker.close(nil) })
	stream, err := worker.openSession(context.Background(), "stream.example", 443, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := worker.openPacketSession(context.Background(), "packet.example", 53, [8]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close(); _ = packetConn.Close() })

	carrier.inject(t, Frame{SessionID: 1, Status: StatusKeep, Option: OptionData, Payload: []byte("stream")})
	carrier.inject(t, Frame{
		SessionID: 2, Status: StatusKeep, Option: OptionData, Network: NetworkUDP,
		Destination: "9.9.9.9", Port: 53, Payload: []byte("packet"),
	})

	streamPayload := make([]byte, len("stream"))
	if _, err := io.ReadFull(stream, streamPayload); err != nil {
		t.Fatal(err)
	}
	packetPayload := make([]byte, len("packet"))
	n, addr, err := packetConn.ReadFrom(packetPayload)
	if err != nil {
		t.Fatal(err)
	}
	if string(streamPayload) != "stream" || n != len(packetPayload) || string(packetPayload) != "packet" || addr.String() != "9.9.9.9:53" {
		t.Fatalf("responses = stream %q, packet (%d, %q, %v)", streamPayload, n, packetPayload, addr)
	}
}

func TestCarrierWorkerEndsUnknownSession(t *testing.T) {
	carrier := newTestCarrier()
	worker := newCarrierWorker(carrier, 8, 128, nil)
	t.Cleanup(func() { worker.close(nil) })

	carrier.inject(t, Frame{SessionID: 77, Status: StatusKeep, Option: OptionData, Payload: []byte("orphan")})
	deadline := time.Now().Add(time.Second)
	for len(carrier.bytes()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	frame, err := DecodeFrame(bytes.NewReader(carrier.bytes()))
	if err != nil {
		t.Fatalf("decode End: %v", err)
	}
	if frame.SessionID != 77 || frame.Status != StatusEnd {
		t.Fatalf("unknown-session response = %+v", frame)
	}
}

func TestCarrierWorkerClosesSessionsOnMalformedFrameAndEOF(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail func(*testCarrier)
	}{
		{name: "malformed", fail: func(c *testCarrier) { _, _ = c.serverWriter.Write([]byte{0, 3, 0, 1, 2}) }},
		{name: "EOF", fail: func(c *testCarrier) { _ = c.serverWriter.Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			carrier := newTestCarrier()
			worker := newCarrierWorker(carrier, 8, 128, nil)
			conn, err := worker.openSession(context.Background(), "failure.example", 80, time.Hour)
			if err != nil {
				t.Fatalf("open session: %v", err)
			}
			tc.fail(carrier)
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := conn.Read(make([]byte, 1)); err == nil {
				t.Fatal("logical session remained open")
			}
		})
	}
}

func TestCarrierWorkerPropagatesWriteFailure(t *testing.T) {
	carrierErr := errors.New("carrier write failed")
	carrier := newTestCarrier()
	worker := newCarrierWorker(carrier, 8, 128, nil)
	conn, err := worker.openSession(context.Background(), "failure.example", 80, time.Hour)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	carrier.setWriteError(carrierErr)
	_, _ = conn.Write([]byte("request"))
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err = conn.Read(make([]byte, 1))
	if !errors.Is(err, carrierErr) {
		t.Fatalf("read error = %v, want %v", err, carrierErr)
	}
}

func TestCarrierWorkerHandlesRemoteEndAndError(t *testing.T) {
	tests := []struct {
		name      string
		option    Option
		wantTyped bool
	}{
		{name: "remote end"},
		{name: "remote error", option: OptionError, wantTyped: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			carrier := newTestCarrier()
			worker := newCarrierWorker(carrier, 8, 128, nil)
			t.Cleanup(func() { worker.close(nil) })
			conn, err := worker.openSession(context.Background(), "remote.example", 80, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			carrier.inject(t, Frame{SessionID: 1, Status: StatusEnd, Option: tt.option})
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			_, err = conn.Read(make([]byte, 1))
			if err == nil {
				t.Fatal("read succeeded after remote close")
			}
			var protocolErr *ProtocolError
			if errors.As(err, &protocolErr) != tt.wantTyped {
				t.Fatalf("read error = %v, typed protocol error = %t", err, errors.As(err, &protocolErr))
			}
			waitFor(t, func() bool { return worker.activeSessions() == 0 })
		})
	}
}

func TestCarrierWorkerDeliversFinalPayloadBeforeRemoteEnd(t *testing.T) {
	carrier := newTestCarrier()
	worker := newCarrierWorker(carrier, 8, 128, nil)
	t.Cleanup(func() { worker.close(nil) })
	conn, err := worker.openSession(context.Background(), "final.example", 80, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	carrier.inject(t, Frame{SessionID: 1, Status: StatusEnd, Option: OptionData, Payload: []byte("final")})
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read final payload: %v", err)
	}
	if string(got) != "final" {
		t.Fatalf("final payload = %q", got)
	}
}
