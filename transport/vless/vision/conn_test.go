package vision

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/transport/vless/encryption"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

var testUUID = uuid.Must(uuid.FromString("b831381d-6324-4d53-ad4f-8cda48b30811"))

func testVisionConn(t *testing.T, framed, direct net.Conn) *Conn {
	t.Helper()
	// CommonConn is one of the supported outer transports. The fixture uses
	// its buffered-input layout without performing an encryption handshake.
	conn, err := NewConn(framed, encryption.NewCommonConn(direct, false), testUUID)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func testPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	deadline := time.Now().Add(10 * time.Second)
	require.NoError(t, a.SetDeadline(deadline))
	require.NoError(t, b.SetDeadline(deadline))
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func waitResult(t *testing.T, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("I/O did not complete")
	}
}

func observeConn(conn *Conn, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	for {
		select {
		case <-stop:
			return
		default:
			conn.FrontHeadroom()
			conn.RearHeadroom()
			conn.NeedHandshake()
			conn.Upstream()
			conn.ReaderPossiblyReplaceable()
			conn.ReaderReplaceable()
			conn.WriterPossiblyReplaceable()
			conn.WriterReplaceable()
			N.CalculateFrontHeadroom(conn)
			N.CalculateRearHeadroom(conn)
			runtime.Gosched()
		}
	}
}

func TestConnDuplexMetadata(t *testing.T) {
	a, b := testPipe(t)
	left := testVisionConn(t, a, a)
	right := testVisionConn(t, b, b)
	stop := make(chan struct{})
	for _, conn := range []*Conn{left, right} {
		done := make(chan struct{})
		go observeConn(conn, stop, done)
		t.Cleanup(func() { <-done })
	}
	t.Cleanup(func() { close(stop) })
	const count = 32
	results := make(chan error, 4)
	payload := func(i int, marker byte) []byte { return bytes.Repeat([]byte{marker}, 1000+i*997) }
	for _, direction := range []struct {
		writer, reader *Conn
		marker         byte
	}{{left, right, 0x41}, {right, left, 0x42}} {
		direction := direction
		go func() {
			for i := 0; i < count; i++ {
				data := payload(i, direction.marker)
				if n, err := direction.writer.Write(data); err != nil {
					results <- err
					return
				} else if n != len(data) {
					results <- io.ErrShortWrite
					return
				}
			}
			results <- nil
		}()
		go func() {
			for i := 0; i < count; i++ {
				want := payload(i, direction.marker)
				got := make([]byte, len(want))
				if _, err := io.ReadFull(direction.reader, got); err != nil {
					results <- err
					return
				}
				if !bytes.Equal(want, got) {
					results <- fmt.Errorf("payload %d was corrupted", i)
					return
				}
			}
			results <- nil
		}()
	}
	for i := 0; i < 4; i++ {
		waitResult(t, results)
	}
	require.False(t, left.NeedHandshake())
	require.False(t, right.NeedHandshake())
}

func TestConnConcurrentReadersWriters(t *testing.T) {
	a, b := testPipe(t)
	writer := testVisionConn(t, a, a)
	reader := testVisionConn(t, b, b)
	const workers, count, size = 4, 32, 64
	results := make(chan error, 2*workers)
	var seenMu sync.Mutex
	seen := make(map[uint32]bool)
	for worker := 0; worker < workers; worker++ {
		worker := worker
		go func() {
			for i := 0; i < count; i++ {
				data := bytes.Repeat([]byte{0x41}, size)
				binary.BigEndian.PutUint32(data, uint32(worker*count+i))
				if _, err := writer.Write(data); err != nil {
					results <- err
					return
				}
			}
			results <- nil
		}()
		go func() {
			for i := 0; i < count; i++ {
				data := make([]byte, size)
				if _, err := io.ReadFull(reader, data); err != nil {
					results <- err
					return
				}
				id := binary.BigEndian.Uint32(data)
				seenMu.Lock()
				duplicate := seen[id]
				seen[id] = true
				seenMu.Unlock()
				if duplicate || id >= workers*count || !bytes.Equal(data[4:], bytes.Repeat([]byte{0x41}, size-4)) {
					results <- fmt.Errorf("interleaved or duplicate message %d", id)
					return
				}
			}
			results <- nil
		}()
	}
	for i := 0; i < 2*workers; i++ {
		waitResult(t, results)
	}
	require.Len(t, seen, workers*count)
}

func visionFrame(command byte, payload []byte) []byte {
	frame := make([]byte, PaddingHeaderLen+len(payload))
	copy(frame, testUUID.Bytes())
	frame[16] = command
	binary.BigEndian.PutUint16(frame[17:], uint16(len(payload)))
	copy(frame[PaddingHeaderLen:], payload)
	return frame
}

func TestConnDirectReadDrainsBuffers(t *testing.T) {
	framed, framedPeer := testPipe(t)
	direct, directPeer := testPipe(t)
	conn := testVisionConn(t, framed, direct)
	conn.input.Reset([]byte("input"))
	_, _ = conn.rawInput.WriteString("raw")
	results := make(chan error, 2)
	go func() { _, err := framedPeer.Write(visionFrame(commandPaddingDirect, []byte("frame"))); results <- err }()
	go func() { _, err := directPeer.Write([]byte("direct")); results <- err }()
	for i, want := range []byte("frameinputraw") {
		require.False(t, conn.ReaderReplaceable(), "buffered byte %d must still pass through Vision", i)
		var data [1]byte
		_, err := io.ReadFull(conn, data[:])
		require.NoError(t, err)
		require.Equal(t, want, data[0])
	}
	require.True(t, conn.ReaderReplaceable())
	require.False(t, conn.WriterReplaceable())
	require.Same(t, direct, N.UnwrapReader(conn))
	require.Same(t, conn, N.UnwrapWriter(conn))
	data := make([]byte, len("direct"))
	_, err := io.ReadFull(conn, data)
	require.NoError(t, err)
	require.Equal(t, "direct", string(data))
	for i := 0; i < 2; i++ {
		waitResult(t, results)
	}
}

func TestConnEmptyWriteHandshake(t *testing.T) {
	a, _ := testPipe(t)
	framed := &recordingConn{Conn: a}
	conn := testVisionConn(t, framed, a)
	require.True(t, conn.NeedHandshake())
	n, err := conn.Write(nil)
	require.NoError(t, err)
	require.Zero(t, n)
	require.False(t, conn.NeedHandshake())
	first := bytes.Clone(framed.written.Bytes())
	require.Equal(t, testUUID.Bytes(), first[:16])
	require.Zero(t, binary.BigEndian.Uint16(first[17:]))
	require.Len(t, first, PaddingHeaderLen+int(binary.BigEndian.Uint16(first[19:])))
	_, err = conn.Write([]byte("second"))
	require.NoError(t, err)
	second := framed.written.Bytes()[len(first):]
	require.Equal(t, commandPaddingContinue, second[0])
	require.EqualValues(t, len("second"), binary.BigEndian.Uint16(second[1:]))
	require.Equal(t, "second", string(second[5:5+len("second")]))
}

func TestConnCloseDuringBufferedDirectRead(t *testing.T) {
	left, right := testPipe(t)
	direct := &signaledConn{Conn: left, writeStarted: make(chan struct{})}
	framed := &recordingConn{Conn: direct}
	conn := testVisionConn(t, framed, direct)
	written := make(chan error, 1)
	go func() {
		_, err := right.Write(visionFrame(commandPaddingDirect, []byte("pending")))
		written <- err
	}()
	var first [1]byte
	_, err := io.ReadFull(conn, first[:])
	require.NoError(t, err)
	require.Equal(t, byte('p'), first[0])
	require.False(t, conn.ReaderReplaceable(), "payload still needs to be drained")
	require.NoError(t, conn.Close())
	require.EqualValues(t, 1, direct.closes.Load())
	require.Zero(t, framed.closes.Load(), "peer already requested direct mode; do not send close_notify")
	waitResult(t, written)
}

type recordingConn struct {
	net.Conn
	written bytes.Buffer // only accessed after the writing goroutine completes
	closes  atomic.Int32
}

func (c *recordingConn) Write(p []byte) (int, error) { return c.written.Write(p) }
func (c *recordingConn) Close() error                { c.closes.Add(1); return c.Conn.Close() }

type signaledConn struct {
	net.Conn
	writeStarted chan struct{}
	once         sync.Once
	closes       atomic.Int32
}

func (c *signaledConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.writeStarted) })
	return c.Conn.Write(p)
}
func (c *signaledConn) Close() error { c.closes.Add(1); return c.Conn.Close() }

func enableDirect(t *testing.T, conn *Conn) {
	t.Helper()
	// A TLS 1.3 ServerHello with a 32-byte session ID and AES-128-GCM.
	hello := make([]byte, 87)
	copy(hello, []byte{22, 3, 3, 0, 82, 2, 0, 0, 78, 3, 3})
	hello[43] = 32
	binary.BigEndian.PutUint16(hello[76:], 0x1301)
	binary.BigEndian.PutUint16(hello[79:], 6)
	copy(hello[81:], tls13SupportedVersions)
	conn.FilterTLS(hello)
}

func TestConnDirectWritePublishesAfterFlush(t *testing.T) {
	a, b := testPipe(t)
	direct := &signaledConn{Conn: a, writeStarted: make(chan struct{})}
	framed := &recordingConn{Conn: direct}
	conn := testVisionConn(t, framed, direct)
	enableDirect(t, conn)
	data := bytes.Repeat([]byte{0x41}, 3*xrayBufSize)
	copy(data, tlsApplicationDataStart)
	result := make(chan error, 1)
	go func() { _, err := conn.Write(data); result <- err }()
	select {
	case <-direct.writeStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not switch to direct transport")
	}
	// The control frame was written, but this Write still has raw chunks to
	// flush. An unwrapped writer must not overtake those chunks.
	require.False(t, conn.WriterReplaceable())
	require.Same(t, conn, N.UnwrapWriter(conn))
	// A blocked write must not prevent a simultaneous read from completing.
	readResult := make(chan error, 1)
	go func() { _, err := b.Write(visionFrame(commandPaddingContinue, []byte("duplex"))); readResult <- err }()
	readData := make([]byte, len("duplex"))
	_, err := io.ReadFull(conn, readData)
	require.NoError(t, err)
	require.Equal(t, "duplex", string(readData))
	waitResult(t, readResult)
	remaining := make([]byte, len(data)-xrayBufSize/2)
	_, err = io.ReadFull(b, remaining)
	require.NoError(t, err)
	waitResult(t, result)
	require.True(t, conn.WriterReplaceable())
	require.False(t, conn.ReaderReplaceable())
	require.Same(t, direct, N.UnwrapWriter(conn))
	frame := framed.written.Bytes()
	require.Equal(t, commandPaddingDirect, frame[16])
	length := int(binary.BigEndian.Uint16(frame[17:]))
	require.Equal(t, data, append(bytes.Clone(frame[PaddingHeaderLen:PaddingHeaderLen+length]), remaining...))
}

func TestConnCloseUnblocksIO(t *testing.T) {
	for _, directMode := range []bool{false, true} {
		name := "stream"
		if directMode {
			name = "direct transition"
		}
		t.Run(name, func(t *testing.T) {
			a, _ := testPipe(t)
			direct := &signaledConn{Conn: a, writeStarted: make(chan struct{})}
			framed := &recordingConn{Conn: direct}
			var carrier net.Conn = direct
			if directMode {
				carrier = framed
			}
			conn := testVisionConn(t, carrier, direct)
			if directMode {
				enableDirect(t, conn)
			}
			data := bytes.Repeat([]byte{0x41}, 3*xrayBufSize)
			if directMode {
				copy(data, tlsApplicationDataStart)
			}
			writes, reads := make(chan error, 1), make(chan error, 1)
			go func() { _, err := conn.Write(data); writes <- err }()
			go func() { _, err := conn.Read(make([]byte, 1)); reads <- err }()
			select {
			case <-direct.writeStarted:
			case <-time.After(5 * time.Second):
				t.Fatal("write did not start")
			}
			closed := make(chan error, 1)
			go func() { closed <- conn.Close() }()
			waitResult(t, closed)
			for _, result := range []<-chan error{writes, reads} {
				select {
				case err := <-result:
					require.Error(t, err)
				case <-time.After(5 * time.Second):
					t.Fatal("Close left I/O blocked")
				}
			}
			require.NoError(t, conn.Close())
			require.EqualValues(t, 1, direct.closes.Load())
			require.Zero(t, framed.closes.Load(), "direct shutdown must bypass the TLS wrapper")
		})
	}
}
