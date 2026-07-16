package xraymux

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type independentFrame struct {
	sessionID uint16
	status    byte
	option    byte
	payload   []byte
}

func readIndependentFrame(reader io.Reader) (independentFrame, error) {
	var lengthBytes [2]byte
	if _, err := io.ReadFull(reader, lengthBytes[:]); err != nil {
		return independentFrame{}, err
	}
	metadataLength := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if metadataLength < 4 || metadataLength > 512 {
		return independentFrame{}, fmt.Errorf("invalid metadata length %d", metadataLength)
	}
	metadata := make([]byte, metadataLength)
	if _, err := io.ReadFull(reader, metadata); err != nil {
		return independentFrame{}, err
	}
	frame := independentFrame{
		sessionID: binary.BigEndian.Uint16(metadata[:2]),
		status:    metadata[2],
		option:    metadata[3],
	}
	if frame.option&1 != 0 {
		if _, err := io.ReadFull(reader, lengthBytes[:]); err != nil {
			return independentFrame{}, err
		}
		frame.payload = make([]byte, int(binary.BigEndian.Uint16(lengthBytes[:])))
		if _, err := io.ReadFull(reader, frame.payload); err != nil {
			return independentFrame{}, err
		}
	}
	return frame, nil
}

func writeIndependentKeep(writer io.Writer, sessionID uint16, payload []byte) error {
	raw := make([]byte, 0, 8+len(payload))
	raw = binary.BigEndian.AppendUint16(raw, 4)
	raw = binary.BigEndian.AppendUint16(raw, sessionID)
	raw = append(raw, 2, 1)
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(payload)))
	raw = append(raw, payload...)
	_, err := writer.Write(raw)
	return err
}

func serveIndependentEcho(carrier net.Conn) {
	defer carrier.Close()
	for {
		frame, err := readIndependentFrame(carrier)
		if err != nil {
			return
		}
		if frame.status == 3 || frame.option&1 == 0 {
			continue
		}
		if err := writeIndependentKeep(carrier, frame.sessionID, frame.payload); err != nil {
			return
		}
	}
}

func TestPoolInteroperatesWithIndependentXrayCompatibleEchoServer(t *testing.T) {
	var carrierDials atomic.Int32
	pool := NewPool(func(context.Context) (net.Conn, error) {
		carrierDials.Add(1)
		client, server := net.Pipe()
		go serveIndependentEcho(server)
		return client, nil
	}, Options{
		MaxConcurrency:      16,
		MaxConnections:      128,
		FirstPayloadTimeout: time.Hour,
		IdleTimeout:         time.Hour,
	})
	t.Cleanup(func() { _ = pool.Close() })

	const streamCount = 12
	connections := make([]net.Conn, 0, streamCount)
	for index := 0; index < streamCount; index++ {
		conn, err := pool.DialContext(context.Background(), fmt.Sprintf("echo-%d.example", index), uint16(8000+index))
		if err != nil {
			t.Fatalf("dial stream %d: %v", index, err)
		}
		connections = append(connections, conn)
	}

	var wg sync.WaitGroup
	for index, conn := range connections {
		wg.Add(1)
		go func(index int, conn net.Conn) {
			defer wg.Done()
			defer conn.Close()
			request := []byte(fmt.Sprintf("stream-%d", index))
			if _, err := conn.Write(request); err != nil {
				t.Errorf("write stream %d: %v", index, err)
				return
			}
			response := make([]byte, len(request))
			if _, err := io.ReadFull(conn, response); err != nil {
				t.Errorf("read stream %d: %v", index, err)
				return
			}
			if string(response) != string(request) {
				t.Errorf("stream %d response = %q, want %q", index, response, request)
			}
		}(index, conn)
	}
	wg.Wait()
	if got := carrierDials.Load(); got != 1 {
		t.Fatalf("carrier dials = %d, want 1", got)
	}
}

func TestPoolConcurrentStreamStress(t *testing.T) {
	var carrierDials atomic.Int32
	pool := NewPool(func(context.Context) (net.Conn, error) {
		carrierDials.Add(1)
		client, server := net.Pipe()
		go serveIndependentEcho(server)
		return client, nil
	}, Options{
		MaxConcurrency:      4,
		MaxConnections:      64,
		FirstPayloadTimeout: time.Hour,
		IdleTimeout:         time.Hour,
	})
	t.Cleanup(func() { _ = pool.Close() })

	const streamCount = 40
	type stream struct {
		conn   net.Conn
		cancel context.CancelFunc
	}
	streams := make([]stream, 0, streamCount)
	for index := 0; index < streamCount; index++ {
		ctx, cancel := context.WithCancel(context.Background())
		conn, err := pool.DialContext(ctx, fmt.Sprintf("stress-%d.example", index), uint16(9000+index))
		if err != nil {
			t.Fatalf("dial stream %d: %v", index, err)
		}
		streams = append(streams, stream{conn: conn, cancel: cancel})
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for index, current := range streams {
		wg.Add(1)
		go func(index int, current stream) {
			defer wg.Done()
			<-start
			stopDeadlines := make(chan struct{})
			deadlinesDone := make(chan struct{})
			go func() {
				defer close(deadlinesDone)
				for {
					select {
					case <-stopDeadlines:
						return
					default:
						_ = current.conn.SetDeadline(time.Now().Add(time.Second))
						_ = current.conn.SetDeadline(time.Time{})
					}
				}
			}()

			request := []byte(fmt.Sprintf("stress-payload-%d", index))
			if _, err := current.conn.Write(request); err != nil {
				t.Errorf("write stream %d: %v", index, err)
			} else {
				response := make([]byte, len(request))
				if _, err := io.ReadFull(current.conn, response); err != nil {
					t.Errorf("read stream %d: %v", index, err)
				} else if string(response) != string(request) {
					t.Errorf("stream %d response = %q", index, response)
				}
			}
			if index%2 == 0 {
				current.cancel()
			} else {
				_ = current.conn.Close()
			}
			close(stopDeadlines)
			<-deadlinesDone
			current.cancel()
			_ = current.conn.Close()
		}(index, current)
	}
	close(start)
	wg.Wait()
	if got := carrierDials.Load(); got < 2 {
		t.Fatalf("carrier dials = %d, want several carriers", got)
	}
	waitFor(t, func() bool { return pool.activeSessions() == 0 })
}
