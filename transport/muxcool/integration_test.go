package muxcool

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
	network   byte
	host      string
	port      uint16
	globalID  [8]byte
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
	if frame.status == 1 || (frame.status == 2 && len(metadata) > 4) {
		if len(metadata) < 8 {
			return independentFrame{}, io.ErrUnexpectedEOF
		}
		frame.network = metadata[4]
		frame.port = binary.BigEndian.Uint16(metadata[5:7])
		host, consumed, err := readIndependentAddress(metadata[7:])
		if err != nil {
			return independentFrame{}, err
		}
		frame.host = host
		remaining := metadata[7+consumed:]
		if frame.status == 1 && frame.network == 2 && frame.option&1 != 0 {
			if len(remaining) != len(frame.globalID) {
				return independentFrame{}, fmt.Errorf("invalid GlobalID length %d", len(remaining))
			}
			copy(frame.globalID[:], remaining)
		} else if len(remaining) != 0 {
			return independentFrame{}, fmt.Errorf("unexpected trailing metadata %d", len(remaining))
		}
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

func readIndependentAddress(raw []byte) (string, int, error) {
	if len(raw) == 0 {
		return "", 0, io.ErrUnexpectedEOF
	}
	switch raw[0] {
	case 1:
		if len(raw) < 5 {
			return "", 0, io.ErrUnexpectedEOF
		}
		return net.IP(raw[1:5]).String(), 5, nil
	case 2:
		if len(raw) < 2 || len(raw) < 2+int(raw[1]) {
			return "", 0, io.ErrUnexpectedEOF
		}
		return string(raw[2 : 2+int(raw[1])]), 2 + int(raw[1]), nil
	case 3:
		if len(raw) < 17 {
			return "", 0, io.ErrUnexpectedEOF
		}
		return net.IP(raw[1:17]).String(), 17, nil
	default:
		return "", 0, fmt.Errorf("invalid address type %d", raw[0])
	}
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

func writeIndependentUDPKeep(writer io.Writer, frame independentFrame) error {
	metadata := make([]byte, 0, 32)
	metadata = binary.BigEndian.AppendUint16(metadata, frame.sessionID)
	metadata = append(metadata, 2, 1, 2)
	metadata = binary.BigEndian.AppendUint16(metadata, frame.port)
	if ip := net.ParseIP(frame.host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			metadata = append(metadata, 1)
			metadata = append(metadata, ip4...)
		} else {
			metadata = append(metadata, 3)
			metadata = append(metadata, ip.To16()...)
		}
	} else {
		metadata = append(metadata, 2, byte(len(frame.host)))
		metadata = append(metadata, frame.host...)
	}
	raw := make([]byte, 0, 4+len(metadata)+len(frame.payload))
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(metadata)))
	raw = append(raw, metadata...)
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(frame.payload)))
	raw = append(raw, frame.payload...)
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

func serveIndependentPacketEcho(carrier net.Conn, observed chan<- independentFrame) {
	defer carrier.Close()
	for {
		frame, err := readIndependentFrame(carrier)
		if err != nil {
			return
		}
		if frame.status == 3 || frame.option&1 == 0 {
			continue
		}
		if observed != nil {
			observed <- frame
		}
		if err := writeIndependentUDPKeep(carrier, frame); err != nil {
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

func TestPoolInteroperatesWithIndependentXrayCompatiblePacketServer(t *testing.T) {
	observed := make(chan independentFrame, 2)
	pool := NewPool(func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go serveIndependentPacketEcho(server, observed)
		return client, nil
	}, Options{MaxConcurrency: 8, MaxConnections: 128, IdleTimeout: time.Hour})
	t.Cleanup(func() { _ = pool.Close() })

	packetConn, err := pool.ListenPacketContext(context.Background(), "dns.example", 53, [8]byte{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })

	requests := []struct {
		payload string
		addr    *net.UDPAddr
		want    string
	}{
		{payload: "one", addr: &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}, want: "dns.example:53"},
		{payload: "second", addr: &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 853}, want: "1.1.1.1:853"},
	}
	for _, request := range requests {
		if _, err := packetConn.WriteTo([]byte(request.payload), request.addr); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 64)
		n, addr, err := packetConn.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if string(buffer[:n]) != request.payload || addr.String() != request.want {
			t.Fatalf("packet response = (%q, %v), want (%q, %s)", buffer[:n], addr, request.payload, request.want)
		}
	}
	first := <-observed
	second := <-observed
	if first.status != 1 || first.host != "dns.example" || second.status != 2 || second.host != "1.1.1.1" {
		t.Fatalf("observed frames = first %+v, second %+v", first, second)
	}
}

func TestPoolPreservesXUDPGlobalIDAcrossCarrierRebind(t *testing.T) {
	globalID := [8]byte{9, 8, 7, 6, 5, 4, 3, 2}
	observed := make(chan independentFrame, 2)
	var carrierDials atomic.Int32
	pool := NewPool(func(context.Context) (net.Conn, error) {
		carrierDials.Add(1)
		client, server := net.Pipe()
		go serveIndependentPacketEcho(server, observed)
		return client, nil
	}, Options{MaxConcurrency: 8, MaxConnections: 1, IdleTimeout: time.Hour})
	t.Cleanup(func() { _ = pool.Close() })

	for index := 0; index < 2; index++ {
		packetConn, err := pool.ListenPacketContext(context.Background(), "rebind.example", 443, globalID)
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte{byte('a' + index)}
		if _, err := packetConn.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 443}); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 1)
		if _, _, err := packetConn.ReadFrom(buffer); err != nil {
			t.Fatal(err)
		}
		if err := packetConn.Close(); err != nil {
			t.Fatal(err)
		}
		waitFor(t, func() bool { return pool.activeSessions() == 0 })
		waitFor(t, func() bool { return pool.workerCount() == 0 })
	}

	first := <-observed
	second := <-observed
	if first.globalID != globalID || second.globalID != globalID {
		t.Fatalf("rebind GlobalIDs = %v, %v", first.globalID, second.globalID)
	}
	if got := carrierDials.Load(); got != 2 {
		t.Fatalf("carrier dials = %d, want 2", got)
	}
}
