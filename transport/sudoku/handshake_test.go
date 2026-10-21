package sudoku

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	sudokuobfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

func TestPackedConnRoundTrip_WithPadding(t *testing.T) {
	payload := []byte{0x3a, 0x1f, 0x71, 0x00, 0xff, 0x10, 0x22}
	tableTypes := []string{"prefer_ascii", "prefer_entropy"}

	for _, tt := range tableTypes {
		t.Run(tt, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			table := sudokuobfs.NewTable("roundtrip-seed", tt)
			writer := sudokuobfs.NewPackedConn(serverConn, table, 30, 80)
			reader := sudokuobfs.NewPackedConn(clientConn, table, 30, 80)

			writeErr := make(chan error, 1)
			go func() {
				if _, err := writer.Write(payload); err != nil {
					writeErr <- err
					return
				}
				if err := writer.Flush(); err != nil {
					writeErr <- err
					return
				}
				writeErr <- serverConn.Close()
			}()

			done := make(chan struct{})
			var got []byte
			var readErr error
			go func() {
				got, readErr = io.ReadAll(reader)
				close(done)
			}()

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("read timeout")
			}

			if err := <-writeErr; err != nil && err != io.EOF {
				t.Fatalf("write side error: %v", err)
			}
			if readErr != nil && readErr != io.EOF {
				t.Fatalf("read side error: %v", readErr)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload mismatch, want %x got %x", payload, got)
			}
		})
	}
}

// newSocketPair returns two connected loopback conns. The packed tests use it instead of net.Pipe: a pipe
// has no buffer, so a Write returns only once the peer has read every byte, including the padding byte that
// may close it. A decoder that already has the whole message never reads that byte, and a server that
// answers at that point leaves both ends blocked in Write.
func newSocketPair() (server, client net.Conn, err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			c = nil
		}
		accepted <- c
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	server = <-accepted
	if server == nil {
		_ = client.Close()
		return nil, nil, errors.New("accept loopback conn failed")
	}
	return server, client, nil
}

func newPackedConfig(table *sudokuobfs.Table) *ProtocolConfig {
	cfg := DefaultConfig()
	cfg.Key = "sudoku-test-key"
	cfg.Table = table
	cfg.PaddingMin = 10
	cfg.PaddingMax = 30
	cfg.EnablePureDownlink = false
	cfg.ServerAddress = "example.com:443"
	cfg.DisableHTTPMask = true
	return cfg
}

func TestPackedDownlinkSoak(t *testing.T) {
	const sessions = 16

	table := sudokuobfs.NewTable("soak-seed", "prefer_ascii")
	cfg := newPackedConfig(table)

	var wg sync.WaitGroup
	errCh := make(chan error, sessions*2)

	for i := 0; i < sessions; i++ {
		wg.Add(2)
		go func(id int) {
			defer wg.Done()
			runPackedTCPSession(id, cfg, errCh)
		}(i)
		go func(id int) {
			defer wg.Done()
			runPackedUoTSession(id, cfg, errCh)
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("soak test timeout")
	}

	close(errCh)
	for err := range errCh {
		t.Fatalf("soak error: %v", err)
	}
}

func runPackedTCPSession(id int, cfg *ProtocolConfig, errCh chan<- error) {
	serverConn, clientConn, err := newSocketPair()
	if err != nil {
		errCh <- err
		return
	}
	target := fmt.Sprintf("1.1.1.%d:80", (id%200)+1)
	payload := []byte{0x42, byte(id)}

	serverErr := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		c, meta, err := ServerHandshake(serverConn, cfg)
		if err != nil {
			serverErr <- fmt.Errorf("server handshake tcp: %w", err)
			return
		}
		defer c.Close()

		session, err := ReadServerSession(c, meta)
		if err != nil {
			serverErr <- fmt.Errorf("server read session tcp: %w", err)
			return
		}
		if session.Type != SessionTypeTCP {
			serverErr <- fmt.Errorf("unexpected session type: %v", session.Type)
			return
		}
		if session.Target != target {
			serverErr <- fmt.Errorf("target mismatch want %s got %s", target, session.Target)
			return
		}
		if _, err := session.Conn.Write(payload); err != nil {
			serverErr <- fmt.Errorf("server write: %w", err)
			return
		}
		serverErr <- nil
	}()

	clientCfg := *cfg
	cConn, err := ClientHandshake(clientConn, &clientCfg)
	if err != nil {
		errCh <- fmt.Errorf("client handshake tcp: %w", err)
		_ = clientConn.Close()
		return
	}
	defer cConn.Close()

	addrBuf, err := EncodeAddress(target)
	if err != nil {
		errCh <- fmt.Errorf("encode address: %w", err)
		return
	}
	if err := WriteKIPMessage(cConn, KIPTypeOpenTCP, addrBuf); err != nil {
		errCh <- fmt.Errorf("client send open tcp: %w", err)
		return
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(cConn, buf); err != nil {
		errCh <- fmt.Errorf("client read: %w", err)
		return
	}
	if !bytes.Equal(buf, payload) {
		errCh <- fmt.Errorf("payload mismatch want %x got %x", payload, buf)
		return
	}
	reportPackedServerErr(serverErr, errCh)
}

func runPackedUoTSession(id int, cfg *ProtocolConfig, errCh chan<- error) {
	serverConn, clientConn, err := newSocketPair()
	if err != nil {
		errCh <- err
		return
	}
	target := "8.8.8.8:53"
	payload := []byte{0xaa, byte(id)}

	serverErr := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		c, meta, err := ServerHandshake(serverConn, cfg)
		if err != nil {
			serverErr <- fmt.Errorf("server handshake uot: %w", err)
			return
		}
		defer c.Close()

		session, err := ReadServerSession(c, meta)
		if err != nil {
			serverErr <- fmt.Errorf("server read session uot: %w", err)
			return
		}
		if session.Type != SessionTypeUoT {
			serverErr <- fmt.Errorf("unexpected session type: %v", session.Type)
			return
		}
		if err := WriteDatagram(session.Conn, target, payload); err != nil {
			serverErr <- fmt.Errorf("server write datagram: %w", err)
			return
		}
		serverErr <- nil
	}()

	clientCfg := *cfg
	cConn, err := ClientHandshake(clientConn, &clientCfg)
	if err != nil {
		errCh <- fmt.Errorf("client handshake uot: %w", err)
		_ = clientConn.Close()
		return
	}
	defer cConn.Close()

	if err := WriteKIPMessage(cConn, KIPTypeStartUoT, nil); err != nil {
		errCh <- fmt.Errorf("client start uot: %w", err)
		return
	}

	addr, data, err := readTestDatagram(cConn)
	if err != nil {
		errCh <- fmt.Errorf("client read datagram: %w", err)
		return
	}
	if addr != target {
		errCh <- fmt.Errorf("uot target mismatch want %s got %s", target, addr)
		return
	}
	if !bytes.Equal(data, payload) {
		errCh <- fmt.Errorf("uot payload mismatch want %x got %x", payload, data)
		return
	}
	reportPackedServerErr(serverErr, errCh)
}

func reportPackedServerErr(serverErr <-chan error, errCh chan<- error) {
	select {
	case err := <-serverErr:
		if err != nil {
			errCh <- err
		}
	default:
	}
}

func TestCustomTableHandshake(t *testing.T) {
	table, err := sudokuobfs.NewTableWithCustom("custom-seed", "prefer_entropy", "xpxvvpvv")
	if err != nil {
		t.Fatalf("build custom table: %v", err)
	}
	cfg := newPackedConfig(table)
	errCh := make(chan error, 2)

	runPackedTCPSession(42, cfg, errCh)
	runPackedUoTSession(43, cfg, errCh)

	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("custom table handshake failed: %v", err)
		}
	}
}

func readTestDatagram(r io.Reader) (string, []byte, error) {
	addr, payload, err := NewUoTReader(r).ReadDatagram()
	if err != nil {
		return "", nil, err
	}
	return addr.String(), payload, nil
}

type countingWriter struct {
	writes int
	bytes.Buffer
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes++
	return w.Buffer.Write(p)
}

func TestUoTDatagramIsOneWrite(t *testing.T) {
	for _, target := range []string{"8.8.8.8:53", "[2001:db8::1]:443", "example.com:80"} {
		var w countingWriter
		payload := bytes.Repeat([]byte{0x5a}, 1200)
		if err := WriteDatagram(&w, target, payload); err != nil {
			t.Fatalf("%s: write datagram: %v", target, err)
		}
		if w.writes != 1 {
			t.Fatalf("%s: datagram took %d writes, want 1", target, w.writes)
		}
		addr, got, err := readTestDatagram(&w.Buffer)
		if err != nil || addr != target || !bytes.Equal(got, payload) {
			t.Fatalf("%s: round trip got %q %d bytes, %v", target, addr, len(got), err)
		}
	}

	var w countingWriter
	if err := WriteDatagram(&w, "8.8.8.8:53", make([]byte, 65535)); err != nil {
		t.Fatalf("largest payload: %v", err)
	}
	if err := WriteDatagram(&w, "8.8.8.8:53", make([]byte, 65536)); err == nil {
		t.Fatal("payload over 65535 bytes must be rejected")
	}
}

func TestUoTPacketConnReadFrom(t *testing.T) {
	frame := func(addr string, padding int, payload string) []byte {
		enc, err := EncodeAddress(addr)
		if err != nil {
			t.Fatal(err)
		}
		b := binary.BigEndian.AppendUint16(nil, uint16(len(enc)+padding))
		b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
		b = append(b, enc...)
		b = append(b, make([]byte, padding)...)
		return append(b, payload...)
	}

	var stream []byte
	stream = append(stream, frame("example.com:53", 0, "dns")...)         // domain peers are dropped
	stream = append(stream, frame("8.8.8.8:53", 0, "too long for p")...)  // consumed, reported as short
	stream = append(stream, frame("[::ffff:1.2.3.4]:5353", 300, "ok")...) // padded address, mapped IPv6
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_, _ = server.Write(stream)
		_ = server.Close()
	}()

	pc := NewUoTPacketConn(client)
	p := make([]byte, 8)
	if _, _, err := pc.ReadFrom(p); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("oversized datagram: err = %v, want io.ErrShortBuffer", err)
	}
	n, from, err := pc.ReadFrom(p)
	if err != nil || string(p[:n]) != "ok" {
		t.Fatalf("read after short buffer: %q, %v", p[:n], err)
	}
	if udp := from.(*net.UDPAddr); udp.String() != "1.2.3.4:5353" || len(udp.IP) != net.IPv4len {
		t.Fatalf("peer = %v (%d-byte IP), want 1.2.3.4:5353 as IPv4", from, len(udp.IP))
	}
}
