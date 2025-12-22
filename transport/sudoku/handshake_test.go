package sudoku

import (
	"bytes"
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
	serverConn, clientConn := net.Pipe()
	target := fmt.Sprintf("1.1.1.%d:80", (id%200)+1)
	payload := []byte{0x42, byte(id)}

	// Server side
	go func() {
		session, err := ServerHandshake(serverConn, cfg)
		if err != nil {
			errCh <- fmt.Errorf("server handshake tcp: %w", err)
			return
		}
		defer session.Conn.Close()

		if session.Type != SessionTypeTCP {
			errCh <- fmt.Errorf("unexpected session type: %v", session.Type)
			return
		}
		if session.Target != target {
			errCh <- fmt.Errorf("target mismatch want %s got %s", target, session.Target)
			return
		}
		if _, err := session.Conn.Write(payload); err != nil {
			errCh <- fmt.Errorf("server write: %w", err)
			return
		}
	}()

	// Client side
	clientCfg := *cfg
	cConn, err := ClientHandshake(clientConn, &clientCfg)
	if err != nil {
		errCh <- fmt.Errorf("client handshake tcp: %w", err)
		return
	}
	defer cConn.Close()

	addrBuf, err := EncodeAddress(target)
	if err != nil {
		errCh <- fmt.Errorf("encode address: %w", err)
		return
	}
	if _, err := cConn.Write(addrBuf); err != nil {
		errCh <- fmt.Errorf("client send addr: %w", err)
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
}

func runPackedUoTSession(id int, cfg *ProtocolConfig, errCh chan<- error) {
	serverConn, clientConn := net.Pipe()
	target := "8.8.8.8:53"
	payload := []byte{0xaa, byte(id)}

	// Server side
	go func() {
		session, err := ServerHandshake(serverConn, cfg)
		if err != nil {
			errCh <- fmt.Errorf("server handshake uot: %w", err)
			return
		}
		defer session.Conn.Close()

		if session.Type != SessionTypeUoT {
			errCh <- fmt.Errorf("unexpected session type: %v", session.Type)
			return
		}
		if err := WriteDatagram(session.Conn, target, payload); err != nil {
			errCh <- fmt.Errorf("server write datagram: %w", err)
			return
		}
	}()

	// Client side
	clientCfg := *cfg
	cConn, err := ClientHandshake(clientConn, &clientCfg)
	if err != nil {
		errCh <- fmt.Errorf("client handshake uot: %w", err)
		return
	}
	defer cConn.Close()

	if err := WritePreface(cConn); err != nil {
		errCh <- fmt.Errorf("client write preface: %w", err)
		return
	}

	addr, data, err := ReadDatagram(cConn)
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
