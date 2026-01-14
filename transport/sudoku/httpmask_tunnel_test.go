package sudoku

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func startTunnelServer(t *testing.T, cfg *ProtocolConfig, handle func(*ServerSession) error) (addr string, stop func(), errCh <-chan error) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	errC := make(chan error, 128)
	done := make(chan struct{})

	tunnelSrv := NewHTTPMaskTunnelServer(cfg)
	var wg sync.WaitGroup
	var stopOnce sync.Once

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				close(done)
				return
			}
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()

				handshakeConn, handshakeCfg, handled, err := tunnelSrv.WrapConn(conn)
				if err != nil {
					_ = conn.Close()
					if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
						return
					}
					if err == io.EOF {
						return
					}
					errC <- err
					return
				}
				if handled {
					return
				}
				if handshakeConn == nil || handshakeCfg == nil {
					_ = conn.Close()
					errC <- fmt.Errorf("wrap conn returned nil")
					return
				}

				session, err := ServerHandshake(handshakeConn, handshakeCfg)
				if err != nil {
					_ = handshakeConn.Close()
					if handshakeConn != conn {
						_ = conn.Close()
					}
					errC <- err
					return
				}
				defer session.Conn.Close()

				if handleErr := handle(session); handleErr != nil {
					errC <- handleErr
				}
			}(c)
		}
	}()

	stop = func() {
		stopOnce.Do(func() {
			_ = ln.Close()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("server did not stop")
			}

			ch := make(chan struct{})
			go func() {
				wg.Wait()
				close(ch)
			}()
			select {
			case <-ch:
			case <-time.After(10 * time.Second):
				t.Fatalf("server goroutines did not exit")
			}
			close(errC)
		})
	}

	return ln.Addr().String(), stop, errC
}

func newTunnelTestTable(t *testing.T, key string) *ProtocolConfig {
	t.Helper()

	tables, err := NewTablesWithCustomPatterns(ClientAEADSeed(key), "prefer_ascii", "", nil)
	if err != nil {
		t.Fatalf("build tables: %v", err)
	}
	if len(tables) != 1 {
		t.Fatalf("unexpected tables: %d", len(tables))
	}

	cfg := DefaultConfig()
	cfg.Key = key
	cfg.AEADMethod = "chacha20-poly1305"
	cfg.Table = tables[0]
	cfg.PaddingMin = 0
	cfg.PaddingMax = 0
	cfg.HandshakeTimeoutSeconds = 5
	cfg.EnablePureDownlink = true
	cfg.DisableHTTPMask = false
	return cfg
}

func TestHTTPMaskTunnel_Stream_TCPRoundTrip(t *testing.T) {
	key := "tunnel-stream-key"
	target := "1.1.1.1:80"

	serverCfg := newTunnelTestTable(t, key)
	serverCfg.HTTPMaskMode = "stream"

	addr, stop, errCh := startTunnelServer(t, serverCfg, func(s *ServerSession) error {
		if s.Type != SessionTypeTCP {
			return fmt.Errorf("unexpected session type: %v", s.Type)
		}
		if s.Target != target {
			return fmt.Errorf("target mismatch: %s", s.Target)
		}
		_, _ = s.Conn.Write([]byte("ok"))
		return nil
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientCfg := *serverCfg
	clientCfg.ServerAddress = addr
	clientCfg.HTTPMaskHost = "example.com"

	tunnelConn, err := DialHTTPMaskTunnel(ctx, clientCfg.ServerAddress, &clientCfg, (&net.Dialer{}).DialContext, nil)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer tunnelConn.Close()

	handshakeCfg := clientCfg
	handshakeCfg.DisableHTTPMask = true
	cConn, err := ClientHandshake(tunnelConn, &handshakeCfg)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer cConn.Close()

	addrBuf, err := EncodeAddress(target)
	if err != nil {
		t.Fatalf("encode addr: %v", err)
	}
	if _, err := cConn.Write(addrBuf); err != nil {
		t.Fatalf("write addr: %v", err)
	}

	buf := make([]byte, 2)
	if _, err := io.ReadFull(cConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("unexpected payload: %q", buf)
	}

	stop()
	for err := range errCh {
		t.Fatalf("server error: %v", err)
	}
}

func TestHTTPMaskTunnel_Poll_UoTRoundTrip(t *testing.T) {
	key := "tunnel-poll-key"
	target := "8.8.8.8:53"
	payload := []byte{0xaa, 0xbb, 0xcc, 0xdd}

	serverCfg := newTunnelTestTable(t, key)
	serverCfg.HTTPMaskMode = "poll"

	addr, stop, errCh := startTunnelServer(t, serverCfg, func(s *ServerSession) error {
		if s.Type != SessionTypeUoT {
			return fmt.Errorf("unexpected session type: %v", s.Type)
		}
		gotAddr, gotPayload, err := ReadDatagram(s.Conn)
		if err != nil {
			return fmt.Errorf("server read datagram: %w", err)
		}
		if gotAddr != target {
			return fmt.Errorf("uot target mismatch: %s", gotAddr)
		}
		if !bytes.Equal(gotPayload, payload) {
			return fmt.Errorf("uot payload mismatch: %x", gotPayload)
		}
		if err := WriteDatagram(s.Conn, gotAddr, gotPayload); err != nil {
			return fmt.Errorf("server write datagram: %w", err)
		}
		return nil
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientCfg := *serverCfg
	clientCfg.ServerAddress = addr

	tunnelConn, err := DialHTTPMaskTunnel(ctx, clientCfg.ServerAddress, &clientCfg, (&net.Dialer{}).DialContext, nil)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer tunnelConn.Close()

	handshakeCfg := clientCfg
	handshakeCfg.DisableHTTPMask = true
	cConn, err := ClientHandshake(tunnelConn, &handshakeCfg)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer cConn.Close()

	if err := WritePreface(cConn); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	if err := WriteDatagram(cConn, target, payload); err != nil {
		t.Fatalf("write datagram: %v", err)
	}
	gotAddr, gotPayload, err := ReadDatagram(cConn)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	if gotAddr != target {
		t.Fatalf("uot target mismatch: %s", gotAddr)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("uot payload mismatch: %x", gotPayload)
	}

	stop()
	for err := range errCh {
		t.Fatalf("server error: %v", err)
	}
}

func TestHTTPMaskTunnel_Auto_TCPRoundTrip(t *testing.T) {
	key := "tunnel-auto-key"
	target := "9.9.9.9:443"

	serverCfg := newTunnelTestTable(t, key)
	serverCfg.HTTPMaskMode = "auto"

	addr, stop, errCh := startTunnelServer(t, serverCfg, func(s *ServerSession) error {
		if s.Type != SessionTypeTCP {
			return fmt.Errorf("unexpected session type: %v", s.Type)
		}
		if s.Target != target {
			return fmt.Errorf("target mismatch: %s", s.Target)
		}
		_, _ = s.Conn.Write([]byte("ok"))
		return nil
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientCfg := *serverCfg
	clientCfg.ServerAddress = addr

	tunnelConn, err := DialHTTPMaskTunnel(ctx, clientCfg.ServerAddress, &clientCfg, (&net.Dialer{}).DialContext, nil)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer tunnelConn.Close()

	handshakeCfg := clientCfg
	handshakeCfg.DisableHTTPMask = true
	cConn, err := ClientHandshake(tunnelConn, &handshakeCfg)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer cConn.Close()

	addrBuf, err := EncodeAddress(target)
	if err != nil {
		t.Fatalf("encode addr: %v", err)
	}
	if _, err := cConn.Write(addrBuf); err != nil {
		t.Fatalf("write addr: %v", err)
	}

	buf := make([]byte, 2)
	if _, err := io.ReadFull(cConn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("unexpected payload: %q", buf)
	}

	stop()
	for err := range errCh {
		t.Fatalf("server error: %v", err)
	}
}

func TestHTTPMaskTunnel_Validation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Key = "k"
	cfg.Table = NewTable("seed", "prefer_ascii")
	cfg.ServerAddress = "127.0.0.1:1"

	cfg.DisableHTTPMask = true
	cfg.HTTPMaskMode = "stream"
	if _, err := DialHTTPMaskTunnel(context.Background(), cfg.ServerAddress, cfg, (&net.Dialer{}).DialContext, nil); err == nil {
		t.Fatalf("expected error for disabled http mask")
	}

	cfg.DisableHTTPMask = false
	cfg.HTTPMaskMode = "legacy"
	if _, err := DialHTTPMaskTunnel(context.Background(), cfg.ServerAddress, cfg, (&net.Dialer{}).DialContext, nil); err == nil {
		t.Fatalf("expected error for legacy mode")
	}
}

func TestHTTPMaskTunnel_Soak_Concurrent(t *testing.T) {
	key := "tunnel-soak-key"
	target := "1.0.0.1:80"

	serverCfg := newTunnelTestTable(t, key)
	serverCfg.HTTPMaskMode = "stream"
	serverCfg.EnablePureDownlink = false

	const (
		sessions   = 8
		payloadLen = 64 * 1024
	)

	addr, stop, errCh := startTunnelServer(t, serverCfg, func(s *ServerSession) error {
		if s.Type != SessionTypeTCP {
			return fmt.Errorf("unexpected session type: %v", s.Type)
		}
		if s.Target != target {
			return fmt.Errorf("target mismatch: %s", s.Target)
		}
		buf := make([]byte, payloadLen)
		if _, err := io.ReadFull(s.Conn, buf); err != nil {
			return fmt.Errorf("server read payload: %w", err)
		}
		_, err := s.Conn.Write(buf)
		return err
	})
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	runErr := make(chan error, sessions)

	for i := 0; i < sessions; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			clientCfg := *serverCfg
			clientCfg.ServerAddress = addr
			clientCfg.HTTPMaskHost = strings.TrimSpace(clientCfg.HTTPMaskHost)

			tunnelConn, err := DialHTTPMaskTunnel(ctx, clientCfg.ServerAddress, &clientCfg, (&net.Dialer{}).DialContext, nil)
			if err != nil {
				runErr <- fmt.Errorf("dial: %w", err)
				return
			}
			defer tunnelConn.Close()

			handshakeCfg := clientCfg
			handshakeCfg.DisableHTTPMask = true
			cConn, err := ClientHandshake(tunnelConn, &handshakeCfg)
			if err != nil {
				runErr <- fmt.Errorf("handshake: %w", err)
				return
			}
			defer cConn.Close()

			addrBuf, err := EncodeAddress(target)
			if err != nil {
				runErr <- fmt.Errorf("encode addr: %w", err)
				return
			}
			if _, err := cConn.Write(addrBuf); err != nil {
				runErr <- fmt.Errorf("write addr: %w", err)
				return
			}

			payload := bytes.Repeat([]byte{byte(id)}, payloadLen)
			if _, err := cConn.Write(payload); err != nil {
				runErr <- fmt.Errorf("write payload: %w", err)
				return
			}
			echo := make([]byte, payloadLen)
			if _, err := io.ReadFull(cConn, echo); err != nil {
				runErr <- fmt.Errorf("read echo: %w", err)
				return
			}
			if !bytes.Equal(echo, payload) {
				runErr <- fmt.Errorf("echo mismatch")
				return
			}
			runErr <- nil
		}(i)
	}

	wg.Wait()
	close(runErr)

	for err := range runErr {
		if err != nil {
			t.Fatalf("soak: %v", err)
		}
	}

	stop()
	for err := range errCh {
		t.Fatalf("server error: %v", err)
	}
}
