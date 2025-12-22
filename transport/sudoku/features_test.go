package sudoku

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	sudokuobfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

type discardConn struct{}

func (discardConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (discardConn) Write(p []byte) (int, error)      { return len(p), nil }
func (discardConn) Close() error                     { return nil }
func (discardConn) LocalAddr() net.Addr              { return nil }
func (discardConn) RemoteAddr() net.Addr             { return nil }
func (discardConn) SetDeadline(time.Time) error      { return nil }
func (discardConn) SetReadDeadline(time.Time) error  { return nil }
func (discardConn) SetWriteDeadline(time.Time) error { return nil }

func TestSudokuObfsWriter_ReducesWriteAllocs(t *testing.T) {
	table := sudokuobfs.NewTable("alloc-seed", "prefer_ascii")
	w := newSudokuObfsWriter(discardConn{}, table, 0, 0)

	payload := bytes.Repeat([]byte{0x42}, 2048)
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("warmup write: %v", err)
	}

	allocs := testing.AllocsPerRun(100, func() {
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocs/run, got %.2f", allocs)
	}
}

func TestHTTPMaskStrategy_WebSocketAndPost(t *testing.T) {
	key := "mask-test-key"
	target := "1.1.1.1:80"
	table := sudokuobfs.NewTable("mask-seed", "prefer_ascii")

	base := DefaultConfig()
	base.Key = key
	base.AEADMethod = "chacha20-poly1305"
	base.Table = table
	base.PaddingMin = 0
	base.PaddingMax = 0
	base.EnablePureDownlink = true
	base.HandshakeTimeoutSeconds = 5
	base.DisableHTTPMask = false
	base.ServerAddress = "example.com:443"

	cases := []string{"post", "websocket"}
	for _, strategy := range cases {
		t.Run(strategy, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			errCh := make(chan error, 1)
			go func() {
				defer close(errCh)
				session, err := ServerHandshake(serverConn, base)
				if err != nil {
					errCh <- err
					return
				}
				defer session.Conn.Close()
				if session.Type != SessionTypeTCP {
					errCh <- io.ErrUnexpectedEOF
					return
				}
				if session.Target != target {
					errCh <- io.ErrClosedPipe
					return
				}
				_, _ = session.Conn.Write([]byte("ok"))
			}()

			cConn, err := ClientHandshakeWithOptions(clientConn, base, ClientHandshakeOptions{HTTPMaskStrategy: strategy})
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

			if err := <-errCh; err != nil {
				t.Fatalf("server: %v", err)
			}
		})
	}
}

func TestCustomTablesRotation_ProbedByServer(t *testing.T) {
	key := "rotate-test-key"
	target := "8.8.8.8:53"

	t1, err := sudokuobfs.NewTableWithCustom("rotate-seed", "prefer_entropy", "xpxvvpvv")
	if err != nil {
		t.Fatalf("t1: %v", err)
	}
	t2, err := sudokuobfs.NewTableWithCustom("rotate-seed", "prefer_entropy", "vxpvxvvp")
	if err != nil {
		t.Fatalf("t2: %v", err)
	}

	serverCfg := DefaultConfig()
	serverCfg.Key = key
	serverCfg.AEADMethod = "chacha20-poly1305"
	serverCfg.Tables = []*sudokuobfs.Table{t1, t2}
	serverCfg.PaddingMin = 0
	serverCfg.PaddingMax = 0
	serverCfg.EnablePureDownlink = true
	serverCfg.HandshakeTimeoutSeconds = 5
	serverCfg.DisableHTTPMask = true

	clientCfg := DefaultConfig()
	*clientCfg = *serverCfg
	clientCfg.ServerAddress = "example.com:443"

	for i := 0; i < 10; i++ {
		serverConn, clientConn := net.Pipe()

		errCh := make(chan error, 1)
		go func() {
			defer close(errCh)
			defer serverConn.Close()
			session, err := ServerHandshake(serverConn, serverCfg)
			if err != nil {
				errCh <- err
				return
			}
			defer session.Conn.Close()
			if session.Type != SessionTypeTCP {
				errCh <- io.ErrUnexpectedEOF
				return
			}
			if session.Target != target {
				errCh <- io.ErrClosedPipe
				return
			}
			_, _ = session.Conn.Write([]byte{0xaa, 0xbb, 0xcc})
		}()

		cConn, err := ClientHandshake(clientConn, clientCfg)
		if err != nil {
			t.Fatalf("client handshake: %v", err)
		}

		addrBuf, err := EncodeAddress(target)
		if err != nil {
			t.Fatalf("encode addr: %v", err)
		}
		if _, err := cConn.Write(addrBuf); err != nil {
			t.Fatalf("write addr: %v", err)
		}

		buf := make([]byte, 3)
		if _, err := io.ReadFull(cConn, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(buf, []byte{0xaa, 0xbb, 0xcc}) {
			t.Fatalf("payload mismatch: %x", buf)
		}
		_ = cConn.Close()

		if err := <-errCh; err != nil {
			t.Fatalf("server: %v", err)
		}
	}
}
