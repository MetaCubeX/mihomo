package sudoku

import (
	"bytes"
	"io"
	"net"
	"testing"

	sudokuobfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

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
			c, meta, err := ServerHandshake(serverConn, serverCfg)
			if err != nil {
				errCh <- err
				return
			}
			session, err := ReadServerSession(c, meta)
			if err != nil {
				errCh <- err
				return
			}
			defer c.Close()
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
		if err := WriteKIPMessage(cConn, KIPTypeOpenTCP, addrBuf); err != nil {
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
