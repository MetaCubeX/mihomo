package outbound

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	tsudoku "github.com/metacubex/mihomo/transport/sudoku"
	sudokuobfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

func TestSudokuDialContextDirectional(t *testing.T) {
	tests := []struct {
		name string
		mode string
		pure bool
	}{
		{name: "UpASCII_DownEntropy_Pure", mode: "up_ascii_down_entropy", pure: true},
		{name: "UpEntropy_DownASCII_Packed", mode: "up_entropy_down_ascii", pure: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "adapter-sudoku-" + tt.name
			target := "127.0.0.1:18080"

			table, err := sudokuobfs.NewTableWithCustom(tsudoku.ServerAEADSeed(key), tt.mode, "xpxvvpvv")
			if err != nil {
				t.Fatalf("table: %v", err)
			}

			serverCfg := tsudoku.DefaultConfig()
			serverCfg.Key = key
			serverCfg.AEADMethod = "chacha20-poly1305"
			serverCfg.Table = table
			serverCfg.PaddingMin = 0
			serverCfg.PaddingMax = 0
			serverCfg.EnablePureDownlink = tt.pure
			serverCfg.HandshakeTimeoutSeconds = 5
			serverCfg.DisableHTTPMask = true

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			serverErr := make(chan error, 1)
			go func() {
				defer close(serverErr)
				raw, err := ln.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				defer raw.Close()

				c, meta, err := tsudoku.ServerHandshake(raw, serverCfg)
				if err != nil {
					serverErr <- err
					return
				}
				defer c.Close()

				session, err := tsudoku.ReadServerSession(c, meta)
				if err != nil {
					serverErr <- err
					return
				}
				if session.Type != tsudoku.SessionTypeTCP || session.Target != target {
					serverErr <- io.ErrUnexpectedEOF
					return
				}

				buf := make([]byte, len("client-payload"))
				if _, err := io.ReadFull(session.Conn, buf); err != nil {
					serverErr <- err
					return
				}
				if !bytes.Equal(buf, []byte("client-payload")) {
					serverErr <- io.ErrUnexpectedEOF
					return
				}
				if _, err := session.Conn.Write([]byte("server-reply")); err != nil {
					serverErr <- err
					return
				}
			}()

			enablePure := tt.pure
			httpMask := false
			out, err := NewSudoku(SudokuOption{
				Name:               "sudoku-test",
				Server:             "127.0.0.1",
				Port:               ln.Addr().(*net.TCPAddr).Port,
				Key:                key,
				TableType:          tt.mode,
				CustomTable:        "xpxvvpvv",
				EnablePureDownlink: &enablePure,
				HTTPMask:           &httpMask,
			})
			if err != nil {
				t.Fatalf("NewSudoku: %v", err)
			}
			defer out.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			metadata := &C.Metadata{
				NetWork: C.TCP,
				DstIP:   netip.MustParseAddr("127.0.0.1"),
				DstPort: 18080,
			}
			conn, err := out.DialContext(ctx, metadata)
			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			defer conn.Close()

			if _, err := conn.Write([]byte("client-payload")); err != nil {
				t.Fatalf("write payload: %v", err)
			}
			reply := make([]byte, len("server-reply"))
			if _, err := io.ReadFull(conn, reply); err != nil {
				t.Fatalf("read reply: %v", err)
			}
			if !bytes.Equal(reply, []byte("server-reply")) {
				t.Fatalf("unexpected reply: %q", reply)
			}

			if err := <-serverErr; err != nil {
				t.Fatalf("server: %v", err)
			}
		})
	}
}
