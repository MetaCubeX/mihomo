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

func TestDirectionalTrafficRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		mode string
		pure bool
	}{
		{name: "UpASCII_DownEntropy_Pure", mode: "up_ascii_down_entropy", pure: true},
		{name: "UpASCII_DownEntropy_Packed", mode: "up_ascii_down_entropy", pure: false},
		{name: "UpEntropy_DownASCII_Pure", mode: "up_entropy_down_ascii", pure: true},
		{name: "UpEntropy_DownASCII_Packed", mode: "up_entropy_down_ascii", pure: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "directional-test-key-" + tt.name
			target := "8.8.8.8:53"

			table, err := sudokuobfs.NewTableWithCustom(ClientAEADSeed(key), tt.mode, "xpxvvpvv")
			if err != nil {
				t.Fatalf("table: %v", err)
			}

			serverCfg := DefaultConfig()
			serverCfg.Key = key
			serverCfg.AEADMethod = "chacha20-poly1305"
			serverCfg.Table = table
			serverCfg.PaddingMin = 0
			serverCfg.PaddingMax = 0
			serverCfg.EnablePureDownlink = tt.pure
			serverCfg.HandshakeTimeoutSeconds = 5
			serverCfg.DisableHTTPMask = true

			clientCfg := DefaultConfig()
			*clientCfg = *serverCfg
			clientCfg.ServerAddress = "example.com:443"

			serverConn, clientConn := net.Pipe()
			defer clientConn.Close()

			serverErr := make(chan error, 1)
			go func() {
				defer close(serverErr)
				defer serverConn.Close()

				c, meta, err := ServerHandshake(serverConn, serverCfg)
				if err != nil {
					serverErr <- err
					return
				}
				defer c.Close()

				session, err := ReadServerSession(c, meta)
				if err != nil {
					serverErr <- err
					return
				}
				if session.Type != SessionTypeTCP {
					serverErr <- io.ErrUnexpectedEOF
					return
				}
				if session.Target != target {
					serverErr <- io.ErrClosedPipe
					return
				}

				want := []byte("client-payload")
				got := make([]byte, len(want))
				if _, err := io.ReadFull(session.Conn, got); err != nil {
					serverErr <- err
					return
				}
				if !bytes.Equal(got, want) {
					serverErr <- io.ErrUnexpectedEOF
					return
				}

				if _, err := session.Conn.Write([]byte("server-reply")); err != nil {
					serverErr <- err
					return
				}
			}()

			cConn, err := ClientHandshake(clientConn, clientCfg)
			if err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			defer cConn.Close()

			addrBuf, err := EncodeAddress(target)
			if err != nil {
				t.Fatalf("encode target: %v", err)
			}
			if err := WriteKIPMessage(cConn, KIPTypeOpenTCP, addrBuf); err != nil {
				t.Fatalf("write target: %v", err)
			}
			if _, err := cConn.Write([]byte("client-payload")); err != nil {
				t.Fatalf("write payload: %v", err)
			}

			reply := make([]byte, len("server-reply"))
			if _, err := io.ReadFull(cConn, reply); err != nil {
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

func TestDirectionalTrafficRoundTripTCP(t *testing.T) {
	tests := []struct {
		name string
		mode string
		pure bool
	}{
		{name: "UpASCII_DownEntropy_Pure_TCP", mode: "up_ascii_down_entropy", pure: true},
		{name: "UpEntropy_DownASCII_Packed_TCP", mode: "up_entropy_down_ascii", pure: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "directional-tcp-test-key-" + tt.name
			target := "127.0.0.1:18080"

			table, err := sudokuobfs.NewTableWithCustom(ClientAEADSeed(key), tt.mode, "xpxvvpvv")
			if err != nil {
				t.Fatalf("table: %v", err)
			}

			serverCfg := DefaultConfig()
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

				c, meta, err := ServerHandshake(raw, serverCfg)
				if err != nil {
					serverErr <- err
					return
				}
				defer c.Close()

				session, err := ReadServerSession(c, meta)
				if err != nil {
					serverErr <- err
					return
				}
				if session.Type != SessionTypeTCP || session.Target != target {
					serverErr <- io.ErrUnexpectedEOF
					return
				}

				want := []byte("client-payload")
				got := make([]byte, len(want))
				if _, err := io.ReadFull(session.Conn, got); err != nil {
					serverErr <- err
					return
				}
				if !bytes.Equal(got, want) {
					serverErr <- io.ErrUnexpectedEOF
					return
				}
				if _, err := session.Conn.Write([]byte("server-reply")); err != nil {
					serverErr <- err
					return
				}
			}()

			clientCfg := DefaultConfig()
			*clientCfg = *serverCfg
			clientCfg.ServerAddress = ln.Addr().String()

			raw, err := net.Dial("tcp", clientCfg.ServerAddress)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer raw.Close()

			cConn, err := ClientHandshake(raw, clientCfg)
			if err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			defer cConn.Close()

			addrBuf, err := EncodeAddress(target)
			if err != nil {
				t.Fatalf("encode target: %v", err)
			}
			if err := WriteKIPMessage(cConn, KIPTypeOpenTCP, addrBuf); err != nil {
				t.Fatalf("write target: %v", err)
			}
			if _, err := cConn.Write([]byte("client-payload")); err != nil {
				t.Fatalf("write payload: %v", err)
			}

			reply := make([]byte, len("server-reply"))
			if _, err := io.ReadFull(cConn, reply); err != nil {
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
